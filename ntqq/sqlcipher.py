"""QQ NT 数据库的纯 Python SQLCipher 解密。

QQ NT 使用非默认配置的 SQLCipher 加密其 SQLite 数据库。*密钥派生*
在各数据库之间是固定的（页大小 4096、4000 次 PBKDF2-HMAC-SHA512 迭代、
256 位密钥），但*页* HMAC 算法并不固定：大多数数据库使用
HMAC-SHA1 认证页（留下 48 字节 reserve 区），而另一些——例如 ``guild1.db``——
使用 HMAC-SHA512（80 字节 reserve 区）。容器头中的 ``HMAC_SHA1`` 字符串
只是一个提示，因此 :func:`detect_config` 通过验证前几个页的 HMAC
来还原真实参数。

页布局（所有页均为 ``page_size`` 字节）::

    +--------------------------+----------+--------+------------------+
    | 加密内容                  | IV (16)  | HMAC   | 未使用 / 零填充   |
    +--------------------------+----------+--------+------------------+
    |<-- page_size - reserve -->|<-- 16 -->|<-- n ->|<-- padding ----->|

第 1 页很特殊：前 16 字节是 SQLCipher 的 *salt*，以明文存储；
因此加密从偏移 16 处开始。解密第 1 页会得到从第 17 字节开始的
SQLite 头部，所以要把标准的 ``SQLite format 3\\x00`` magic 补回前面。
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import struct
from dataclasses import dataclass, field
from pathlib import Path

from .header import HEADER_SIZE, parse_header

PAGE_SIZE = 4096
SALT_SIZE = 16
IV_SIZE = 16
HMAC_MASK = 0x3A
KDF_ITER = 4000
KDF_PRF = "sha512"
HMAC_PRF = "sha1"
SQLITE_MAGIC = b"SQLite format 3\x00"

#: 每个受支持的页 HMAC 算法的摘要长度。
HMAC_SIZES = {"sha1": 20, "sha256": 32, "sha512": 64}

try:  # pragma: no cover - 导入保护
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "the 'cryptography' package is required for decryption (pip install cryptography)"
    ) from exc


def _reserve_for(hmac_prf: str) -> int:
    """每页保留的字节数：IV 与 HMAC，向上取整到 16 的倍数。

    SQLCipher 在每一页的末尾存储 IV（16 字节），紧随其后的是页 HMAC；
    QQ 会把总长度向上取整到下一个 16 字节边界，因此 HMAC-SHA1
    得到 48（36 -> 48），HMAC-SHA512 得到 80（80 -> 80）。
    """
    return -(-(IV_SIZE + HMAC_SIZES[hmac_prf]) // 16) * 16


@dataclass(frozen=True)
class CipherConfig:
    """单个数据库的 SQLCipher 参数。"""

    page_size: int = PAGE_SIZE
    kdf_prf: str = KDF_PRF
    kdf_iter: int = KDF_ITER
    key_size: int = 32
    hmac_prf: str = HMAC_PRF
    hmac_mask: int = HMAC_MASK

    @property
    def hmac_size(self) -> int:
        return HMAC_SIZES[self.hmac_prf]

    @property
    def reserve(self) -> int:
        return _reserve_for(self.hmac_prf)

    def summary(self) -> dict[str, object]:
        return {
            "page_size": self.page_size,
            "kdf": f"PBKDF2-HMAC-{self.kdf_prf.upper()}",
            "kdf_iter": self.kdf_iter,
            "key_size": self.key_size,
            "hmac": f"HMAC-{self.hmac_prf.upper()}",
            "reserve": self.reserve,
        }


DEFAULT_CONFIG = CipherConfig()

# 向后兼容的模块级常量（默认配置）。
RESERVE = DEFAULT_CONFIG.reserve
HMAC_SIZE = DEFAULT_CONFIG.hmac_size
ZERO_PAGE = bytes(PAGE_SIZE)


# ---------------------------------------------------------------------------
# 密钥派生
# ---------------------------------------------------------------------------


def derive_enc_key(passphrase: bytes, salt: bytes, config: CipherConfig = DEFAULT_CONFIG) -> bytes:
    """PBKDF2 密钥派生（默认 SHA512、4000 次迭代、256 位密钥）。"""
    return hashlib.pbkdf2_hmac(config.kdf_prf, passphrase, salt, config.kdf_iter, config.key_size)


def derive_hmac_key(enc_key: bytes, salt: bytes, config: CipherConfig = DEFAULT_CONFIG) -> bytes:
    """HMAC 密钥 = PBKDF2(enc_key, salt XOR 0x3a, 2 次迭代)。"""
    masked = bytes(b ^ config.hmac_mask for b in salt)
    return hashlib.pbkdf2_hmac(config.kdf_prf, enc_key, masked, 2, config.key_size)


@dataclass
class Keys:
    passphrase: bytes
    salt: bytes
    enc_key: bytes
    hmac_key: bytes
    config: CipherConfig = DEFAULT_CONFIG


def keys_for(passphrase: bytes, salt: bytes, config: CipherConfig = DEFAULT_CONFIG) -> Keys:
    enc_key = derive_enc_key(passphrase, salt, config)
    return Keys(passphrase, salt, enc_key, derive_hmac_key(enc_key, salt, config), config)


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


# ---------------------------------------------------------------------------
# 页认证 / 解密
# ---------------------------------------------------------------------------


def verify_page(
    page: bytes, pgno: int, hmac_key: bytes, config: CipherConfig = DEFAULT_CONFIG
) -> bool:
    """校验每页的 HMAC。"""
    data_end = config.page_size - config.reserve
    skip = SALT_SIZE if pgno == 1 else 0
    content = page[skip:data_end]
    iv = page[data_end : data_end + IV_SIZE]
    stored = page[data_end + IV_SIZE : data_end + IV_SIZE + config.hmac_size]
    computed = hmac_mod.new(
        hmac_key, content + iv + struct.pack("<I", pgno), config.hmac_prf
    ).digest()
    return hmac_mod.compare_digest(computed, stored)


def decrypt_page(
    page: bytes, pgno: int, enc_key: bytes, config: CipherConfig = DEFAULT_CONFIG
) -> bytes:
    """解密单个页并返回完整的明文 ``page_size`` 页。"""
    data_end = config.page_size - config.reserve
    skip = SALT_SIZE if pgno == 1 else 0
    content = page[skip:data_end]
    iv = page[data_end : data_end + IV_SIZE]
    plain = _aes_cbc_decrypt(enc_key, iv, content)
    if pgno == 1:
        plain = SQLITE_MAGIC + plain
    return plain + bytes(config.reserve)


# ---------------------------------------------------------------------------
# 配置探测
# ---------------------------------------------------------------------------

#: :func:`detect_config` 探测的 KDF 与页 HMAC 组合，最可能的排在前面。
#: 在所有观察到的 QQ 版本中 KDF 始终是 PBKDF2-HMAC-SHA512/4000，
#: 但页 HMAC 会变化，因此两者都进行探测以增强健壮性。
_CANDIDATE_KDFS = ("sha512", "sha1", "sha256")
_CANDIDATE_HMACS = ("sha1", "sha256", "sha512")


def read_header_and_salt(source: str | Path) -> tuple[object, bytes]:
    with open(source, "rb") as handle:
        header = parse_header(handle.read(HEADER_SIZE))
        salt = handle.read(SALT_SIZE)
    return header, salt


def looks_encrypted(data: bytes) -> bool:
    """*data* 是否以 QQ 容器头开头（即不是明文 SQLite）？"""
    if len(data) < 16:
        return False
    return not data.startswith(SQLITE_MAGIC)


def detect_config(
    source: str | Path, passphrase: bytes, probe_pages: int = 2
) -> CipherConfig | None:
    """通过逐一尝试 HMAC 校验来还原 SQLCipher 配置。

    读取 salt 以及最多 *probe_pages* 个加密页，返回第一个
    所有页 HMAC 均校验通过的候选配置；若都不匹配
    （密钥错误或文件损坏）则返回 ``None``。
    """
    source = Path(source)
    with open(source, "rb") as handle:
        handle.seek(HEADER_SIZE)
        salt = handle.read(SALT_SIZE)
        if len(salt) < SALT_SIZE:
            return None
        handle.seek(HEADER_SIZE)
        pages: list[tuple[int, bytes]] = []
        for index in range(probe_pages):
            page = handle.read(PAGE_SIZE)
            if len(page) < PAGE_SIZE:
                break
            if page == ZERO_PAGE:
                continue
            pages.append((index + 1, page))
    if not pages:
        return None

    for kdf_prf in _CANDIDATE_KDFS:
        for hmac_prf in _CANDIDATE_HMACS:
            config = CipherConfig(kdf_prf=kdf_prf, hmac_prf=hmac_prf)
            enc_key = derive_enc_key(passphrase, salt, config)
            hmac_key = derive_hmac_key(enc_key, salt, config)
            if all(verify_page(page, pgno, hmac_key, config) for pgno, page in pages):
                return config
    return None


# ---------------------------------------------------------------------------
# 整文件操作
# ---------------------------------------------------------------------------


@dataclass
class PageStats:
    total_pages: int = 0
    good_pages: int = 0
    sparse_zero_pages: list[int] = field(default_factory=list)
    hmac_failures: list[int] = field(default_factory=list)


class DecryptedDatabase:
    """解密 QQ NT 数据库的结果。"""

    def __init__(self, header, keys: Keys, stats: PageStats):
        self.header = header
        self.keys = keys
        self.stats = stats
        self.config = keys.config

    def report(self) -> dict:
        return {
            "version": self.header.version,
            "header_hmac": self.header.hmac_algorithm,
            "cipher": self.config.summary(),
            "rand": self.header.rand,
            "salt": self.keys.salt.hex(),
            "total_pages": self.stats.total_pages,
            "good_pages": self.stats.good_pages,
            "sparse_zero_pages": self.stats.sparse_zero_pages,
            "hmac_failures": self.stats.hmac_failures,
        }


def verify_file(
    source: str | Path,
    passphrase: bytes,
    progress=None,
    config: CipherConfig | None = None,
) -> tuple[object, bytes, PageStats]:
    """校验 *source* 每一页的 HMAC，不写出任何输出。

    返回 ``(header, salt, stats)``。这是 :func:`decrypt_file` 的
    只读等价版本，适合在开始动辄数 GB 的解密之前校验密钥
    （或确认未改动的数据库完好无损）。当 *config* 为 ``None`` 时，
    会从前几个页自动探测。
    """
    source = Path(source)
    header, salt = read_header_and_salt(source)
    if config is None:
        config = detect_config(source, passphrase) or DEFAULT_CONFIG
    keys = keys_for(passphrase, salt, config)
    stats = PageStats()
    zero_page = bytes(config.page_size)

    total_bytes = source.stat().st_size - HEADER_SIZE
    stats.total_pages = total_bytes // config.page_size

    with open(source, "rb") as src:
        src.seek(HEADER_SIZE)
        pgno = 0
        while True:
            page = src.read(config.page_size)
            if len(page) < config.page_size:
                break
            pgno += 1
            if page == zero_page:
                stats.sparse_zero_pages.append(pgno)
            elif verify_page(page, pgno, keys.hmac_key, config):
                stats.good_pages += 1
            else:
                stats.hmac_failures.append(pgno)
            if progress and pgno % 50000 == 0:
                progress(pgno, stats.total_pages)

    return header, salt, stats


def decrypt_file(
    source: str | Path,
    destination: str | Path,
    passphrase: bytes,
    verify: bool = True,
    progress=None,
    config: CipherConfig | None = None,
) -> DecryptedDatabase:
    """将 *source* 解密为明文 SQLite 的 *destination*。

    HMAC 校验失败的页会写成零页（以便 SQLite 仍能打开数据库）
    并记录到报告中。稀疏的全零页会保留为零页。当 *config* 为
    ``None`` 时，会从前几个页自动探测。
    """
    source = Path(source)
    destination = Path(destination)
    header, salt = read_header_and_salt(source)
    if config is None:
        config = detect_config(source, passphrase) or DEFAULT_CONFIG
    keys = keys_for(passphrase, salt, config)
    stats = PageStats()
    zero_page = bytes(config.page_size)

    total_bytes = source.stat().st_size - HEADER_SIZE
    stats.total_pages = total_bytes // config.page_size

    with open(source, "rb") as src, open(destination, "wb") as dst:
        src.seek(HEADER_SIZE)
        pgno = 0
        while True:
            page = src.read(config.page_size)
            if len(page) < config.page_size:
                break
            pgno += 1
            if page == zero_page:
                stats.sparse_zero_pages.append(pgno)
                dst.write(zero_page)
                if progress and pgno % 50000 == 0:
                    progress(pgno, stats.total_pages)
                continue
            if verify and not verify_page(page, pgno, keys.hmac_key, config):
                stats.hmac_failures.append(pgno)
                dst.write(zero_page)
                if progress and pgno % 50000 == 0:
                    progress(pgno, stats.total_pages)
                continue
            plain = decrypt_page(page, pgno, keys.enc_key, config)
            if pgno == 1:
                page_size = struct.unpack_from(">H", plain, 16)[0]
                if page_size not in (0, config.page_size):
                    raise ValueError(f"unexpected SQLite page size {page_size} in decrypted header")
            stats.good_pages += 1
            dst.write(plain)
            if progress and pgno % 50000 == 0:
                progress(pgno, stats.total_pages)

    return DecryptedDatabase(header, keys, stats)


# ---------------------------------------------------------------------------
# 写前日志（WAL）支持
# ---------------------------------------------------------------------------

WAL_MAGIC_BE = 0x377F0682
WAL_MAGIC_LE = 0x377F0683
WAL_HEADER_SIZE = 32
WAL_FRAME_HEADER_SIZE = 24


def decrypt_wal(
    wal_path: str | Path, keys: Keys, verify: bool = True
) -> tuple[dict[int, bytes], int]:
    """解密一个 SQLCipher WAL 文件。

    返回 ``(pages, db_size)``，其中 *pages* 将页号映射到直到最后
    一次提交为止每一帧的解密后页镜像，*db_size* 是以页为单位的
    已提交数据库大小（未知时为 0）。

    WAL 是一个环形缓冲区：当它被重置（在一次 checkpoint 之后）时，
    SQLite 会带着新的 salt 对从第一帧重新开始写入。只有 salt 与
    WAL 头部一致的帧才属于当前代；上一代遗留的旧帧必须忽略，
    否则陈旧页会覆盖新页。
    """
    config = keys.config
    data = Path(wal_path).read_bytes()
    if len(data) < WAL_HEADER_SIZE:
        return {}, 0
    magic, _version, page_size, _checkpoint, salt1, salt2, _csum1, _csum2 = struct.unpack(
        ">IIIIIIII", data[:WAL_HEADER_SIZE]
    )
    if magic not in (WAL_MAGIC_BE, WAL_MAGIC_LE):
        raise ValueError("not a SQLite WAL file")
    if page_size != config.page_size:
        raise ValueError(f"unexpected WAL page size {page_size}")

    frame_size = WAL_FRAME_HEADER_SIZE + config.page_size
    frames = []
    offset = WAL_HEADER_SIZE
    while offset + frame_size <= len(data):
        pgno, db_size, fs1, fs2, _fc1, _fc2 = struct.unpack(
            ">IIIIII", data[offset : offset + WAL_FRAME_HEADER_SIZE]
        )
        frames.append(
            (
                pgno,
                db_size,
                data[offset + WAL_FRAME_HEADER_SIZE : offset + frame_size],
                fs1,
                fs2,
            )
        )
        offset += frame_size

    # 只保留当前 salt 代（一段连续前缀），并找出其中
    # 最后一次已提交的帧。
    current = 0
    for _pgno, _db_size, _page, fs1, fs2 in frames:
        if (fs1, fs2) != (salt1, salt2):
            break
        current += 1
    frames = frames[:current]

    last_commit = -1
    for index, (_, db_size, _, _, _) in enumerate(frames):
        if db_size:
            last_commit = index
    pages: dict[int, bytes] = {}
    committed_size = 0
    for pgno, db_size, page, _, _ in frames[: last_commit + 1]:
        if pgno == 0:
            continue
        if verify and not verify_page(page, pgno, keys.hmac_key, config):
            continue
        pages[pgno] = decrypt_page(page, pgno, keys.enc_key, config)
        if db_size:
            committed_size = db_size
    return pages, committed_size


def apply_wal(
    destination: str | Path,
    pages: dict[int, bytes],
    db_size: int = 0,
    page_size: int = PAGE_SIZE,
) -> None:
    """将解密后的 WAL *pages* 就地叠加到 *destination* 上。

    当 *db_size* 已知时，会更新数据库头部的页计数字段，并把文件
    截断到相应页数，与 SQLite 完成 checkpoint 的方式一致。
    否则文件会在已提交大小之后残留陈旧的尾部页，
    ``PRAGMA quick_check`` 会把这些报为无效页号。
    """
    with open(destination, "r+b") as handle:
        for pgno, page in pages.items():
            handle.seek((pgno - 1) * page_size)
            handle.write(page)
        if db_size:
            handle.seek(28)
            handle.write(struct.pack(">I", db_size))
            handle.truncate(db_size * page_size)
