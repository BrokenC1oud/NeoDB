#!/usr/bin/env python3
"""从进程内存中恢复 Linux QQ NT 客户端的 SQLCipher 密钥。

QQ NT 用 SQLCipher 加密每个数据库。16 字节的密钥在登录时由服务器下发，
且只存在于内存中，因此获取它的可行做法是在客户端运行时读取其内存。

如何找到密钥
------------
``wrapper.node``（QQ 的原生插件）中含有一个供其 SQLCipher wrapper 使用的
小型日志辅助函数::

    nt_sqlite3_key_v2: db=%p zDb=%s

该字符串恰好被一个函数引用——即密钥入口点，其签名为
``(sqlite3 *db, const void *key, int key_len)``。该工具会：

1. 在 ``wrapper.node`` 中定位该字符串，并借助 ELF 节表将其映射为虚拟地址；
2. 扫描 ``.text``，找出引用该字符串的指令（密钥函数内部的日志调用）；
3. 从这些引用处逆向回溯到函数序言，从而得到密钥函数的*相对*地址——
   这是确定性的，无需猜测；对 SQLCipher 的 ``..._set_pass`` 入口点
   也做同样处理，因为它会第二次看到口令；
4. 在 ``gdb`` 下运行 QQ（这是必需的，因为 ``kernel.yama.ptrace_scope=1``
   禁止附加到不是你启动的进程），根据一个导出符号计算 ``wrapper.node``
   的加载基址，在两个密钥函数上设置断点，并记录传给它们的每一份密钥材料；
5. 用 :func:`ntqq.sqlcipher.detect_config` 拿真实数据库校验每个候选密钥，
   并报告真正能解密它们的那个。

第 5 步很重要，因为 QQ 会把*若干*不同的数据块传给密钥函数
（例如一个 20 字节的按数据库 token）；只有账号密钥——在测试过的客户端上
是 16 个可打印 ASCII 字节——能解密这些文件。

环境要求
--------
``gdb``、``objdump`` 和 ``readelf``（binutils）。必须先关闭 QQ：
该工具会在调试器下启动一个新实例。

这些地址因构建版本而异——每次运行都会从磁盘上的 ``wrapper.node``
重新推导，因此只要日志字符串还在，该工具就能在 QQ 更新后继续工作。
如果自动回溯哪天失效了，``--func-rva`` 可以直接接受函数的相对虚拟地址
（见 ``--static-only`` 的输出），而 ``--print-script`` 会转储 gdb 脚本。
"""

from __future__ import annotations

import argparse
import contextlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NoReturn

DEFAULT_QQ = "/opt/QQ/qq"
WRAPPER_CANDIDATES = [
    "/opt/QQ/resources/app/wrapper.node",
]
LOG_STRING = b"nt_sqlite3_key_v2: db=%p zDb=%s"
KEY_SIZE = 16

# 函数序言：push rbp; push r15; push r14; push r13; push r12; push rbx; push rax
PROLOGUES = [
    bytes.fromhex("5541574156415541545350"),
    # 函数序言：push rbp; push r15; push r14; push rbx; push rax
    bytes.fromhex("55415741565350"),
]

#: 引用该字符串的函数即 SQLCipher 的口令入口点。
SETPASS_STRING = b"sqlcipher_codec_ctx_set_pass: error %d from sqlcipher_cipher_ctx_set_pass"


def fail(message: str) -> NoReturn:
    raise SystemExit(f"error: {message}")


def require(tool: str) -> str:
    path = shutil.which(tool)
    if path is None:
        fail(f"{tool} is required but was not found on PATH")
    return path


def find_wrapper(explicit: str | None) -> Path:
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            fail(f"wrapper.node not found: {path}")
        return path
    for candidate in WRAPPER_CANDIDATES:
        if Path(candidate).is_file():
            return Path(candidate)
    for root in ("/opt/QQ/resources/app", str(Path.home() / ".config/QQ")):
        for found in Path(root).rglob("wrapper.node"):
            return found
    fail("could not find wrapper.node; pass --wrapper")


def read_sections(path: Path) -> dict[str, tuple[int, int, int]]:
    """解析 ``readelf -SW``，返回 ``{name: (vaddr, file_offset, size)}``。"""
    out = subprocess.run(["readelf", "-SW", str(path)], capture_output=True, text=True).stdout
    sections: dict[str, tuple[int, int, int]] = {}
    pattern = re.compile(
        r"\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)"
    )
    for match in pattern.finditer(out):
        name, _type, addr, offset, size = match.groups()
        sections[name] = (int(addr, 16), int(offset, 16), int(size, 16))
    return sections


def vaddr_to_offset(sections: dict[str, tuple[int, int, int]], vaddr: int) -> int:
    for _name, (addr, sec_off, size) in sections.items():
        if addr <= vaddr < addr + size:
            return sec_off + (vaddr - addr)
    return vaddr


def locate_string(path: Path, needle: bytes) -> tuple[int, int]:
    """返回 *needle* 在 *path* 中的 ``(file_offset, vaddr)``。"""
    sections = read_sections(path)
    data = path.read_bytes()
    offset = data.find(needle)
    if offset < 0:
        fail(f"the marker string {needle!r} was not found in {path}")
    for _name, (addr, sec_off, size) in sections.items():
        if sec_off <= offset < sec_off + size:
            return offset, addr + (offset - sec_off)
    return offset, offset


def find_references(path: Path, target_vaddr: int) -> list[int]:
    """引用 *target_vaddr* 的指令的虚拟地址。"""
    out = subprocess.run(
        ["objdump", "-d", "-j", ".text", str(path)],
        capture_output=True,
        text=True,
    ).stdout
    refs: list[int] = []
    comment = re.compile(f"#\\s*0*{target_vaddr:x}\\b")
    addr_re = re.compile(r"^\s*([0-9a-fA-F]+):")
    for line in out.splitlines():
        if "#" not in line or not comment.search(line):
            continue
        match = addr_re.match(line)
        if match:
            refs.append(int(match.group(1), 16))
    return refs


def find_function_start(path: Path, entry_vaddr: int, limit: int = 1 << 16) -> int | None:
    """从 *entry_vaddr* 逆向扫描，寻找已知的函数序言模式。"""
    sections = read_sections(path)
    off = vaddr_to_offset(sections, entry_vaddr)
    start_of_window = max(0, off - limit)
    with open(path, "rb") as handle:
        handle.seek(start_of_window)
        window = handle.read(min(limit, off) + 32)
    best = -1
    for pattern in PROLOGUES:
        found = window.rfind(pattern)
        if found > best:
            best = found
    if best < 0:
        return None
    file_off = start_of_window + best
    for _name, (addr, sec_off, size) in sections.items():
        if sec_off <= file_off < sec_off + size:
            return addr + (file_off - sec_off)
    return file_off


GDB_TEMPLATE = r"""
set pagination off
set confirm off
set breakpoint pending on
set width 0
python
import gdb

FUNC_RVA = {func_rva}
SETPASS_RVA = {setpass_rva}
ANCHOR_RVA = {anchor_rva}
ANCHOR_SYM = "{anchor_sym}"
LIBRARY = "{library}"
MAX_HITS = {max_hits}
MAX_LEN = 128

def emit(message):
    print("KEYRESULT:" + message, flush=True)

def read_ptr(expr):
    return int(gdb.parse_and_eval(expr))

try:
    # 一旦 wrapper.node 被映射进来就停下——此时 QQ 还没打开任何数据库。
    gdb.execute("catch load %s" % LIBRARY)
    gdb.execute("run")
    anchor = read_ptr("(unsigned long)&%s" % ANCHOR_SYM)
    base = anchor - ANCHOR_RVA
    emit("BASE %#x" % base)
    emit("FUNC %#x" % (base + FUNC_RVA))

    gdb.execute("delete breakpoints")
    for rva in (FUNC_RVA, SETPASS_RVA):
        if rva:
            gdb.execute("break *%#x" % (base + rva))

    seen = set()
    for _ in range(MAX_HITS):
        gdb.execute("continue")
        try:
            key_ptr = read_ptr("$rsi")
            nkey = read_ptr("$rdx")
        except gdb.error:
            continue
        if nkey <= 0 or nkey > MAX_LEN:
            continue
        try:
            data = gdb.selected_inferior().read_memory(key_ptr, nkey).tobytes()
        except gdb.error:
            continue
        if data in seen:
            continue
        seen.add(data)
        emit("CAND %d %s" % (nkey, data.hex()))
        try:
            emit("ASCII %d %s" % (nkey, data.decode("ascii")))
        except UnicodeDecodeError:
            pass
    emit("DONE")
    gdb.execute("quit")
except gdb.error as error:
    emit("ERROR %s" % error)
    try:
        gdb.execute("quit")
    except gdb.error:
        pass
end
"""


def find_symbol_vaddr(path: Path, name: str) -> int | None:
    """返回导出符号（dynsym）的虚拟地址。"""
    out = subprocess.run(
        ["readelf", "-sW", "--dyn-syms", str(path)], capture_output=True, text=True
    ).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[-1] == name and parts[3] == "FUNC":
            try:
                return int(parts[1], 16)
            except ValueError:
                continue
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[-1] == name:
            try:
                return int(parts[1], 16)
            except ValueError:
                continue
    return None


def build_gdb_script(
    func_rva: int,
    anchor_rva: int,
    anchor_sym: str,
    setpass_rva: int | None = None,
    max_hits: int = 100,
) -> str:
    return GDB_TEMPLATE.format(
        func_rva=func_rva,
        setpass_rva=setpass_rva or 0,
        anchor_rva=anchor_rva,
        anchor_sym=anchor_sym,
        library="wrapper.node",
        max_hits=max_hits,
    )


def run_gdb(qq: str, script: str, timeout: int | None) -> str:
    """运行 gdb 并返回它打印的所有内容。

    被调试进程会一直运行，直到 *timeout* 到期；返回截至彼时已产生的
    输出，因为关键行（候选密钥）是在发现时即时打印的。
    """
    gdb = require("gdb")
    with tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False) as handle:
        handle.write(script)
        script_path = handle.name
    try:
        result = subprocess.run(
            [gdb, "-q", "-batch", "-x", script_path, "--args", qq],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout + "\n" + result.stderr
    except subprocess.TimeoutExpired as expired:
        out = expired.stdout or b""
        err = expired.stderr or b""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        return out + "\n" + err
    finally:
        os.unlink(script_path)


def discover_db_dirs() -> list[Path]:
    base = Path.home() / ".config" / "QQ"
    dirs = sorted(
        [d for d in base.glob("nt_qq_*/nt_db") if d.is_dir()]
        + [d for d in [base / "global" / "nt_db"] if d.is_dir()]
    )
    return dirs


def validate_candidate(passphrase: bytes, dbdir: Path, limit: int = 4) -> int:
    """返回 *dbdir* 中有多少个数据库能用 *passphrase* 解密。"""
    try:
        from ntqq import sqlcipher  # 局部导入：keys/ 是独立脚本
    except ImportError:
        return -1
    ok = 0
    checked = 0
    for path in sorted(dbdir.glob("*.db")):
        if checked >= limit:
            break
        if path.stat().st_size < 2048:
            continue
        try:
            sqlcipher.read_header_and_salt(path)
        except ValueError:
            continue
        checked += 1
        try:
            if sqlcipher.detect_config(path, passphrase) is not None:
                ok += 1
        except Exception:
            pass
    return ok


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--wrapper", help="wrapper.node 的路径")
    parser.add_argument("--qq", default=DEFAULT_QQ, help="要调试的 QQ 可执行文件")
    parser.add_argument(
        "--static-only",
        action="store_true",
        help="只定位字符串、其引用和密钥函数",
    )
    parser.add_argument(
        "--func-rva",
        type=lambda value: int(value, 0),
        help="密钥函数的相对虚拟地址（跳过静态回溯）",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=240,
        help="监视进程的时长（秒）",
    )
    parser.add_argument(
        "--verify-dir",
        action="append",
        help="用于校验候选密钥的数据库目录（默认：所有 ~/.config/QQ/nt_qq_*/nt_db）",
    )
    parser.add_argument("--print-script", action="store_true", help="打印 gdb 脚本")
    args = parser.parse_args(argv)

    require("readelf")
    require("objdump")
    wrapper = find_wrapper(args.wrapper)

    offset, vaddr = locate_string(wrapper, LOG_STRING)
    refs = find_references(wrapper, vaddr)
    func_rva = args.func_rva
    if func_rva is None and refs:
        func_rva = find_function_start(wrapper, refs[0])

    anchor_rva = None
    anchor_sym = ""
    for candidate in ("LZ4_compress", "http_server_init", "http_async_call"):
        anchor_rva = find_symbol_vaddr(wrapper, candidate)
        if anchor_rva is not None:
            anchor_sym = candidate
            break

    setpass_rva = None
    try:
        _off, setpass_vaddr = locate_string(wrapper, SETPASS_STRING)
        setpass_refs = find_references(wrapper, setpass_vaddr)
        if setpass_refs:
            setpass_rva = find_function_start(wrapper, setpass_refs[0])
    except SystemExit:
        setpass_rva = None

    print(f"wrapper:        {wrapper}")
    print(f"字符串偏移：    {offset:#x}")
    print(f"字符串虚拟地址：{vaddr:#x}")
    print(f"引用：          {', '.join(hex(r) for r in refs) or '（未找到）'}")
    if func_rva is not None:
        print(f"密钥函数：      {func_rva:#x} (rva)")
    if setpass_rva is not None:
        print(f"set-pass:       {setpass_rva:#x} (rva)")
    if anchor_rva is not None:
        print(f"加载基准：      {anchor_sym} @ {anchor_rva:#x} (rva)")

    if args.static_only:
        return 0

    if func_rva is None and not refs:
        fail("could not locate the key function; pass --func-rva manually")
    if anchor_rva is None:
        fail("could not find an exported symbol to anchor the module base")

    script = build_gdb_script(func_rva, anchor_rva, anchor_sym, setpass_rva)
    if args.print_script:
        print(script)
        return 0

    if not Path(args.qq).exists():
        fail(f"QQ executable not found: {args.qq}")

    print(f"正在监视 QQ，最长 {args.timeout} 秒 ...", file=sys.stderr)
    output = run_gdb(args.qq, script, args.timeout)

    candidates: dict[bytes, int] = {}
    for line in output.splitlines():
        if not line.startswith("KEYRESULT:"):
            continue
        payload = line[len("KEYRESULT:") :]
        if payload.startswith(("BASE", "FUNC", "DONE", "ERROR")):
            print("  " + payload)
            continue
        if payload.startswith("CAND "):
            _, size, hexdata = payload.split(" ", 2)
            try:
                data = bytes.fromhex(hexdata)
            except ValueError:
                continue
            if int(size) == len(data):
                candidates[data] = candidates.get(data, 0) + 1

    if not candidates:
        print("\n未能恢复密钥（没有观察到任何密钥材料）", file=sys.stderr)
        return 1

    dirs = [Path(d).expanduser() for d in (args.verify_dir or [])]
    dirs = dirs or discover_db_dirs()

    print(f"\n候选密钥：{len(candidates)}")
    validated: list[bytes] = []
    for data in sorted(candidates, key=lambda item: -candidates[item]):
        try:
            printable = data.decode("ascii")
        except UnicodeDecodeError:
            printable = ""
        score = None
        for dbdir in dirs:
            got = validate_candidate(data, dbdir)
            if got > 0:
                score = f"{got} databases in {dbdir}"
                break
        label = f"{len(data):>3} bytes  {data.hex()}"
        if printable:
            label += f"  {printable!r}"
        if score:
            print(f"  VALID   {label}  ({score})")
            validated.append(data)
        else:
            print(f"  ?       {label}")

    if not validated:
        print("\n没有任何候选密钥能解密数据库", file=sys.stderr)
        return 1

    best = validated[0]
    print(f"\n密钥（hex）：{best.hex()}")
    with contextlib.suppress(UnicodeDecodeError):
        print(f"密钥（ascii）：{best.decode('ascii')}")
    print(f"\nexport NTQQ_DB_KEY='{best.decode('ascii', 'replace')}'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
