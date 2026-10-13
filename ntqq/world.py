"""高层 API：打开 QQ 配置目录、浏览会话、检索、导出。

参照参考项目的 ``db.DatabaseManager`` + ``Communicant`` 类设计，但它同样能直接
处理*加密*的配置目录：传入 ``~/.config/QQ/nt_qq_<profile>``，它会先把数据库
解密（并可选地修复）到一个缓存目录。

    from ntqq.world import QQNT

    qq = QQNT.open(profile="~/.config/QQ/nt_qq_<profile>", key="<passphrase>")

    for group in qq.groups():
        print(group.uin, group.name, group.member_count, group.unread)

    chat = qq.group(1145141919810)
    for message in chat.messages(limit=50, order="desc"):
        print(message.time_str, message.display_sender, message.text)

    for message in qq.search("关键词", chat=chat, since="2025-09-01"):
        print(message)

    qq.export_html(chat, "group.html")
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import hashlib
import json
import os
import sqlite3
import time
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from dataclasses import field as dc_field
from pathlib import Path
from typing import Any, TextIO

from . import export as exporters
from . import schema, sqlcipher
from .message import Message
from .orm import DatabaseManager, Table

DEFAULT_CACHE = Path(os.environ.get("NTQQ_CACHE", Path.home() / ".cache" / "ntqq-py"))

#: 所有消息表模型（用于快速判断某张表是否需要逐条解析消息体）。
MESSAGE_MODELS: frozenset = frozenset(schema.MESSAGE_MODELS.values())

MESSAGE_TABLES: dict[str, str] = {
    "group": "group_msg_table",
    "c2c": "c2c_msg_table",
    "dataline": "dataline_msg_table",
    "discuss": "discuss_msg_table",
    "temp": "c2c_temp_msg_table",
    "service": "service_assistant_msg_table",
    "ai": "ai_assistant_msg_table",
}


# ---------------------------------------------------------------------------
# 配置目录准备
# ---------------------------------------------------------------------------


def repair_file(path: str | Path) -> list[str]:
    """让已解密的数据库能被标准 SQLite 读取。

    QQ 在 ``nt_msg.db`` 中留下了一个结构损坏的索引（``group_msg_table_idx40027_40058``
    内存在重复的页引用）。表的 b-tree 是完整的，因此重建或删除该索引即可恢复
    完整可读性，而无需改动任何行数据。
    """
    path = Path(path)
    actions: list[str] = []
    connection = sqlite3.connect(str(path))
    try:
        check = _quick_check(connection)
        if check == "ok":
            actions.append("quick_check: ok")
            return actions
        actions.append("quick_check: " + check.replace("\n", "; "))

        indexes = [
            (row[0], row[1])
            for row in connection.execute(
                "SELECT name, rootpage FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"
            )
        ]
        for name, _rootpage in indexes:
            if _try(connection, f'REINDEX "{name}"'):
                actions.append(f"reindex {name}: ok")
                continue
            if _try(connection, f'DROP INDEX IF EXISTS "{name}"'):
                actions.append(f"drop {name}: ok")
                continue
            if _try(
                connection,
                "PRAGMA writable_schema=ON",
                f"DELETE FROM sqlite_master WHERE type='index' AND name='{name.replace(chr(39), chr(39) * 2)}'",
            ):
                actions.append(f"schema-drop {name}: ok")
                continue
            actions.append(f"could not repair {name}")

        after = _quick_check(connection)
        actions.append("quick_check after repair: " + after.replace("\n", "; "))
    finally:
        connection.close()
    return actions


def _try(connection: sqlite3.Connection, *statements: str) -> bool:
    try:
        for statement in statements:
            connection.execute(statement)
        connection.commit()
        return True
    except sqlite3.Error:
        return False


def _quick_check(connection: sqlite3.Connection) -> str:
    try:
        rows = connection.execute("PRAGMA quick_check").fetchall()
    except sqlite3.DatabaseError as exc:
        return f"error: {exc}"
    return "\n".join(row[0] for row in rows)


def prepare_profile(
    source: str | Path,
    key: bytes | str | None,
    *,
    target: str | Path | None = None,
    repair: bool = True,
    progress=None,
) -> Path:
    """将 QQ 配置目录中的每个 ``*.db`` 解密到 *target* 并修复它们。

    返回存放明文数据库的目录。已解密的文件会被复用，除非它们比其加密源文件更旧。
    """
    source = Path(source).expanduser()
    if not source.is_dir():
        raise NotADirectoryError(source)
    if (source / "nt_db").is_dir():
        source = source / "nt_db"
    if isinstance(key, str):
        key = key.encode("utf-8")

    if target is None:
        digest = hashlib.sha256(str(source.resolve()).encode()).hexdigest()[:16]
        target = DEFAULT_CACHE / digest
    target = Path(target)
    target.mkdir(parents=True, exist_ok=True)

    decrypted = 0
    failures: list[str] = []
    for database in sorted(source.glob("*.db")):
        destination = target / database.name
        if (
            destination.is_file()
            and destination.stat().st_mtime >= database.stat().st_mtime
            and destination.stat().st_size > 0
        ):
            decrypted += 1
            continue
        try:
            header = database.read_bytes()[:1024]
        except OSError:
            continue
        if len(header) < 1024:
            continue
        if not sqlcipher.looks_encrypted(header):
            destination.write_bytes(database.read_bytes())
            decrypted += 1
            continue
        if database.stat().st_size <= 1024 + sqlcipher.PAGE_SIZE:
            # 仅含容器头的文件（QQ 会预留少量这类文件），没有可读内容。
            continue
        if not key:
            raise ValueError(
                f"{database.name} is encrypted and no key was supplied "
                "(pass key=... or set NTQQ_DB_KEY)"
            )
        config = sqlcipher.detect_config(database, key)
        if config is None:
            failures.append(database.name)
            continue
        try:
            sqlcipher.decrypt_file(database, destination, key, config=config, progress=progress)
            wal = database.with_name(database.name + "-wal")
            if wal.is_file() and wal.stat().st_size:
                keys = _keys(database, key, config)
                pages, db_size = sqlcipher.decrypt_wal(wal, keys)
                if pages:
                    sqlcipher.apply_wal(destination, pages, db_size)
            if repair:
                repair_file(destination)
            decrypted += 1
        except Exception as error:  # 继续处理：单个损坏文件不应中断其余文件
            failures.append(f"{database.name} ({error})")
            destination.unlink(missing_ok=True)

    if failures and not decrypted:
        raise ValueError(
            "cannot decrypt the profile: " + "; ".join(failures) + " - is the key correct?"
        )
    if failures:
        print(f"warning: skipped {', '.join(failures)}", file=os.sys.stderr)
    return target


def _profile_is_plain(directory: Path) -> bool:
    """*directory* 中的数据库是否已经解密？

    QQ 配置目录中混合了两种文件（``bc_09.db`` 是明文 SQLite，其余都已加密），
    因此判断时先看 ``nt_msg.db``，然后才看其余文件——只要发现任何加密文件
    就视为“非明文”。
    """
    preferred = directory / "nt_msg.db"
    candidates = [preferred] if preferred.is_file() else []
    candidates += [p for p in sorted(directory.glob("*.db")) if p != preferred]
    for path in candidates:
        try:
            head = path.read_bytes()[:1024]
        except OSError:
            continue
        if len(head) < 1024:
            continue
        if sqlcipher.looks_encrypted(head):
            return False
    return True


def _keys(database: Path, key: bytes, config: sqlcipher.CipherConfig):
    _header, salt = sqlcipher.read_header_and_salt(database)
    return sqlcipher.keys_for(key, salt, config)


# ---------------------------------------------------------------------------
# 联系人
# ---------------------------------------------------------------------------


@dataclass
class Contact:
    """从该账号视角看到的一个联系人或群。"""

    uid: str | None = None
    uin: int | None = None
    nickname: str | None = None
    remark: str | None = None
    kind: str = "unknown"
    avatar: str | None = None
    extra: dict[str, Any] = dc_field(default_factory=dict)

    @property
    def display_name(self) -> str:
        return (
            self.remark
            or self.nickname
            or (str(self.uin) if self.uin is not None else self.uid or "?")
        )

    @property
    def name(self) -> str | None:
        """:attr:`nickname` 的别名（与参考项目的命名保持一致）。"""
        return self.nickname

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "uid": self.uid,
            "uin": self.uin,
            "nickname": self.nickname,
            "remark": self.remark,
            "display_name": self.display_name,
            **self.extra,
        }

    def __str__(self) -> str:
        return self.display_name

    def __hash__(self) -> int:
        return hash((self.kind, self.uid, self.uin))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Contact) and (self.kind, self.uid, self.uin) == (
            other.kind,
            other.uid,
            other.uin,
        )


@dataclass
class Group(Contact):
    kind: str = "group"
    member_count: int | None = None
    max_member: int | None = None
    create_time: int | None = None
    bulletin: bytes | None = None

    @property
    def create_time_str(self) -> str:
        if not self.create_time:
            return ""
        try:
            return _dt.datetime.fromtimestamp(self.create_time).strftime("%Y-%m-%d")
        except (OverflowError, OSError, ValueError):
            return str(self.create_time)


@dataclass
class Friend(Contact):
    kind: str = "friend"
    category: int | None = None
    signature: str | None = None


# ---------------------------------------------------------------------------
# 主门面
# ---------------------------------------------------------------------------


@dataclass
class ScanReport:
    """逐行解析整库后的统计与问题清单（供测试与 ``ntqq scan`` 使用）。"""

    directory: str = ""
    tables: dict[str, int] = dc_field(default_factory=dict)
    missing_columns: dict[str, list[str]] = dc_field(default_factory=dict)
    table_failures: dict[str, str] = dc_field(default_factory=dict)
    rows: int = 0
    decoded: int = 0
    empty_bodies: int = 0
    kinds: dict[str, int] = dc_field(default_factory=dict)
    unsupported: int = 0
    unsupported_types: dict[str, int] = dc_field(default_factory=dict)
    decoder_errors: dict[str, int] = dc_field(default_factory=dict)
    first_time: int | None = None
    last_time: int | None = None
    samples: list[dict[str, Any]] = dc_field(default_factory=list)
    failures: list[dict[str, Any]] = dc_field(default_factory=list)
    failures_total: int = 0
    seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return self.failures_total == 0 and not self.table_failures and not self.decoder_errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "directory": self.directory,
            "tables": dict(self.tables),
            "rows": self.rows,
            "decoded": self.decoded,
            "empty_bodies": self.empty_bodies,
            "kinds": dict(sorted(self.kinds.items(), key=lambda kv: -kv[1])),
            "unsupported": self.unsupported,
            "unsupported_types": dict(self.unsupported_types),
            "decoder_errors": dict(self.decoder_errors),
            "missing_columns": {k: v for k, v in self.missing_columns.items() if v},
            "table_failures": dict(self.table_failures),
            "time_range": [self.first_time, self.last_time],
            "seconds": round(self.seconds, 2),
            "failures_total": self.failures_total,
            "failures": self.failures,
            "ok": self.ok,
        }

    def summary(self) -> str:
        """人类可读的中文报告。"""
        lines = [
            f"目录        {self.directory}",
            f"表数量      {len(self.tables)}",
            f"总行数      {self.rows:,}",
            f"解析消息数  {self.decoded:,}（其中空消息体 {self.empty_bodies:,}）",
            f"耗时        {self.seconds:.1f}s",
        ]
        if self.first_time and self.last_time:
            lines.append(f"时间范围    {_fmt_time(self.first_time)} ~ {_fmt_time(self.last_time)}")
        if self.unsupported_types:
            lines.append(
                "未知元素类型"
                + "; ".join(f"{k} / {v}" for k, v in sorted(self.unsupported_types.items()))
            )
        if self.decoder_errors:
            lines.append(
                "解码失败    " + "; ".join(f"{k} / {v}" for k, v in self.decoder_errors.items())
            )
        if self.kinds:
            kinds = "、".join(
                f"{k} {v:,}" for k, v in sorted(self.kinds.items(), key=lambda kv: -kv[1])
            )
            lines.append(f"元素类型    {kinds}")
        missing = {k: v for k, v in self.missing_columns.items() if v}
        if missing:
            lines.append(
                "缺列的表    " + "; ".join(f"{k}({len(v)} 列)" for k, v in missing.items())
            )
        if self.table_failures:
            lines.append(
                "读表失败    " + "; ".join(f"{k}: {v}" for k, v in self.table_failures.items())
            )
        if self.samples:
            lines.append(
                "样例        " + " | ".join(s["text"][:24] or s["type"] for s in self.samples)
            )
        lines.append(
            "结果        "
            + ("全部通过，无解析失败" if self.ok else f"{self.failures_total} 行解析失败")
        )
        for failure in self.failures[:10]:
            lines.append(f"  ! {failure}")
        return "\n".join(lines)


def _fmt_time(ts: int) -> str:
    try:
        return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return str(ts)


class QQNT:
    """入口点：打开一个配置目录（加密的或已解密的）。"""

    def __init__(
        self, directory: str | Path, *, writable: bool = False, not_indexed: bool = True
    ) -> None:
        self.directory = Path(directory)
        self.manager = DatabaseManager(self.directory, writable=writable, not_indexed=not_indexed)
        self._uid_to_uin: dict[str, int] = {}
        self._uin_to_uid: dict[int, str] = {}
        self._names: dict[str, str] = {}
        self._load_identity_maps()

    # -- 构造 -----------------------------------------------------------
    @classmethod
    def open(
        cls,
        profile: str | Path,
        key: bytes | str | None = None,
        *,
        plain_dir: str | Path | None = None,
        cache: str | Path | None = None,
        repair: bool = True,
        writable: bool = False,
        progress=None,
    ) -> QQNT:
        """打开 QQ 配置目录或已解密数据库所在目录。

        ``profile`` 可以是 ``.../nt_qq_<profile>``（内含 ``nt_db``），也可以是
        ``nt_db`` 目录本身。若其中已是明文 SQLite 文件，则直接使用。
        """
        profile = Path(profile).expanduser()
        if key is None:
            key = os.environ.get("NTQQ_DB_KEY")
        probe = profile / "nt_db" if (profile / "nt_db").is_dir() else profile
        if _profile_is_plain(probe):
            directory = probe
        else:
            directory = prepare_profile(probe, key, target=cache, repair=repair, progress=progress)
        return cls(directory, writable=writable)

    def close(self) -> None:
        self.manager.close()

    def __enter__(self) -> QQNT:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- 身份 -----------------------------------------------------------
    def _load_identity_maps(self) -> None:
        tables = self.manager.tables
        if "nt_uid_mapping_table" in tables:
            for row in tables["nt_uid_mapping_table"].all():
                uid, uin = row.uid, row.uin
                if uid and uin:
                    self._uid_to_uin[uid] = uin
                    self._uin_to_uid.setdefault(uin, uid)
        if "profile_info_v6" in tables:
            for row in tables["profile_info_v6"].all():
                if row.uid:
                    if row.uin:
                        self._uid_to_uin.setdefault(row.uid, row.uin)
                        self._uin_to_uid.setdefault(row.uin, row.uid)
                    if row.nickname or row.remark:
                        self._names[row.uid] = row.remark or row.nickname
        if "buddy_list" in tables:
            for row in tables["buddy_list"].all():
                if row.uid and row.uin:
                    self._uid_to_uin.setdefault(row.uid, row.uin)
                    self._uin_to_uid.setdefault(row.uin, row.uid)

    def uin_of(self, uid: str | None) -> int | None:
        return self._uid_to_uin.get(uid) if uid else None

    def uid_of(self, uin: int | None) -> str | None:
        return self._uin_to_uid.get(uin) if uin else None

    def name_of(self, uid: str | None = None, uin: int | None = None) -> str | None:
        if uid and uid in self._names:
            return self._names[uid]
        if uid and uid in self._uid_to_uin:
            return str(self._uid_to_uin[uid])
        return str(uin) if uin else None

    # -- 联系人 ---------------------------------------------------------
    def groups(self) -> list[Group]:
        table = self.manager.tables.get("group_list")
        if table is None:
            return []
        details = {}
        detail_table = self.manager.tables.get("group_detail_info_ver1")
        if detail_table is not None:
            details = {row.group_uin: row for row in detail_table.all()}
        out = []
        for row in table.all():
            detail = details.get(row.group_uin)
            out.append(
                Group(
                    uid=self.uid_of(row.group_uin),
                    uin=row.group_uin,
                    nickname=row.name,
                    remark=row.remark,
                    member_count=row.member_count,
                    max_member=row.max_member,
                    create_time=row.create_time,
                    bulletin=getattr(detail, "bulletin", None) if detail else None,
                    extra={"owner_uid": getattr(detail, "owner_uid", None) if detail else None},
                )
            )
        out.sort(key=lambda g: g.uin or 0)
        return out

    def friends(self) -> list[Friend]:
        buddies = self.manager.tables.get("buddy_list")
        if buddies is None:
            return []
        profiles = {}
        profile_table = self.manager.tables.get("profile_info_v6")
        if profile_table is not None:
            profiles = {row.uid: row for row in profile_table.all()}
        out = []
        for row in buddies.all():
            profile = profiles.get(row.uid)
            out.append(
                Friend(
                    uid=row.uid,
                    uin=row.uin,
                    nickname=getattr(profile, "nickname", None) if profile else None,
                    remark=getattr(profile, "remark", None) if profile else None,
                    category=row.category,
                    signature=getattr(profile, "signature", None) if profile else None,
                    avatar=getattr(profile, "avatar_url", None) if profile else None,
                )
            )
        out.sort(key=lambda f: f.uin or 0)
        return out

    def group(self, key: int | str) -> Group | None:
        for group in self.groups():
            if group.uin == key or (isinstance(key, str) and group.uid == key):
                return group
        return None

    def friend(self, key: int | str) -> Friend | None:
        for friend in self.friends():
            if friend.uin == key or (isinstance(key, str) and friend.uid == key):
                return friend
        return None

    def contact(self, key: int | str) -> Contact | None:
        """将 uin / uid / 昵称片段解析为一个联系人。"""
        if isinstance(key, str) and key.isdigit():
            key = int(key)
        if isinstance(key, int):
            return self.group(key) or self.friend(key)
        group = self.group(key)
        if group:
            return group
        friend = self.friend(key)
        if friend:
            return friend
        lowered = str(key).lower()
        for candidate in (*self.groups(), *self.friends()):
            haystacks = (
                candidate.display_name,
                candidate.nickname,
                candidate.remark,
                candidate.uid,
            )
            if any(h and lowered in h.lower() for h in haystacks):
                return candidate
        return None

    def members(self, group: Group | int) -> list[dict[str, Any]]:
        table = self.manager.tables.get("group_member3")
        if table is None:
            return []
        uin = group.uin if isinstance(group, Group) else int(group)
        out = []
        for row in table.filter(group_uin=uin).all():
            out.append(
                {
                    "uid": row.uid,
                    "uin": row.uin,
                    "nickname": row.nickname,
                    "card": row.card,
                    "admin": row.admin,
                    "level": row.level,
                    "join_time": row.join_time,
                    "last_message_time": row.last_message_time,
                }
            )
        return out

    # -- 消息 -----------------------------------------------------------
    def _message_tables(self, scope: str | None) -> list[tuple[str, Table]]:
        if scope and scope in MESSAGE_TABLES:
            names = [MESSAGE_TABLES[scope]]
        elif scope:
            names = list(MESSAGE_TABLES.values())
        else:
            names = list(MESSAGE_TABLES.values())
        out = []
        for name in names:
            table = self.manager.tables.get(name)
            if table is not None:
                out.append((name, table))
        return out

    def _messages_of(
        self,
        table: Table,
        *,
        chat: Contact | None,
        limit: int | None,
        since: Any,
        until: Any,
        sender: Any,
        order: str,
        where: str | None,
    ) -> Iterator[Message]:
        query = table.query()
        is_group_table = table.model in (schema.GroupMessage, schema.AtMeMessage)
        if chat is not None:
            if is_group_table or chat.kind == "group":
                query.filter(peer_uin=chat.uin if chat.uin is not None else -1)
            else:
                query.where(
                    '("40021" = ? OR "40027" = ? OR "40030" = ? OR "40020" = ?)',
                    chat.uid or "",
                    chat.uin or -1,
                    chat.uin or -1,
                    chat.uid or "",
                )
        if since is not None:
            query.where('"40050" >= ?', _to_timestamp(since))
        if until is not None:
            query.where('"40050" <= ?', _to_timestamp(until, end_of_day=True))
        if sender is not None:
            if isinstance(sender, int):
                query.where('("40033" = ? OR "40020" = ?)', sender, self.uid_of(sender) or "")
            else:
                query.where(
                    '("40020" = ? OR "40090" LIKE ? OR "40093" LIKE ?)',
                    sender,
                    f"%{sender}%",
                    f"%{sender}%",
                )
        if where:
            query.where(where)
        order_by = "-msg_time" if order == "desc" else "msg_time"
        query.order_by(order_by)
        if limit:
            query.limit(limit)
        for row in query.iterate():
            yield Message.from_row(row)

    def messages(
        self,
        *,
        chat: Contact | int | str | None = None,
        scope: str | None = None,
        limit: int | None = None,
        since: Any = None,
        until: Any = None,
        sender: Any = None,
        order: str = "asc",
        where: str | None = None,
        decode: bool = True,
    ) -> Iterator[Message]:
        """迭代消息，可选地限定到单个会话/范围。

        ``scope`` 取 ``group``、``c2c``、``dataline``、``discuss``、``temp``、
        ``service``、``ai`` 之一（默认：全部）。``chat`` 接受
        :class:`Contact`/:class:`Group`/:class:`Friend`、一个 uin 或一个 uid。
        """
        if chat is not None and not isinstance(chat, Contact):
            chat = self.contact(chat)
        for _name, table in self._message_tables(scope):
            yield from self._messages_of(
                table,
                chat=chat,
                limit=limit,
                since=since,
                until=until,
                sender=sender,
                order=order,
                where=where,
            )

    def history(
        self,
        chat: Contact | int | str,
        *,
        limit: int = 100,
        since: Any = None,
        until: Any = None,
        order: str = "asc",
    ) -> list[Message]:
        """某个会话的最新消息，默认最旧的在前。

        ``limit`` 从最新一条消息（或从 ``until``）向前计数，因此
        ``history(chat, limit=50)`` 表示“最近 50 条消息”。传入
        ``order="desc"`` 可让它们按最新在前返回。
        """
        if not isinstance(chat, Contact):
            resolved = self.contact(chat)
            if resolved is None:
                raise KeyError(f"unknown chat {chat!r}")
            chat = resolved
        table = self.manager.tables[MESSAGE_TABLES["group" if chat.kind == "group" else "c2c"]]
        # 始终取最新的 `limit` 行，再按要求的顺序排列结果。
        found = list(
            self._messages_of(
                table,
                chat=chat,
                limit=limit,
                since=since,
                until=until,
                sender=None,
                order="desc",
                where=None,
            )
        )
        if order == "desc":
            return found
        found.reverse()
        return found

    # -- 检索 -----------------------------------------------------------
    def search(
        self,
        keyword: str,
        *,
        chat: Contact | int | str | None = None,
        scope: str | None = None,
        since: Any = None,
        until: Any = None,
        sender: Any = None,
        kinds: Sequence[str] | None = None,
        limit: int | None = None,
        case_sensitive: bool = False,
        include_media_text: bool = True,
    ) -> list[Message]:
        """在消息体（以及媒体摘要/文件名）中检索 *keyword*。

        在解码任何内容之前，会先在原始 protobuf 上运行一次廉价的字节级预过滤，
        因此扫描数百万行仍然可行。
        """
        needle = keyword if case_sensitive else keyword.lower()
        needle_bytes = keyword.encode("utf-8")
        if chat is not None and not isinstance(chat, Contact):
            chat = self.contact(chat)
        wanted = set(kinds) if kinds else None

        found: list[Message] = []
        for name, table in self._message_tables(scope):
            if name == "group_at_me_msg":
                continue
            for message in self._messages_of(
                table,
                chat=chat,
                limit=None,
                since=since,
                until=until,
                sender=sender,
                order="asc",
                where=None,
            ):
                body = message.columns.get(40800)
                if not isinstance(body, (bytes, bytearray)) or needle_bytes not in body:
                    continue
                text = message.text
                haystack = text if case_sensitive else text.lower()
                if not include_media_text and not any(e.kind == "text" for e in message.elements):
                    continue
                if needle not in haystack:
                    continue
                if wanted and not any(e.kind in wanted for e in message.elements):
                    continue
                found.append(message)
                if limit and len(found) >= limit:
                    return found
        return found

    # -- 统计 -----------------------------------------------------------
    def scan(
        self,
        *,
        limit: int | None = None,
        tables: Sequence[str] | None = None,
        samples: int = 5,
        dump: str | Path | TextIO | None = None,
        progress=None,
        strict: bool = False,
        max_failures: int = 200,
        batch: int = 4096,
    ) -> ScanReport:
        """逐表、逐行读取整库，并对每条消息做完整解析，返回 :class:`ScanReport`。

        这是"代码可用性"的穷举验证：任何一行读不出来、或某条消息体解不开，
        都会被记进 ``report.failures``（而不是中断整个扫描）。给定 *dump* 时，
        同时把每一条解析结果以 JSON Lines 写出。

        *limit* 限制**每张表**的最大行数（用于快速抽样）；*progress* 是
        ``callable(表名, 已处理行数)`` 形式的回调；``strict=True`` 时首个错误
        立即抛出；失败明细最多记录 *max_failures* 条（总数照常累加）。
        """
        report = ScanReport(directory=str(self.directory))
        started = time.monotonic()

        with contextlib.ExitStack() as stack:
            if dump is None:
                sink = None
            elif isinstance(dump, (str, Path)):
                sink = stack.enter_context(open(dump, "w", encoding="utf-8"))
            else:
                sink = dump

            for name, table in sorted(self.manager.tables.items()):
                if tables and name not in tables:
                    continue
                if table.columns_missing:
                    report.missing_columns[name] = [str(c.number) for c in table.columns_missing]
                report.tables[name] = 0
                is_message_table = table.model in MESSAGE_MODELS
                # 表级问题（例如模型列号与真实表完全不匹配）只记录，不阻断其余表；
                # 注意 query().iterate() 是生成器，异常要到迭代时才抛出。
                try:
                    for count, row in enumerate(table.query().iterate(batch=batch), 1):
                        report.tables[name] = count
                        report.rows += 1
                        if is_message_table:
                            self._scan_message(row, report, sink, samples, max_failures, strict)
                        if progress and count % 20000 == 0:
                            progress(name, count)
                        if limit and count >= limit:
                            break
                except Exception as error:
                    if strict:
                        raise
                    report.table_failures[name] = f"{type(error).__name__}: {error}"

        report.seconds = time.monotonic() - started
        return report

    def _scan_message(
        self,
        row: Any,
        report: ScanReport,
        sink,
        samples: int,
        max_failures: int,
        strict: bool,
    ) -> None:
        try:
            message = Message.from_row(row)
            payload = message.to_dict()
            # 序列化一遍，确保结果真的可被 JSON 消费（导出路径的实际要求）。
            line = json.dumps(payload, ensure_ascii=False)
        # 逐行容错：单行解析失败只记进报告，不中断整库扫描
        except Exception as error:
            if strict:
                raise
            report.failures_total += 1
            if len(report.failures) >= max_failures:
                return
            report.failures.append(
                {
                    "table": getattr(row, "table", "") or type(row).__name__,
                    "msg_id": getattr(row, "msg_id", None),
                    "error": f"{type(error).__name__}: {error}",
                }
            )
            return
        report.decoded += 1
        if not message.columns.get(40800):
            report.empty_bodies += 1
        for element in message.elements:
            report.kinds[element.kind] = report.kinds.get(element.kind, 0) + 1
            if element.kind == "unsupported":
                report.unsupported += 1
                error = getattr(element, "error", None)
                if error:
                    key = f"45002={element.element_type}: {error}"
                    report.decoder_errors[key] = report.decoder_errors.get(key, 0) + 1
                else:
                    key = str(element.element_type)
                    report.unsupported_types[key] = report.unsupported_types.get(key, 0) + 1
        if message.time:
            if report.first_time is None or message.time < report.first_time:
                report.first_time = message.time
            if report.last_time is None or message.time > report.last_time:
                report.last_time = message.time
        if len(report.samples) < samples:
            report.samples.append(payload)
        if sink is not None:
            sink.write(line)
            sink.write("\n")

    # -- 统计 -----------------------------------------------------------
    def stats(self) -> dict[str, Any]:
        out: dict[str, Any] = {"directory": str(self.directory), "tables": {}}
        for _filename, database in sorted(self.manager.databases.items()):
            for name, table in sorted(database.tables.items()):
                try:
                    out["tables"][name] = table.count()
                except sqlite3.DatabaseError as exc:
                    out["tables"][name] = f"error: {exc}"
        out["groups"] = len(self.groups())
        out["friends"] = len(self.friends())
        return out

    # -- 导出 -----------------------------------------------------------
    def export_jsonl(self, messages: Iterable[Message], target: Any, **kwargs: Any) -> int:
        return exporters.export_jsonl(messages, target, **kwargs)

    def export_csv(self, messages: Iterable[Message], target: Any) -> int:
        return exporters.export_csv(messages, target)

    def export_markdown(
        self, messages: Iterable[Message], target: Any, title: str = "聊天记录"
    ) -> int:
        return exporters.export_markdown(messages, target, title)

    def export_html(
        self,
        messages: Iterable[Message] | Contact | int | str,
        target: Any,
        *,
        title: str | None = None,
        limit: int | None = None,
    ) -> int:
        if not isinstance(messages, Iterable) or isinstance(messages, (Contact, int, str)):
            chat = messages
            if not isinstance(chat, Contact):
                chat = self.contact(chat)
            if chat is None:
                raise KeyError(f"unknown chat {chat!r}")
            stream = self.history(chat, limit=limit or 10_000)
            title = title or f"{chat.display_name} ({chat.kind})"
        else:
            stream = messages
            title = title or "聊天记录"
        return exporters.export_html(stream, target, title=title)


# ---------------------------------------------------------------------------


def _to_timestamp(value: Any, *, end_of_day: bool = False) -> int | None:
    """接受 datetime、date、ISO 字符串或 int/float 时间戳。

    仅含日期的字符串表示一整天：配合 ``end_of_day`` 解析为 23:59:59，
    否则解析为 00:00:00。
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, _dt.datetime):
        return int(value.timestamp())
    if isinstance(value, _dt.date):
        moment = _dt.datetime(value.year, value.month, value.day)
        return int(moment.timestamp()) + (86399 if end_of_day else 0)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.isdigit():
            return int(text)
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
            try:
                return int(_dt.datetime.strptime(text, fmt).timestamp())
            except ValueError:
                continue
        for fmt in ("%Y-%m-%d", "%Y/%m/%d"):
            try:
                moment = _dt.datetime.strptime(text, fmt)
                return int(moment.timestamp()) + (86399 if end_of_day else 0)
            except ValueError:
                continue
        for fmt in ("%Y-%m", "%Y/%m"):
            try:
                moment = _dt.datetime.strptime(text, fmt)
            except ValueError:
                continue
            if end_of_day:  # 整月 -> 最后一天 23:59:59
                year, month = moment.year, moment.month
                if month == 12:
                    following = _dt.datetime(year + 1, 1, 1)
                else:
                    following = _dt.datetime(year, month + 1, 1)
                return int(following.timestamp()) - 1
            return int(moment.timestamp())
        try:
            return int(_dt.datetime.fromisoformat(text).timestamp())
        except ValueError:
            raise ValueError(f"cannot parse time {value!r}") from None
    raise TypeError(f"unsupported time value {value!r}")
