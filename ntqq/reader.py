"""对已解密 QQ NT 数据库的高层访问。

本模块把数字列消息表中的行转换为结构化的 :class:`MessageRecord` 对象。
每一列都会被保留：已知列在 :data:`COLUMN_NAMES` 中获得可读名称，
而原始的数字映射始终可通过 ``record.columns`` 获得。
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import protobuf
from .elements import MessageBody, decode_message_body

# 存放聊天消息的表。所有表的列布局都相同。
MESSAGE_TABLES = [
    "c2c_msg_table",
    "group_msg_table",
    "dataline_msg_table",
    "discuss_msg_table",
    "c2c_temp_msg_table",
    "service_assistant_msg_table",
    "ai_assistant_msg_table",
    "group_ai_assistant_msg_table",
]

# 其取值本身是 protobuf 的列，protobuf 被包装在以列命名的字段中。
# ``40800`` 是消息体。
BLOB_COLUMNS = [40800, 40900, 40801, 40600, 40601, 40605, 40062, 40722]

# 数字列的可读名称（尽力而为）。未列出的列仍会被导出，
# 只是使用其数字键。
COLUMN_NAMES: dict[int, str] = {
    40001: "msg_id",
    40002: "msg_seq",
    40003: "msg_type",
    40005: "msg_flags_a",
    40006: "msg_random",
    40008: "msg_flags_b",
    40009: "msg_flags_c",
    40010: "chat_type",
    40011: "chat_type_2",
    40012: "element_flags",
    40013: "sub_type",
    40020: "sender_uid",
    40021: "peer_uid",
    40026: "msg_flags_d",
    40027: "peer_uin",
    40030: "peer_uin_2",
    40033: "sender_uin",
    40040: "msg_flags_e",
    40041: "msg_flags_f",
    40050: "timestamp",
    40052: "msg_flags_g",
    40058: "server_time",
    40060: "msg_flags_h",
    40062: "msg_meta",
    40083: "sender_role",
    40084: "sender_level",
    40090: "sender_name",
    40093: "sender_card",
    40100: "msg_flags_i",
    40105: "msg_flags_j",
    40800: "body",
    40801: "msg_extra",
    40850: "msg_flags_k",
    40851: "msg_flags_l",
    40900: "msg_extra_2",
    40600: "msg_meta_2",
    40601: "msg_meta_3",
    40605: "msg_meta_4",
    40722: "msg_meta_5",
}


def column_name(number: int) -> str:
    return COLUMN_NAMES.get(number, f"col_{number}")


def unwrap_column(blob: bytes | None, number: int) -> bytes | None:
    """从列的 blob 中提取内部消息。

    QQ 以 ``<field number> = <bytes>`` 的形式存储 protobuf 取值；
    字段 tag 与列号一致。有些取值是直接原始存储的，
    因此当包装字段不存在时回退为原始字节。
    """
    if blob is None:
        return None
    if not isinstance(blob, (bytes, bytearray)):
        return None
    try:
        fields = protobuf.parse(bytes(blob))
    except protobuf.ProtobufError:
        return bytes(blob)
    inner = protobuf.first(fields, number)
    if inner is not None and inner.wire_type == protobuf.WIRE_LEN:
        return inner.value
    return bytes(blob)


def _jsonable(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"hex": bytes(value).hex()}
    return value


@dataclass
class MessageRecord:
    table: str
    columns: dict[int, Any]
    body: MessageBody | None = None

    # -- 便捷访问器 -------------------------------------------------------
    def col(self, number: int, default: Any = None) -> Any:
        value = self.columns.get(number, default)
        return value

    @property
    def msg_id(self) -> int | None:
        return self.col(40001)

    @property
    def timestamp(self) -> int | None:
        return self.col(40050)

    @property
    def time_str(self) -> str:
        ts = self.timestamp
        if not ts:
            return ""
        try:
            return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        except (OverflowError, OSError, ValueError):
            return str(ts)

    @property
    def text(self) -> str:
        return self.body.text() if self.body else ""

    def to_dict(self, include_raw_columns: bool = True) -> dict[str, Any]:
        record: dict[str, Any] = {
            "table": self.table,
            "msg_id": self.msg_id,
            "timestamp": self.timestamp,
            "time": self.time_str,
            "chat_type": self.col(40010),
            "peer_uid": self.col(40021),
            "peer_uin": self.col(40027),
            "sender_uid": self.col(40020),
            "sender_uin": self.col(40033),
            "sender_name": self.col(40090),
            "sender_card": self.col(40093),
            "text": self.text,
        }
        if self.body is not None:
            record["element_type"] = self.body.msg_type
            record["element_type_name"] = self.body.element_type_name
            record["elements"] = [e.to_dict() for e in self.body.elements]
        if include_raw_columns:
            record["columns"] = {str(k): _jsonable(v) for k, v in sorted(self.columns.items())}
        return record


class MessageDatabase:
    """已解密 QQ NT 数据库的只读包装。"""

    def __init__(self, path: str | Path):
        self.path = str(path)
        self.conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        self.conn.row_factory = None

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> MessageDatabase:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def tables(self) -> list[str]:
        rows = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        return [row[0] for row in rows]

    def message_tables(self) -> list[str]:
        present = set(self.tables())
        return [t for t in MESSAGE_TABLES if t in present]

    def columns(self, table: str) -> list[int]:
        rows = self.conn.execute(f'PRAGMA table_info("{table}")').fetchall()
        out = []
        for row in rows:
            name = row[1]
            with contextlib.suppress(ValueError):
                out.append(int(name))
        return out

    def count(self, table: str) -> int:
        # ``NOT INDEXED`` 强制进行全表扫描：QQ 数据库的二级索引可能损坏，
        # 而表本身的 b-tree 仍然完好。
        return self.conn.execute(f'SELECT count(*) FROM "{table}" NOT INDEXED').fetchone()[0]

    def iter_messages(
        self,
        table: str,
        where: str | None = None,
        limit: int | None = None,
        order_by: str | None = None,
        decode: bool = True,
        batch_size: int = 5000,
        not_indexed: bool = True,
    ) -> Iterator[MessageRecord]:
        columns = self.columns(table)
        col_list = ", ".join(f'"{c}"' for c in columns)
        sql = f'SELECT {col_list} FROM "{table}"'
        if not_indexed:
            sql += " NOT INDEXED"
        if where:
            sql += f" WHERE {where}"
        if order_by:
            sql += f" ORDER BY {order_by}"
        if limit is not None:
            sql += f" LIMIT {int(limit)}"

        cursor = self.conn.execute(sql)
        while True:
            rows = cursor.fetchmany(batch_size)
            if not rows:
                break
            for row in rows:
                values = dict(zip(columns, row, strict=True))
                body = None
                if decode and 40800 in values:
                    inner = unwrap_column(values.get(40800), 40800)
                    if inner:
                        body = decode_message_body(inner)
                yield MessageRecord(table=table, columns=values, body=body)
