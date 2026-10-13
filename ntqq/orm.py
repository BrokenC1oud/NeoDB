"""QQ NT 数据库专用的微型 ORM，零依赖。

参考项目（``nt_msg.py``）用 SQLAlchemy 把 QQ 的数字列映射为具名属性。
本模块只用标准库完成同样的事：:class:`Model` 只需声明一次列映射，
查询返回的对象便带有易读的属性名::

    db.group_messages.filter(groupUin=1145141919810).count()
    for msg in db.group_messages.order_by("-msgTime").limit(20):
        print(msg.msgTime, msg.senderUid, len(msg.msgBody))

列名就是 QQ 用作 SQL 标识符的数字协议字段号（``"40001"`` 等）；
列映射定义在 :mod:`ntqq.schema` 中。
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Column:
    """QQ 表的一列。"""

    number: int
    name: str
    type: str = "int"  # int | str | bytes
    primary_key: bool = False

    @property
    def sql_name(self) -> str:
        return f'"{self.number}"'


class Model:
    """表模型的基类；子类通过 :attr:`__columns__` 声明列映射。"""

    __tablename__: str = ""
    __columns__: dict[str, Column] = {}
    __by_number__: dict[int, Column] = {}

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if cls.__columns__:
            cls.__by_number__ = {c.number: c for c in cls.__columns__.values()}

    def __init__(self, values: dict[int, Any], table: Table | None = None) -> None:
        object.__setattr__(self, "_values", values)
        object.__setattr__(self, "_table", table)

    # -- 访问 -----------------------------------------------------------
    def __getattr__(self, item: str) -> Any:
        columns = type(self).__columns__
        if item in columns:
            return self._values.get(columns[item].number)
        raise AttributeError(item)

    def get(self, name: str, default: Any = None) -> Any:
        column = type(self).__columns__.get(name)
        if column is None:
            return default
        value = self._values.get(column.number)
        return default if value is None else value

    @property
    def values(self) -> dict[int, Any]:
        """原始的 ``{列号: 值}`` 映射（无损保留）。"""
        return dict(self._values)

    def to_dict(self, *, raw: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for column in type(self).__columns__.values():
            value = self._values.get(column.number)
            out[column.name] = value.hex() if isinstance(value, (bytes, bytearray)) else value
        if raw:
            out["columns"] = {
                str(k): (v.hex() if isinstance(v, (bytes, bytearray)) else v)
                for k, v in sorted(self._values.items())
            }
        return out

    def __repr__(self) -> str:
        name = type(self).__name__
        key = ""
        for column in type(self).__columns__.values():
            if column.primary_key:
                key = f" {column.name}={self._values.get(column.number)!r}"
                break
        return f"<{name}{key}>"


def col(number: int, name: str, type: str = "int", primary_key: bool = False) -> Column:
    return Column(number, name, type, primary_key)


class Query:
    """针对单个 :class:`Model` 的惰性 SELECT。"""

    def __init__(self, table: Table) -> None:
        self._table = table
        self._where: list[tuple[str, list[Any]]] = []
        self._order: list[str] = []
        self._limit: int | None = None
        self._offset: int | None = None

    # -- 构建 -----------------------------------------------------------
    def filter(self, **equals: Any) -> Query:
        """``filter(groupUin=123, msgSeq=7)`` -> ``WHERE ... AND ...``."""
        for key, value in equals.items():
            column = self._column(key)
            if value is None:
                self._where.append((f"{column.sql_name} IS NULL", []))
            elif isinstance(value, (list, tuple, set, frozenset)):
                values = list(value)
                self._where.append(
                    (f"{column.sql_name} IN ({', '.join('?' * len(values))})", values)
                )
            else:
                self._where.append((f"{column.sql_name} = ?", [value]))
        return self

    filter_by = filter

    def contains(self, column: str, text: str) -> Query:
        """对文本列执行 ``LIKE '%text%'``。"""
        target = self._column(column)
        self._where.append((f"{target.sql_name} LIKE ?", [f"%{text}%"]))
        return self

    def between(self, column: str, low: Any, high: Any) -> Query:
        target = self._column(column)
        self._where.append((f"{target.sql_name} BETWEEN ? AND ?", [low, high]))
        return self

    def where(self, sql: str, *params: Any) -> Query:
        """逃生通道：原始 SQL 片段 + 绑定参数。"""
        self._where.append((sql, list(params)))
        return self

    def order_by(self, *columns: str) -> Query:
        for name in columns:
            desc = name.startswith("-")
            key = name[1:] if desc else name
            self._order.append(f"{self._column(key).sql_name}{' DESC' if desc else ''}")
        return self

    def limit(self, count: int) -> Query:
        self._limit = int(count)
        return self

    def offset(self, count: int) -> Query:
        self._offset = int(count)
        return self

    # -- 执行 -----------------------------------------------------------
    def sql(self, *, count: bool = False) -> tuple[str, list[Any]]:
        model = self._table.model
        if not self._table.columns_present:
            raise ValueError(
                f"模型 {model.__name__} 映射的列在表 {model.__tablename__} 中一个都不存在"
                "（QQ 版本差异？）；请用 ntqq.schema 核对列号。"
            )
        columns = ", ".join(c.sql_name for c in self._table.columns_present)
        select = "count(*)" if count else columns
        sql = f"SELECT {select} FROM {model.__tablename__}"
        if self._table.not_indexed:
            sql += " NOT INDEXED"
        if self._where:
            sql += " WHERE " + " AND ".join(clause for clause, _ in self._where)
        params = [p for _, values in self._where for p in values]
        if not count:
            if self._order:
                sql += " ORDER BY " + ", ".join(self._order)
            if self._limit is not None:
                sql += f" LIMIT {self._limit}"
            if self._offset is not None:
                sql += f" OFFSET {self._offset}"
        return sql, params

    def __iter__(self) -> Iterator[Model]:
        return self.iterate()

    def iterate(self, batch: int = 4096) -> Iterator[Model]:
        sql, params = self.sql()
        cursor = self._table.connection.execute(sql, params)
        columns = list(self._table.columns_present)
        while True:
            rows = cursor.fetchmany(batch)
            if not rows:
                return
            for row in rows:
                yield self._table.model(
                    {c.number: v for c, v in zip(columns, row, strict=True)}, self._table
                )

    def all(self, limit: int | None = None) -> list[Model]:
        if limit is not None:
            self.limit(limit)
        return list(self.iterate())

    def first(self) -> Model | None:
        self._limit = 1
        for item in self.iterate():
            return item
        return None

    def count(self) -> int:
        sql, params = self.sql(count=True)
        row = self._table.connection.execute(sql, params).fetchone()
        return int(row[0]) if row else 0

    def delete(self) -> int:
        """删除匹配的行（仅限可写的数据库副本）。"""
        self._table.require_writable()
        model = self._table.model
        sql = f"DELETE FROM {model.__tablename__}"
        if self._where:
            sql += " WHERE " + " AND ".join(clause for clause, _ in self._where)
        params = [p for _, values in self._where for p in values]
        return self._table.connection.execute(sql, params).rowcount

    def _column(self, name: str) -> Column:
        column = self._table.model.__columns__.get(name)
        if column is None:
            raise KeyError(
                f"{self._table.model.__name__} has no column {name!r}; "
                f"known: {', '.join(self._table.model.__columns__)}"
            )
        return column


class Table:
    """绑定到一个已打开的 SQLite 连接的单个模型。"""

    def __init__(
        self,
        connection: sqlite3.Connection,
        model: type[Model],
        not_indexed: bool = True,
        writable: bool = False,
    ) -> None:
        self.connection = connection
        self.model = model
        self.not_indexed = not_indexed
        self.writable = writable
        # 只选取确实存在的列：SQLite 会把无法解析的带引号名称静默地变成
        # *字符串字面量*，否则会掩盖不同 QQ 版本之间的表结构差异。
        present = {
            row[1] for row in connection.execute(f'PRAGMA table_info("{model.__tablename__}")')
        }
        self.columns_present: list[Column] = [
            column for column in model.__columns__.values() if str(column.number) in present
        ]
        self.columns_missing: list[Column] = [
            column for column in model.__columns__.values() if str(column.number) not in present
        ]

    def query(self) -> Query:
        return Query(self)

    def filter(self, **equals: Any) -> Query:
        return Query(self).filter(**equals)

    filter_by = filter

    def where(self, sql: str, *params: Any) -> Query:
        return Query(self).where(sql, *params)

    def contains(self, column: str, text: str) -> Query:
        return Query(self).contains(column, text)

    def between(self, column: str, low: Any, high: Any) -> Query:
        return Query(self).between(column, low, high)

    def order_by(self, *columns: str) -> Query:
        return Query(self).order_by(*columns)

    def all(self, limit: int | None = None) -> list[Model]:
        return Query(self).all(limit)

    def first(self) -> Model | None:
        return Query(self).first()

    def count(self) -> int:
        return Query(self).count()

    def columns(self) -> dict[str, Column]:
        return dict(self.model.__columns__)

    def insert(self, **values: Any) -> None:
        """使用易读的列名插入一行（仅限可写副本）。"""
        self.require_writable()
        pairs = []
        for name, value in values.items():
            pairs.append((self.model.__columns__[name], value))
        numbers = ", ".join(c.sql_name for c, _ in pairs)
        marks = ", ".join("?" for _ in pairs)
        sql = f"INSERT INTO {self.model.__tablename__} ({numbers}) VALUES ({marks})"
        self.connection.execute(sql, [v for _, v in pairs])

    def require_writable(self) -> None:
        if not self.writable:
            raise PermissionError(
                "this database is open read-only; use QQNT.open(..., writable=True) "
                "to modify a copy"
            )


def _decode_text(raw: bytes) -> str:
    """TEXT 列的解码函数。

    QQ 里偶有非法 UTF-8（例如 ``group_member3.64023`` 是**按字节**截断的自定义
    头衔，会停在多字节字符中间）。Python 的 sqlite3 默认遇到这种值会直接抛
    ``OperationalError``，导致**整张表**读不出来；这里用 ``replace`` 兜底，
    保证坏字节只影响它自己（显示为 U+FFFD），其余数据照常可读。
    """
    return raw.decode("utf-8", "replace")


class Database:
    """由单个已解密的 ``.db`` 文件支撑的一组模型。"""

    def __init__(
        self,
        path: str | Path,
        models: Sequence[type[Model]],
        writable: bool = False,
        not_indexed: bool = True,
    ) -> None:
        self.path = Path(path)
        if not writable:
            self.connection = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        else:
            self.connection = sqlite3.connect(str(self.path))
        # 见 _decode_text：不能让一行非法 UTF-8 毁掉整张表。
        self.connection.text_factory = _decode_text
        self.connection.execute(f"PRAGMA query_only = {0 if writable else 1}")
        self.writable = writable
        self.tables: dict[str, Table] = {}
        for model in models:
            if self.has_table(model.__tablename__):
                self.tables[model.__tablename__] = Table(
                    self.connection, model, not_indexed=not_indexed, writable=writable
                )

    def has_table(self, name: str) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone()
        return row is not None

    def table(self, name: str) -> Table:
        if name not in self.tables:
            raise KeyError(f"{self.path.name} has no mapped table {name!r}")
        return self.tables[name]

    def table_names(self) -> list[str]:
        rows = self.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        return [r[0] for r in rows]

    def execute(self, sql: str, *params: Any) -> list[sqlite3.Row]:
        cursor = self.connection.execute(sql, params)
        return cursor.fetchall()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> Database:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


#: 别名，让调用处的写法与参考项目一致。
TABLE_ALIASES = {
    "group_messages": "group_msg_table",
    "private_messages": "c2c_msg_table",
    "dataline_messages": "dataline_msg_table",
    "discuss_messages": "discuss_msg_table",
    "at_me": "group_at_me_msg",
    "groups": "group_list",
    "members": "group_member3",
    "friends": "buddy_list",
    "uid_mapping": "nt_uid_mapping_table",
    "recent_contacts": "recent_contact_v3_table",
    "sys_emoji": "base_sys_emoji_table",
}


class DatabaseManager:
    """打开一个存放已解密 QQ 数据库的目录并暴露其中的模型。

    与参考项目的 ``db.DatabaseManager`` 对应，但改为接收目录，
    而不是依赖 CWD 下的 ``*.decrypt.db`` 文件::

        manager = DatabaseManager("work/plain")
        manager.group_messages.filter(groupUin=1145141919810).count()
        manager.table("group_list").all()
    """

    def __init__(
        self, directory: str | Path, *, writable: bool = False, not_indexed: bool = True
    ) -> None:
        from . import schema

        self.directory = Path(directory)
        self.writable = writable
        self.databases: dict[str, Database] = {}
        self.tables: dict[str, Table] = {}
        for filename, models in schema.DATABASES.items():
            path = self.directory / filename
            if not path.is_file():
                continue
            try:
                database = Database(path, models, writable=writable, not_indexed=not_indexed)
            except sqlite3.DatabaseError:
                continue
            self.databases[filename] = database
            self.tables.update(database.tables)

    # -- 表访问 ---------------------------------------------------------
    def __getattr__(self, name: str) -> Table:
        tables = self.__dict__.get("tables") or {}
        if name in tables:
            return tables[name]
        alias = TABLE_ALIASES.get(name)
        if alias and alias in tables:
            return tables[alias]
        raise AttributeError(f"{name!r}; loaded tables: {', '.join(sorted(tables)) or '(none)'}")

    def table(self, name: str) -> Table:
        try:
            return self.__getattr__(name)
        except AttributeError as exc:
            raise KeyError(str(exc)) from None

    def table_names(self) -> list[str]:
        return sorted(self.tables)

    def db(self, filename: str) -> Database:
        if filename not in self.databases:
            have = ", ".join(sorted(self.databases)) or "(none)"
            raise KeyError(f"no {filename} in {self.directory}; loaded: {have}")
        return self.databases[filename]

    def missing(self) -> list[str]:
        from . import schema

        return [name for name in schema.DATABASES if not (self.directory / name).is_file()]

    def close(self) -> None:
        for database in self.databases.values():
            database.close()

    def __enter__(self) -> DatabaseManager:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
