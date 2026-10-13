"""极简、无第三方依赖的 Protocol Buffers wire 格式解码器。

QQ NT 把消息体以原始 protobuf blob 的形式存放在 SQLite BLOB 列中。
由于 schema 并未公开，我们不使用生成的类，而是通用地解码 wire 格式，
并保留发现的*一切*内容。未知字段会被保留而不是丢弃，
这正是实现无损导出所必需的。

wire 格式参考：https://protobuf.dev/programming-guides/encoding/
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

# Wire 类型
WIRE_VARINT = 0
WIRE_FIXED64 = 1
WIRE_LEN = 2
WIRE_START_GROUP = 3
WIRE_END_GROUP = 4
WIRE_FIXED32 = 5


class ProtobufError(ValueError):
    """当字节串不是合法的 protobuf 时抛出。"""


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """读取一个 base-128 varint，返回 ``(value, new_offset)``。"""
    shift = 0
    value = 0
    while True:
        if offset >= len(data):
            raise ProtobufError("truncated varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
        if shift > 63:
            raise ProtobufError("varint too long")
    # 不可达


def encode_varint(value: int) -> bytes:
    out = bytearray()
    if value < 0:
        value += 1 << 64
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


@dataclass
class Field:
    """单个已解码的 protobuf 字段。"""

    number: int
    wire_type: int
    value: Any  # int | bytes
    # 由 :func:`decode_tree` 惰性填充：适用于那些自身
    # 看起来像合法子消息的 length-delimited 字段。
    message: list[Field] | None = None

    @property
    def is_message(self) -> bool:
        return self.message is not None

    def as_text(self) -> str | None:
        """当取值看起来像文本时，返回按 UTF-8 解码后的文本。"""
        if self.wire_type != WIRE_LEN or self.message is not None:
            return None
        return try_decode_utf8(self.value)


def try_decode_utf8(data: bytes) -> str | None:
    """若 *data* 是可打印内容则按 UTF-8 解码，否则返回 ``None``。"""
    if not data:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    for ch in text:
        if ch in "\n\r\t":
            continue
        if not ch.isprintable():
            return None
    return text


def parse(data: bytes) -> list[Field]:
    """把 *data* 解码为扁平的 :class:`Field` 列表。

    如果字节不是合法的 protobuf 消息则抛出 :class:`ProtobufError`。
    不支持分组（wire 类型 3/4），会被拒绝。
    """
    fields: list[Field] = []
    offset = 0
    end = len(data)
    while offset < end:
        tag, offset = read_varint(data, offset)
        number = tag >> 3
        wire = tag & 7
        if number == 0:
            raise ProtobufError("field number 0 is invalid")
        if wire == WIRE_VARINT:
            value, offset = read_varint(data, offset)
        elif wire == WIRE_FIXED64:
            if offset + 8 > end:
                raise ProtobufError("truncated fixed64")
            value = int.from_bytes(data[offset : offset + 8], "little")
            offset += 8
        elif wire == WIRE_LEN:
            length, offset = read_varint(data, offset)
            if length < 0 or offset + length > end:
                raise ProtobufError("truncated length-delimited field")
            value = data[offset : offset + length]
            offset += length
        elif wire == WIRE_FIXED32:
            if offset + 4 > end:
                raise ProtobufError("truncated fixed32")
            value = int.from_bytes(data[offset : offset + 4], "little")
            offset += 4
        else:
            raise ProtobufError(f"unsupported wire type {wire}")
        fields.append(Field(number, wire, value))
    return fields


def looks_like_message(data: bytes) -> bool:
    """启发式判断：*data* 能否干净地解码为一条 protobuf 消息？"""
    if not data:
        return False
    try:
        fields = parse(data)
    except ProtobufError:
        return False
    return bool(fields)


def decode_tree(data: bytes, depth: int = 0, max_depth: int = 16) -> list[Field]:
    """递归解码 *data*，并把子消息挂到 length 字段上。

    只有当某 length-delimited 字段的字节既能干净解码、*又*明显不是
    可打印字符串时，才把它当作子消息。文本优先于碰巧成立的
    消息解析，这与 QQ 存储文本的方式一致。
    """
    fields = parse(data)
    if depth >= max_depth:
        return fields
    for fld in fields:
        if fld.wire_type != WIRE_LEN or len(fld.value) == 0:
            continue
        # 在 QQ 的 schema 中，可打印字符串几乎不会是嵌套消息；
        # 优先采用文本解释。
        if try_decode_utf8(fld.value) is not None and not _looks_like_structured(fld.value):
            continue
        try:
            fld.message = decode_tree(fld.value, depth + 1, max_depth)
        except ProtobufError:
            fld.message = None
    return fields


def _looks_like_structured(data: bytes) -> bool:
    """很小的保护措施，避免短字符串被误认为消息。"""
    try:
        fields = parse(data)
    except ProtobufError:
        return False
    return len(fields) >= 2


def iter_fields(fields: list[Field]) -> Iterator[Field]:
    for fld in fields:
        yield fld
        if fld.message is not None:
            yield from iter_fields(fld.message)


def to_jsonable(fields: list[Field]) -> list[dict[str, Any]]:
    """把已解码字段转换为便于 JSON 序列化的字典。

    每个字段都会被表示出来，从而不丢失任何内容。原始字节以十六进制编码。
    """
    out = []
    for fld in fields:
        entry: dict[str, Any] = {"field": fld.number, "wire": fld.wire_type}
        if fld.message is not None:
            entry["message"] = to_jsonable(fld.message)
        elif fld.wire_type == WIRE_LEN:
            text = try_decode_utf8(fld.value)
            if text is not None:
                entry["string"] = text
            else:
                entry["hex"] = fld.value.hex()
        else:
            entry["value"] = fld.value
        out.append(entry)
    return out


def get(fields: list[Field], number: int) -> list[Field]:
    """返回具有给定编号的所有字段（允许重复字段）。"""
    return [f for f in fields if f.number == number]


def first(fields: list[Field], number: int) -> Field | None:
    for f in fields:
        if f.number == number:
            return f
    return None
