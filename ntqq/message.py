"""带类型的消息元素与消息。

参照参考项目的 ``nt_msg/message.py`` 设计：每种元素类型对应一个类
（元素类型取自消息体的 ``45002`` 字段），另有一个按该 id 分发的注册表，
以及一个能从数据库行自建自身的 :class:`Message`。

与参考项目不同，这里会无损保留每个元素的原始 protobuf 字段，
因此即便解码器暂不理解某个字段，也不会有任何信息丢失。

    >>> from ntqq.message import parse_body
    >>> msg = next(iter(manager.group_messages.limit(1)))
    >>> message = Message.from_row(msg)
    >>> print(message.time_str, message.sender_name, message.text)
"""

from __future__ import annotations

import datetime as _dt
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import Any, ClassVar

from . import protobuf
from .protobuf import Field

# ---------------------------------------------------------------------------
# 元素类型 id（消息体字段 45002）
# ---------------------------------------------------------------------------

ELEMENT_NAMES: dict[int, str] = {
    1: "text",
    2: "image",
    3: "file",
    4: "voice",
    5: "video",
    6: "face",
    7: "reply",
    8: "poke",
    9: "gift",
    10: "share",
    11: "ark",
    12: "music",
    13: "online_file",
    14: "markdown",
    15: "gray_tip",
    16: "forward",
    17: "bot_markdown",
    18: "video_call",
    21: "call",
    43: "menu",
}


def element_name(element_type: int | None) -> str:
    if element_type is None:
        return "unknown"
    return ELEMENT_NAMES.get(element_type, f"type_{element_type}")


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------


def _ints(fields: Iterable[Field]) -> dict[int, list[Any]]:
    out: dict[int, list[Any]] = {}
    for fld in fields:
        out.setdefault(fld.number, []).append(fld.value)
    return out


def _text(fields: Iterable[Field], number: int) -> str | None:
    for fld in fields:
        if fld.number == number and fld.wire_type == protobuf.WIRE_LEN:
            value = protobuf.try_decode_utf8(fld.value)
            if value is not None:
                return value
    return None


def _bytes(fields: Iterable[Field], number: int) -> bytes | None:
    for fld in fields:
        if fld.number == number and fld.wire_type == protobuf.WIRE_LEN:
            return fld.value
    return None


def _int(fields: Iterable[Field], number: int) -> int | None:
    for fld in fields:
        if fld.number == number:
            return fld.value if isinstance(fld.value, int) else None
    return None


def _message(fields: Iterable[Field], number: int) -> list[Field] | None:
    for fld in fields:
        if fld.number == number and fld.message is not None:
            return fld.message
    return None


# ---------------------------------------------------------------------------
# 元素
# ---------------------------------------------------------------------------


@dataclass
class Element:
    """所有已解码元素的基类。"""

    kind: ClassVar[str] = "unknown"
    raw: list[Field] = dc_field(default_factory=list)

    @property
    def type_name(self) -> str:
        return self.kind

    def __str__(self) -> str:  # pragma: no cover - 由子类重写
        return ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "text": str(self),
            "fields": protobuf.to_jsonable(self.raw),
        }


@dataclass
class Text(Element):
    kind: ClassVar[str] = "text"
    content: str = ""
    at_uids: list[str] = dc_field(default_factory=list)
    at_uins: list[int] = dc_field(default_factory=list)

    def __str__(self) -> str:
        return self.content

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data.update(content=self.content, at_uids=self.at_uids, at_uins=self.at_uins)
        return data


@dataclass
class MediaElement(Element):
    """图片 / 视频 / 语音 / 文件元素共用的结构。"""

    filename: str | None = None
    size: int | None = None
    md5: str | None = None
    uuid: str | None = None
    url: str | None = None
    width: int | None = None
    height: int | None = None

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data.update(
            filename=self.filename,
            size=self.size,
            md5=self.md5,
            uuid=self.uuid,
            url=self.url,
            width=self.width,
            height=self.height,
        )
        return data


@dataclass
class Image(MediaElement):
    kind: ClassVar[str] = "image"
    summary: str | None = None

    def __str__(self) -> str:
        return self.summary or "[图片]"

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["summary"] = self.summary
        return data


@dataclass
class File(MediaElement):
    kind: ClassVar[str] = "file"
    local_path: str | None = None

    def __str__(self) -> str:
        return f"[文件 {self.filename}]" if self.filename else "[文件]"


@dataclass
class Voice(MediaElement):
    kind: ClassVar[str] = "voice"
    seconds: int | None = None

    def __str__(self) -> str:
        return "[语音]"


@dataclass
class Video(MediaElement):
    kind: ClassVar[str] = "video"

    def __str__(self) -> str:
        return "[视频]"


@dataclass
class Face(Element):
    kind: ClassVar[str] = "face"
    face_id: int | None = None
    name: str | None = None
    pack_id: int | None = None

    def __str__(self) -> str:
        if self.name:
            return f"[{self.name}]"
        return f"[表情 {self.face_id}]" if self.face_id is not None else "[表情]"


@dataclass
class Reply(Element):
    kind: ClassVar[str] = "reply"
    source_seq: int | None = None
    source_sender_uin: int | None = None
    source_time: int | None = None
    source_msg_id: int | None = None
    quoted: Message | None = None

    def __str__(self) -> str:
        return f"[回复 {self.quoted.text}]" if self.quoted else "[回复]"


@dataclass
class Poke(Element):
    kind: ClassVar[str] = "poke"
    sender_name: str | None = None
    target_name: str | None = None
    suffix: str | None = None
    action: str | None = None

    def __str__(self) -> str:
        if self.action:  # 撤回与好友相关的戳一戳带有可读后缀
            who = self.sender_name or ""
            return f"{who}{self.action}"
        if self.sender_name and self.target_name:
            return f"[戳一戳 {self.sender_name} -> {self.target_name}]"
        return "[戳一戳]"


@dataclass
class Share(Element):
    kind: ClassVar[str] = "share"
    json_payload: str | None = None
    title: str | None = None

    def __str__(self) -> str:
        return self.title or "[分享]"

    @property
    def data(self) -> dict[str, Any] | None:
        if not self.json_payload:
            return None
        try:
            return json.loads(self.json_payload)
        except json.JSONDecodeError:
            return None


@dataclass
class Ark(Element):
    kind: ClassVar[str] = "ark"
    ark_id: int | None = None
    summary: str | None = None
    prompt: str | None = None

    def __str__(self) -> str:
        return self.summary or "[卡片消息]"


@dataclass
class Forward(Element):
    kind: ClassVar[str] = "forward"
    resid: str | None = None
    xml: str | None = None
    filename: str | None = None

    def __str__(self) -> str:
        return "[聊天记录]"


@dataclass
class BotMarkdown(Element):
    kind: ClassVar[str] = "bot_markdown"
    payload: str | None = None
    app_id: int | None = None

    def __str__(self) -> str:
        return self.payload or "[消息]"


@dataclass
class Call(Element):
    kind: ClassVar[str] = "call"
    text: str | None = None

    def __str__(self) -> str:
        return self.text or "[通话]"


@dataclass
class MenuItem:
    """内嵌菜单里的一个按钮（子字段 ``48753``）。

    ``48754`` 是按钮标识（如 ``"b1"``），``48755`` 是按钮上显示的文字
    （如 ``"面板"``、``"菜单"``）；其余字段原样保留在 :attr:`raw`。
    """

    id: str | None = None
    label: str | None = None
    raw: list[Field] = dc_field(default_factory=list, repr=False)

    def __str__(self) -> str:
        return self.label or self.id or ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "fields": protobuf.to_jsonable(self.raw),
        }


@dataclass
class Menu(Element):
    """内嵌按钮菜单（客户端里显示为一条可点按钮的卡片）。

    ``48751`` 是按钮列表（每个 ``48753`` 一个按钮），``48752`` 是所属应用 id；
    其余字段原样保留在 :attr:`Element.raw`。
    """

    kind: ClassVar[str] = "menu"
    app_id: int | None = None
    items: list[MenuItem] = dc_field(default_factory=list)

    def __str__(self) -> str:
        labels = [str(item) for item in self.items if str(item)]
        return " | ".join(labels) or "[菜单]"

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["app_id"] = self.app_id
        data["items"] = [item.to_dict() for item in self.items]
        return data


@dataclass
class Unsupported(Element):
    """没有专用解码器、或解码器失败的元素。

    ``error`` 非空表示是**解码器抛错**（代码问题），为空则只是该元素类型
    尚未支持（数据问题）；原始字段始终保留在 ``raw`` 中。
    """

    kind: ClassVar[str] = "unsupported"
    element_type: int | None = None
    text: str | None = None
    error: str | None = None

    def __str__(self) -> str:
        if self.text:
            return self.text
        return f"[{element_name(self.element_type)}]"


@dataclass
class Gift(Element):
    """红包 / 礼物卡片（元素类型 9）。"""

    kind: ClassVar[str] = "gift"
    title: str | None = None
    alt: str | None = None

    def __str__(self) -> str:
        return self.title or self.alt or "[礼物]"


@dataclass
class Markdown(Element):
    """Markdown / 灰提示风格的富文本（元素类型 14、15）。"""

    kind: ClassVar[str] = "markdown"
    content: str | None = None

    def __str__(self) -> str:
        return self.content or "[Markdown]"


# ---------------------------------------------------------------------------
# 解码
# ---------------------------------------------------------------------------

_REGISTRY: dict[int, Any] = {}


def _decode_text(fields: list[Field]) -> Element:
    return Text(
        raw=fields,
        content=_text(fields, 45101) or "",
        at_uids=[
            v.decode("utf-8", "replace")
            for v in _ints(fields).get(45105, [])
            if isinstance(v, bytes)
        ],
        at_uins=[v for v in _ints(fields).get(45103, []) if isinstance(v, int)],
    )


def _media(fields: list[Field]) -> dict[str, Any]:
    md5 = _bytes(fields, 45406)
    uuid = _bytes(fields, 45503)
    url = _text(fields, 45804) or _text(fields, 45803) or _text(fields, 45802)
    return {
        "filename": _text(fields, 45402),
        "size": _int(fields, 45405),
        "md5": md5.hex() if md5 else None,
        "uuid": uuid.decode("utf-8", "replace") if uuid else None,
        "url": url,
        "width": _int(fields, 45411),
        "height": _int(fields, 45412),
    }


def _decode_image(fields: list[Field]) -> Element:
    return Image(raw=fields, summary=_text(fields, 45815), **_media(fields))


def _decode_file(fields: list[Field]) -> Element:
    path = _text(fields, 45954)
    return File(raw=fields, local_path=path, **_media(fields))


def _decode_voice(fields: list[Field]) -> Element:
    return Voice(raw=fields, seconds=_int(fields, 45906), **_media(fields))


def _decode_video(fields: list[Field]) -> Element:
    return Video(raw=fields, **_media(fields))


def _decode_face(fields: list[Field]) -> Element:
    return Face(
        raw=fields,
        face_id=_int(fields, 47601),
        name=_text(fields, 47602),
        pack_id=_int(fields, 47603),
    )


def _decode_reply(fields: list[Field]) -> Element:
    groups = [f.message for f in fields if f.number == 47423 and f.message is not None]
    quoted = Message.from_body_fields(groups) if groups else None
    return Reply(
        raw=fields,
        source_seq=_int(fields, 47402),
        source_sender_uin=_int(fields, 47403),
        source_time=_int(fields, 47404),
        source_msg_id=_int(fields, 47422),
        quoted=quoted,
    )


def _decode_poke(fields: list[Field]) -> Element:
    suffix = _text(fields, 47713)
    sender = _text(fields, 47705) or _text(fields, 47714)
    target = _text(fields, 47707) or _text(fields, 47716)
    action = None
    if suffix and "撤回" in suffix:
        action = "撤回了一条消息"
    return Poke(raw=fields, sender_name=sender, target_name=target, suffix=suffix, action=action)


def _decode_share(fields: list[Field]) -> Element:
    payload = _text(fields, 47901) or (
        _bytes(fields, 47901).decode("utf-8", "replace") if _bytes(fields, 47901) else None
    )
    title = None
    if payload:
        try:
            data = json.loads(payload)
            title = (
                data.get("desc")
                or data.get("title")
                or (data.get("meta") or {}).get("detail_1", {}).get("desc")
            )
        except (json.JSONDecodeError, AttributeError):
            title = None
    return Share(raw=fields, json_payload=payload, title=title)


def _decode_ark(fields: list[Field]) -> Element:
    return Ark(
        raw=fields,
        ark_id=_int(fields, 80810),
        summary=_text(fields, 80900),
        prompt=_text(fields, 80902),
    )


def _decode_forward(fields: list[Field]) -> Element:
    resid = _bytes(fields, 48601)
    return Forward(
        raw=fields,
        resid=resid.decode("utf-8", "replace") if resid else None,
        xml=_text(fields, 48602),
        filename=_text(fields, 48603),
    )


def _decode_bot_markdown(fields: list[Field]) -> Element:
    payload = _bytes(fields, 48751)
    return BotMarkdown(
        raw=fields,
        payload=payload.decode("utf-8", "replace") if payload else None,
        app_id=_int(fields, 48752),
    )


def _decode_call(fields: list[Field]) -> Element:
    return Call(raw=fields, text=_text(fields, 48153) or _text(fields, 48157))


def _decode_gift(fields: list[Field]) -> Element:
    nested = _message(fields, 48403)
    title = alt = None
    if nested:
        title = _text(nested, 48443) or _text(nested, 48402)
        alt = _text(nested, 48448) or _text(nested, 48445)
    return Gift(raw=fields, title=title or _text(fields, 48402), alt=alt or _text(fields, 45815))


def _decode_menu(fields: list[Field]) -> Element:
    items: list[MenuItem] = []
    for container in fields:
        if container.number != 48751 or container.message is None:
            continue
        for button in container.message:
            if button.number != 48753 or button.message is None:
                continue
            items.append(
                MenuItem(
                    id=_text(button.message, 48754),
                    label=_text(button.message, 48755),
                    raw=button.message,
                )
            )
    return Menu(raw=fields, app_id=_int(fields, 48752), items=items)


def _decode_markdown(fields: list[Field]) -> Element:
    return Markdown(
        raw=fields, content=_text(fields, 48403) or _text(fields, 48271) or _text(fields, 48402)
    )


#: 通常携带可读字符串的字段；当某种元素类型还没有专用解码器时，
#: 会按此顺序依次尝试。
_FALLBACK_TEXT_FIELDS = (45101, 45815, 80900, 48403, 47713, 48153, 45402, 48751, 45804)


def _decode_unsupported(fields: list[Field]) -> Element:
    for number in _FALLBACK_TEXT_FIELDS:
        text = _text(fields, number)
        if text:
            return Unsupported(raw=fields, element_type=_int(fields, 45002), text=text)
    return Unsupported(raw=fields, element_type=_int(fields, 45002))


#: 元素类型 id -> 解码器。注册表与 ``ELEMENT_NAMES`` 一一对应（由测试保证），
#: 未登记的类型统一走 :func:`_decode_unsupported`。
#:
#: 注意：``49154``/``49155``（商城表情信息）**不是**独立的元素类型，它们作为
#: 子字段随类型 8（戳一戳）与 16（转发）一起下发；其原始字段由 ``Element.raw``
#: 原样保留。
_REGISTRY.update(
    {
        1: _decode_text,
        2: _decode_image,
        3: _decode_file,
        4: _decode_voice,
        5: _decode_video,
        6: _decode_face,
        7: _decode_reply,
        8: _decode_poke,
        9: _decode_gift,
        10: _decode_share,
        11: _decode_ark,
        12: _decode_markdown,
        13: _decode_file,
        14: _decode_markdown,
        15: _decode_markdown,
        16: _decode_forward,
        17: _decode_bot_markdown,
        18: _decode_call,
        21: _decode_call,
        43: _decode_menu,
    }
)


def register(element_type: int, decoder: Any) -> None:
    """为某个元素类型 id 注册（或覆盖）解码器。"""
    _REGISTRY[element_type] = decoder


# ---------------------------------------------------------------------------
# 消息
# ---------------------------------------------------------------------------


@dataclass
class Message:
    """一条聊天消息及其已解码的元素。"""

    id: int | None = None
    seq: int | None = None
    random: int | None = None
    time: int | None = None
    chat_type: int | None = None
    peer_uin: int | None = None
    sender_uid: str | None = None
    sender_uin: int | None = None
    sender_name: str | None = None
    sender_card: str | None = None
    elements: list[Element] = dc_field(default_factory=list)
    columns: dict[int, Any] = dc_field(default_factory=dict)
    source: str = ""

    # -- 构造 -----------------------------------------------------------
    @classmethod
    def from_body_fields(cls, groups: Sequence[list[Field]] | None = None) -> Message:
        """从若干段已解析的元素字段构建消息（用于引用等内嵌场景）。

        *groups* 的每一项是一段消息体的字段列表——被引用的正文、图片等各占
        一段 ``47423``，实测约 22% 的引用不止一段。
        """
        groups = list(groups or [])
        elements = [element for group in groups for element in parse_elements(group)]
        first = groups[0] if groups else []
        return cls(
            id=_int(first, 45001),
            elements=elements,
            columns={},
            source="embed",
        )

    @classmethod
    def from_row(cls, row: Any, *, decode: bool = True, body_field: int = 40800) -> Message:
        """从 :class:`ntqq.orm.Model` 或 :class:`ntqq.reader.MessageRecord`
        构建一条消息。

        ``body_field`` 是存放 protobuf 消息体的列：真实消息为 ``40800``，
        最近会话预览为 ``40051``。
        """
        columns = getattr(row, "values", None) or {}
        if not columns:
            columns = dict(getattr(row, "columns", {}) or {})

        def column(number: int) -> Any:
            return columns.get(number)

        body = column(body_field)
        elements: list[Element] = decode_elements(body, body_field) if decode else []

        return cls(
            id=column(40001),
            seq=column(40003),
            random=column(40002),
            time=column(40050),
            chat_type=column(40010),
            peer_uin=column(40030) or column(40027),
            sender_uid=column(40020),
            sender_uin=column(40033),
            sender_name=column(40090),
            sender_card=column(40093),
            elements=elements,
            columns=dict(columns),
            source=getattr(row, "table", "") or type(row).__name__,
        )

    # -- 便捷访问 -------------------------------------------------------
    @property
    def datetime(self) -> _dt.datetime | None:
        if not self.time:
            return None
        try:
            return _dt.datetime.fromtimestamp(self.time)
        except (OverflowError, OSError, ValueError):
            return None

    @property
    def time_str(self) -> str:
        moment = self.datetime
        return moment.strftime("%Y-%m-%d %H:%M:%S") if moment else ""

    @property
    def text(self) -> str:
        return "".join(str(e) for e in self.elements)

    @property
    def type_id(self) -> int | None:
        return _int(_body_fields(self.columns.get(40800)), 45002)

    @property
    def type_name(self) -> str:
        if self.elements:
            return self.elements[0].kind
        # 消息体缺失意味着该行完全不含元素（已删除或
        # 服务号行）；将其与“未知元素类型”区分开来会更有帮助。
        return "empty" if not self.columns.get(40800) else "unknown"

    @property
    def quote(self) -> Reply | None:
        for element in self.elements:
            if isinstance(element, Reply):
                return element
        return None

    @property
    def display_sender(self) -> str:
        return (
            self.sender_card
            or self.sender_name
            or (str(self.sender_uin) if self.sender_uin else self.sender_uid or "")
        )

    def element(self, kind: str) -> Element | None:
        for element in self.elements:
            if element.kind == kind:
                return element
        return None

    def to_dict(self, *, raw: bool = False) -> dict[str, Any]:
        data = {
            "id": self.id,
            "seq": self.seq,
            "time": self.time,
            "time_str": self.time_str,
            "chat_type": self.chat_type,
            "peer_uin": self.peer_uin,
            "sender_uid": self.sender_uid,
            "sender_uin": self.sender_uin,
            "sender_name": self.sender_name,
            "sender_card": self.sender_card,
            "type": self.type_name,
            "text": self.text,
            "elements": [e.to_dict() for e in self.elements],
        }
        if raw:
            data["columns"] = {
                str(k): (v.hex() if isinstance(v, (bytes, bytearray)) else v)
                for k, v in sorted(self.columns.items())
            }
        return data

    def __str__(self) -> str:
        return f"[{self.time_str}] {self.display_sender}: {self.text}"


def unwrap_bodies(blob: bytes, field: int = 40800) -> list[bytes]:
    """QQ 把消息体包在一个以其列名命名的 protobuf 字段中，且**一条消息可以有多段**。

    ``40800`` 存放聊天消息，``40051`` 存放最近会话预览。消息的正文、图片、
    引用等各占一个 ``40800``（实测约 18% 的群消息不止一段），因此必须全部取出，
    只取第一段会丢掉其余元素。
    """
    try:
        fields = protobuf.parse(blob)
    except protobuf.ProtobufError:
        return [blob]
    bodies = [f.value for f in fields if f.number == field and f.wire_type == protobuf.WIRE_LEN]
    return bodies or [blob]


def unwrap_body(blob: bytes, field: int = 40800) -> bytes:
    """只取第一段消息体；需要全部分段请用 :func:`unwrap_bodies`。"""
    return unwrap_bodies(blob, field)[0]


def parse_elements(fields: list[Field] | None) -> list[Element]:
    """把消息体的字段列表解码为带类型的元素。"""
    fields = fields or []
    if not fields:
        return []
    element_type = _int(fields, 45002)
    decoder = _REGISTRY.get(element_type if element_type is not None else -1, _decode_unsupported)
    try:
        return [decoder(fields)]
    # 绝不让单个解码器破坏整个导出；把失败原因带上，便于扫描时暴露问题
    except Exception as error:
        return [
            Unsupported(
                raw=fields,
                element_type=element_type,
                error=f"{type(error).__name__}: {error}",
            )
        ]


def decode_elements(blob: Any, field: int = 40800) -> list[Element]:
    """把消息体列的原始字节解码为元素列表。

    一条消息可能由多段组成（正文、图片、引用各一段），全部段都会被解析并
    按原始顺序拼接，因此不会丢元素。
    """
    if not isinstance(blob, (bytes, bytearray)) or not blob:
        return []
    elements: list[Element] = []
    for inner in unwrap_bodies(bytes(blob), field):
        try:
            fields = protobuf.decode_tree(inner)
        except protobuf.ProtobufError:
            continue
        elements.extend(parse_elements(fields))
    return elements


def _body_fields(blob: Any) -> list[Field]:
    if not isinstance(blob, (bytes, bytearray)) or not blob:
        return []
    try:
        return protobuf.decode_tree(unwrap_body(bytes(blob)))
    except protobuf.ProtobufError:
        return []
