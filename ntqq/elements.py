"""QQ NT 消息元素的语义解码。

``40800`` BLOB 列存放一条 protobuf 消息，它被包装在一个字段里，
而该字段的编号就是列号本身::

    40800 {                 # 外层包装（field == 列 id）
        45001: msg_id       # 消息 id（与 [40001] 主键一致）
        45002: element_type # 1 text, 2 image, 3 file, 4 voice, ...
        45003: sub_type
        ...                 # 按元素家族区分，见 ELEMENT_FIELDS
    }

字段编号按元素家族分组，消息体在这里正是据此解释的。该映射是通过
将 ``45002`` 与大量真实消息样本中实际出现的字段相关联得出的
（见 ``ELEMENT_FIELDS``）；未知内容仍会原样保留在
:attr:`MessageBody.raw` 和 :attr:`Element.fields` 中。

在真实数据中观察到的元素类型取值（``45002``）::

    1  text          45101 文本，45103/45105 提及
    2  image         454xx 媒体，458xx url/摘要
    3  file          45402 文件名，45405 大小，45503 uuid
    4  voice         45402 .amr，459xx 语音附加字段
    5  video         45402 .mp4，458xx 预览 url
    6  face          476xx 表情 id/名称
    7  reply         47423 引用的消息体
    8  poke          477xx 发起/被戳 uid 与名称
    10 share         47901 分享 JSON 负载
    11 ark           80810 ark id，80900 摘要
    16 forward       48602 聊天记录 XML，48601 resid
    17 bot_markdown  48751 负载，48752 应用 id
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import Any

from . import protobuf
from .protobuf import Field

# 消息体中字段 45002 所表示的元素类型。
MESSAGE_TYPES: dict[int, str] = {
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
}

# 已知字段号的可读名称（尽力而为）。
FIELD_NAMES: dict[int, str] = {
    # 消息体头部
    45001: "msg_id",
    45002: "element_type",
    45003: "sub_type",
    40010: "chat_type",
    40020: "sender_uid",
    40021: "peer_uid",
    40030: "peer_uin",
    40033: "sender_uin",
    40040: "msg_flags",
    40050: "timestamp",
    # 文本
    45101: "text",
    45102: "at_type",
    45103: "at_uin",
    45105: "at_uid",
    45106: "at_flag",
    45108: "at_flags2",
    45109: "at_flags3",
    45111: "at_flags4",
    45112: "at_flags5",
    # 媒体（图片 / 视频 / 语音 / 文件共用同一区块）
    45402: "filename",
    45405: "file_size",
    45406: "md5",
    45408: "token",
    45410: "file_ttl_or_flags",
    45411: "width",
    45412: "height",
    45413: "thumb_width",
    45414: "thumb_height",
    45416: "image_type",
    45418: "media_flags",
    45421: "media_flags2",
    45424: "media_extra",
    45501: "file_type",
    45503: "file_uuid",
    45505: "expire_time",
    45510: "file_status2",
    45511: "file_status",
    45513: "download_status",
    45517: "upload_time",
    45518: "ttl",
    45550: "media_sub_type",
    45802: "url_thumb",
    45803: "url_screen",
    45804: "url_original",
    45815: "summary",
    45816: "host",
    45817: "file_type_2",
    # 语音附加字段
    45906: "voice_format",
    45907: "voice_flags",
    # 回复
    47402: "reply_seq",
    47403: "reply_sender_uin",
    47404: "reply_time",
    47405: "reply_flags2",
    47411: "reply_flags3",
    47415: "reply_flags",
    47416: "reply_attr",
    47422: "reply_msg_id",
    47423: "reply_body",
    # 表情 / 贴纸
    47601: "face_id",
    47602: "face_name",
    47603: "face_pack_id",
    47604: "face_type",
    47605: "face_flags",
    47606: "face_flags2",
    # 戳一戳
    47702: "poke_type",
    47703: "poker_uid",
    47704: "poked_uid",
    47705: "poker_name",
    47707: "poked_name",
    47713: "poke_extra",
    47714: "poker_name_alt",
    47716: "poked_name_alt",
    # 分享（图文 / news card）
    47901: "share_json",
    # markdown
    48401: "md_flag",
    48402: "md_title",
    48403: "md_content",
    48409: "md_extra_a",
    48410: "md_extra_b",
    48417: "md_payload",
    48418: "md_token",
    48421: "md_style",
    # 转发 / 聊天记录
    48601: "forward_resid",
    48602: "forward_xml",
    48603: "forward_uuid",
    # 机器人 Markdown
    48751: "bot_markdown",
    48752: "bot_app_id",
    # 商城表情
    49154: "market_face_id",
    49155: "market_face_time",
    # ark
    80810: "ark_id",
    80824: "ark_data",
    80900: "ark_summary",
    80901: "ark_view",
    80902: "ark_prompt",
    80903: "ark_meta",
    80905: "ark_flags",
}

# 元素类型 -> 家族（承载元素负载的字段范围）。
ELEMENT_FIELDS: dict[int, tuple[str, range]] = {
    1: ("text", range(45100, 45200)),
    2: ("media", range(45400, 46000)),
    3: ("media", range(45400, 46000)),
    4: ("media", range(45400, 46000)),
    5: ("media", range(45400, 46000)),
    6: ("face", range(47600, 47700)),
    7: ("reply", range(47400, 47500)),
    8: ("poke", range(47700, 47800)),
    10: ("share", range(47900, 48000)),
    11: ("ark", range(80800, 81000)),
    16: ("forward", range(48600, 48700)),
    17: ("bot_markdown", range(48700, 48800)),
}

# 元素类型未知时使用的回退家族：这些范围内的任何字段
# 都会作为通用元素挂到消息体上。
_FALLBACK_FAMILIES = [
    ("text", range(45100, 45200)),
    ("media", range(45400, 46000)),
    ("reply", range(47400, 47500)),
    ("face", range(47600, 47700)),
    ("poke", range(47700, 47800)),
    ("share", range(47900, 48000)),
    ("system", range(48200, 48300)),
    ("markdown", range(48400, 48500)),
    ("forward", range(48600, 48700)),
    ("bot_markdown", range(48700, 48800)),
    ("market_face", range(49100, 49200)),
    ("ark", range(80800, 81000)),
]


@dataclass
class Element:
    kind: str
    fields: list[Field]

    def get(self, number: int) -> Field | None:
        return protobuf.first(self.fields, number)

    def value(self, number: int) -> Any:
        fld = self.get(number)
        return fld.value if fld is not None else None

    def string(self, number: int) -> str | None:
        fld = self.get(number)
        if fld is None or fld.wire_type != 2:
            return None
        return protobuf.try_decode_utf8(fld.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "fields": protobuf.to_jsonable(self.fields),
        }


@dataclass
class MessageBody:
    fields: list[Field]
    elements: list[Element] = dc_field(default_factory=list)

    @property
    def msg_id(self) -> int | None:
        fld = protobuf.first(self.fields, 45001)
        return fld.value if fld is not None else None

    @property
    def msg_type(self) -> int | None:
        fld = protobuf.first(self.fields, 45002)
        return fld.value if fld is not None else None

    @property
    def sub_type(self) -> int | None:
        fld = protobuf.first(self.fields, 45003)
        return fld.value if fld is not None else None

    @property
    def element_type_name(self) -> str:
        return MESSAGE_TYPES.get(self.msg_type, f"type_{self.msg_type}")

    def element(self, kind: str) -> Element | None:
        for element in self.elements:
            if element.kind == kind:
                return element
        return None

    def text(self) -> str:
        """消息尽力而为的纯文本表示。"""
        parts = []
        for element in self.elements:
            rendered = render_element(element)
            if rendered:
                parts.append(rendered)
        return "".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "msg_id": self.msg_id,
            "element_type": self.msg_type,
            "element_type_name": self.element_type_name,
            "sub_type": self.sub_type,
            "raw": protobuf.to_jsonable(self.fields),
            "elements": [e.to_dict() for e in self.elements],
        }


def decode_message_body(body: bytes) -> MessageBody:
    """解码存储在 ``40800`` 列中的内部消息体。"""
    if not body:
        return MessageBody(fields=[])
    fields = protobuf.decode_tree(body)
    return MessageBody(fields=fields, elements=_group_elements(fields))


def _group_elements(fields: list[Field]) -> list[Element]:
    """收集由 ``45002`` 选中的元素家族（外加任何额外字段）。"""
    element_type = None
    for fld in fields:
        if fld.number == 45002:
            element_type = fld.value
            break

    buckets: dict[str, list[Field]] = {}
    if element_type in ELEMENT_FIELDS:
        kind, rng = ELEMENT_FIELDS[element_type]
        buckets[kind] = [f for f in fields if f.number in rng]
    else:
        for fld in fields:
            kind = _fallback_family(fld.number)
            if kind is not None:
                buckets.setdefault(kind, []).append(fld)
    return [Element(kind, items) for kind, items in buckets.items() if items]


def _fallback_family(number: int) -> str | None:
    for kind, rng in _FALLBACK_FAMILIES:
        if number in rng:
            return kind
    return None


# ---------------------------------------------------------------------------
# 渲染
# ---------------------------------------------------------------------------


def _quote_reply(element: Element) -> str:
    inner = element.get(47423)
    if inner is None or inner.message is None:
        return "[回复]"
    quoted = MessageBody(fields=inner.message, elements=_group_elements(inner.message))
    return "[回复 " + quoted.text() + "]"


def render_element(element: Element) -> str:
    kind = element.kind
    if kind == "text":
        text = element.string(45101) or ""
        at_uid = element.string(45105)
        if at_uid and not text.startswith("@"):
            text = "@" + text
        return text
    if kind == "media":
        name = element.string(45402) or ""
        summary = element.string(45815)
        lower = name.lower()
        if lower.endswith((".amr", ".silk", ".mp3", ".wav", ".m4a")):
            return "[语音]"
        if lower.endswith((".mp4", ".mkv", ".mov", ".avi", ".wmv")):
            return "[视频]"
        if summary:
            return summary
        if name and not lower.endswith((".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".heic")):
            return f"[文件 {name}]"
        return "[图片]"
    if kind == "reply":
        return _quote_reply(element)
    if kind == "face":
        return element.string(47602) or "[表情]"
    if kind == "poke":
        poker = element.string(47705) or ""
        poked = element.string(47707) or ""
        if poker and poked:
            return f"[戳一戳 {poker} -> {poked}]"
        return "[戳一戳]"
    if kind == "share":
        return "[分享]"
    if kind == "market_face":
        return "[表情]"
    if kind == "ark":
        return element.string(80900) or "[卡片消息]"
    if kind == "forward":
        return "[聊天记录]"
    if kind == "markdown":
        return element.string(48403) or "[Markdown]"
    if kind == "bot_markdown":
        payload = element.string(48751)
        if payload:
            return payload
        return "[消息]"
    if kind == "system":
        return element.string(48271) or "[系统消息]"
    return ""


def element_to_dict(element: Element) -> dict[str, Any]:
    return element.to_dict()
