"""QQ NT 数据库的列映射。

已解密数据库中的每张表都用数字协议字段号标识（``"40001"``、``"60007"`` ...）。
本模块为这些列提供稳定、易读的名称，应用代码从此无需记住数字。

名称沿用参考项目（``nt_msg.py``）的布局，以及逆向这些文件时收集到的
证据；尚未弄清楚的列保留中性的 ``f<number>`` 名称，其原始数据仍会无损保留，
可通过 :meth:`Model.to_dict(raw=True)` 访问。
"""

from __future__ import annotations

from .orm import Model, col

# ---------------------------------------------------------------------------
# nt_msg.db - 消息表
# ---------------------------------------------------------------------------


class _MessageColumns(Model):
    """所有聊天表共用的列（群聊 / 私聊 / 数据线 / 讨论组）。"""

    __columns__ = {
        "msg_id": col(40001, "msg_id", "int", primary_key=True),
        "msg_random": col(40002, "msg_random"),
        "msg_seq": col(40003, "msg_seq"),
        "chat_type": col(40010, "chat_type"),
        "msg_type": col(40011, "msg_type"),
        "sub_msg_type": col(40012, "sub_msg_type"),
        "send_type": col(40013, "send_type"),
        "sender_uid": col(40020, "sender_uid", "str"),
        "f40026": col(40026, "f40026"),
        "peer_uid": col(40021, "peer_uid", "str"),
        "peer_uin": col(40027, "peer_uin"),
        "f40040": col(40040, "f40040"),
        "send_status": col(40041, "send_status"),
        "msg_time": col(40050, "msg_time"),
        "f40052": col(40052, "f40052"),
        "sender_name": col(40090, "sender_name", "str"),
        "sender_card": col(40093, "sender_card", "str"),
        "msg_body": col(40800, "msg_body", "bytes"),
        "ref_body": col(40900, "ref_body", "bytes"),
        "f40105": col(40105, "f40105"),
        "f40005": col(40005, "f40005"),
        "msg_time_day": col(40058, "msg_time_day"),
        "elem_id": col(40006, "elem_id"),
        "at_flag": col(40100, "at_flag"),
        "msg_status": col(40600, "msg_status", "bytes"),
        "group_state": col(40060, "group_state"),
        "ref_seq": col(40850, "ref_seq"),
        "f40851": col(40851, "f40851"),
        "f40601": col(40601, "f40601", "bytes"),
        "f40801": col(40801, "f40801", "bytes"),
        "f40605": col(40605, "f40605", "bytes"),
        "peer_uin_2": col(40030, "peer_uin_2"),
        "sender_uin": col(40033, "sender_uin"),
        "f40062": col(40062, "f40062", "bytes"),
        "f40083": col(40083, "f40083"),
        "f40084": col(40084, "f40084"),
        "f40008": col(40008, "f40008"),
        "f40009": col(40009, "f40009"),
        "f40722": col(40722, "f40722", "bytes"),
    }


class GroupMessage(_MessageColumns):
    """``nt_msg.db`` -> ``group_msg_table`` (群聊消息)."""

    __tablename__ = "group_msg_table"


class PrivateMessage(_MessageColumns):
    """``nt_msg.db`` -> ``c2c_msg_table`` (私聊消息)."""

    __tablename__ = "c2c_msg_table"


class DatalineMessage(_MessageColumns):
    """``nt_msg.db`` -> ``dataline_msg_table`` (我的设备 / 数据线)."""

    __tablename__ = "dataline_msg_table"


class DiscussMessage(_MessageColumns):
    """``nt_msg.db`` -> ``discuss_msg_table`` (讨论组消息)."""

    __tablename__ = "discuss_msg_table"


class C2CTempMessage(_MessageColumns):
    """``nt_msg.db`` -> ``c2c_temp_msg_table`` (临时会话)."""

    __tablename__ = "c2c_temp_msg_table"


class ServiceAssistantMessage(_MessageColumns):
    """``nt_msg.db`` -> ``service_assistant_msg_table`` (服务号)."""

    __tablename__ = "service_assistant_msg_table"


class AiAssistantMessage(_MessageColumns):
    """``nt_msg.db`` -> ``ai_assistant_msg_table`` (AI 助手)."""

    __tablename__ = "ai_assistant_msg_table"


class UidMapping(Model):
    """``nt_msg.db`` -> ``nt_uid_mapping_table`` (uid <-> uin)."""

    __tablename__ = "nt_uid_mapping_table"
    __columns__ = {
        "id": col(48901, "id", "str", primary_key=True),
        "uid": col(48902, "uid", "str"),
        "f48912": col(48912, "f48912", "str"),
        "uin": col(1002, "uin"),
    }


class RecentContact(Model):
    """``nt_msg.db`` -> ``recent_contact_v3_table`` (最近会话).

    最后一条消息的预览（以消息体的形式）存放在列 ``40051`` 中；
    会话标题是 ``40094``，发送者名片是 ``40093``。
    """

    __tablename__ = "recent_contact_v3_table"
    __columns__ = {
        "id": col(41102, "id", primary_key=True),
        "chat_type": col(40010, "chat_type"),
        "peer": col(40021, "peer", "str"),
        "f40027": col(40027, "f40027"),
        "msg_id": col(40001, "msg_id"),
        "msg_seq": col(40003, "msg_seq"),
        "msg_time": col(40050, "msg_time"),
        "update_time": col(41136, "update_time"),
        "sender_uid": col(40020, "sender_uid", "str"),
        "sender_uin": col(40033, "sender_uin"),
        "sender_name": col(40090, "sender_name", "str"),
        "sender_card": col(40093, "sender_card", "str"),
        "chat_name": col(40094, "chat_name", "str"),
        "f40095": col(40095, "f40095", "str"),
        "f40096": col(40096, "f40096", "str"),
        "preview": col(40051, "preview", "bytes"),
        "avatar": col(41110, "avatar", "str"),
        "f40055": col(40055, "f40055"),
    }


class AtMeMessage(Model):
    """``nt_msg.db`` -> ``group_at_me_msg``（群里 @ 我 的消息索引）。

    这是一张"瘦"表：只记录被 @ 到的消息的定位信息，**没有消息体**，
    因此不继承 :class:`_MessageColumns`。
    """

    __tablename__ = "group_at_me_msg"
    __columns__ = {
        "msg_id": col(40001, "msg_id", primary_key=True),
        "peer_uin": col(40027, "peer_uin"),
        "sender_uid": col(40020, "sender_uid", "str"),
        "at_flag": col(40100, "at_flag"),
        "msg_time": col(40050, "msg_time"),
        "msg_seq": col(40003, "msg_seq"),
    }


class UnreadInfo(Model):
    """``nt_msg.db`` -> ``msg_unread_info_table``（未读状态，键值表）。

    实际只有 ``48901``/``48902`` 两列：键形如 ``"2_369573838"``（对话类型_对端），
    值为序列化后的未读状态。
    """

    __tablename__ = "msg_unread_info_table"
    __columns__ = {
        "key": col(48901, "key", "str", primary_key=True),
        "value": col(48902, "value", "bytes"),
    }


class KVStorage(Model):
    """``nt_msg.db`` -> ``nt_kv_storage_table`` (杂项键值)."""

    __tablename__ = "nt_kv_storage_table"
    __columns__ = {
        "key": col(48901, "key", "str", primary_key=True),
        "value": col(48902, "value", "str"),
    }


# ---------------------------------------------------------------------------
# group_info.db
# ---------------------------------------------------------------------------


class GroupList(Model):
    """``group_info.db`` -> ``group_list`` (群列表)."""

    __tablename__ = "group_list"
    __columns__ = {
        "group_uin": col(60001, "group_uin", primary_key=True),
        "f60221": col(60221, "f60221"),
        "create_time": col(60004, "create_time"),
        "max_member": col(60005, "max_member"),
        "member_count": col(60006, "member_count"),
        "name": col(60007, "name", "str"),
        "f60008": col(60008, "f60008"),
        "f60009": col(60009, "f60009"),
        "f60020": col(60020, "f60020"),
        "f60011": col(60011, "f60011"),
        "f60010": col(60010, "f60010"),
        "f60017": col(60017, "f60017"),
        "f60018": col(60018, "f60018"),
        "remark": col(60026, "remark", "str"),
        "f60022": col(60022, "f60022"),
        "f60023": col(60023, "f60023"),
        "f60027": col(60027, "f60027"),
        "f60028": col(60028, "f60028"),
        "f60029": col(60029, "f60029"),
        "f60030": col(60030, "f60030"),
        "f60031": col(60031, "f60031"),
        "f60269": col(60269, "f60269"),
        "f60012": col(60012, "f60012"),
        "f60034": col(60034, "f60034"),
        "f60035": col(60035, "f60035"),
        "f60036": col(60036, "f60036"),
        "f60037": col(60037, "f60037"),
        "f60038": col(60038, "f60038"),
        "f60204": col(60204, "f60204"),
        "f60238": col(60238, "f60238"),
        "f60258": col(60258, "f60258"),
        "f60277": col(60277, "f60277"),
        "f60040": col(60040, "f60040", "bytes"),
        "f60216": col(60216, "f60216", "bytes"),
        "f60267": col(60267, "f60267", "str"),
        "f60344": col(60344, "f60344"),
    }


class GroupMember(Model):
    """``group_info.db`` -> ``group_member3`` (群成员)."""

    __tablename__ = "group_member3"
    __columns__ = {
        "group_uin": col(60001, "group_uin", primary_key=True),
        "uid": col(1000, "uid", "str", primary_key=True),
        "qid": col(1001, "qid", "str"),
        "uin": col(1002, "uin"),
        "nickname": col(20002, "nickname", "str"),
        "card": col(64003, "card", "str"),
        "f64002": col(64002, "f64002"),
        "f64004": col(64004, "f64004", "bytes"),
        "f64005": col(64005, "f64005"),
        "f64006": col(64006, "f64006"),
        "join_time": col(64007, "join_time"),
        "last_message_time": col(64008, "last_message_time"),
        "last_ban_ends": col(64009, "last_ban_ends"),
        "admin": col(64010, "admin"),
        "f64011": col(64011, "f64011"),
        "f64012": col(64012, "f64012"),
        "f64013": col(64013, "f64013"),
        "f64015": col(64015, "f64015"),
        "status": col(64016, "status"),
        "f64017": col(64017, "f64017"),
        "f64018": col(64018, "f64018"),
        "f64020": col(64020, "f64020"),
        "f64021": col(64021, "f64021"),
        "f64022": col(64022, "f64022"),
        "custom_badge": col(64023, "custom_badge", "str"),
        "f64024": col(64024, "f64024"),
        "f64025": col(64025, "f64025"),
        "f64026": col(64026, "f64026"),
        "f64027": col(64027, "f64027"),
        "f64028": col(64028, "f64028"),
        "f64029": col(64029, "f64029", "str"),
        "f64030": col(64030, "f64030"),
        "f64031": col(64031, "f64031"),
        "f64032": col(64032, "f64032"),
        "f64034": col(64034, "f64034"),
        "level": col(64035, "level"),
    }


class GroupDetail(Model):
    """``group_info.db`` -> ``group_detail_info_ver1`` (群聊更多信息)."""

    __tablename__ = "group_detail_info_ver1"
    __columns__ = {
        "group_uin": col(60001, "group_uin", primary_key=True),
        "owner_uid": col(60002, "owner_uid", "str"),
        "create_time": col(60004, "create_time"),
        "max_member": col(60005, "max_member"),
        "member_count": col(60006, "member_count"),
        "name": col(60007, "name", "str"),
        "remark": col(60026, "remark", "str"),
        "bulletin": col(60216, "bulletin", "bytes"),
        "desc": col(60217, "desc", "bytes"),
        "tags": col(60218, "tags", "str"),
        "question": col(60224, "question", "str"),
        "f60221": col(60221, "f60221"),
        "f60258": col(60258, "f60258"),
        "f60277": col(60277, "f60277"),
        "f60340": col(60340, "f60340"),
        "f60344": col(60344, "f60344"),
    }


class GroupEssence(Model):
    """``group_info.db`` -> ``group_essence`` (群精华消息)."""

    __tablename__ = "group_essence"
    __columns__ = {
        "group_uin": col(60001, "group_uin", primary_key=True),
        "seq": col(67501, "seq", primary_key=True),
        "msg_random": col(67502, "msg_random", primary_key=True),
        "sender_uin": col(67503, "sender_uin"),
        "sender_nickname": col(67504, "sender_nickname", "str"),
        "status": col(67505, "status"),
        "setter_uin": col(67506, "setter_uin"),
        "setter_nickname": col(67507, "setter_nickname", "str"),
        "timestamp": col(67508, "timestamp"),
        "f67509": col(67509, "f67509"),
    }


class GroupBulletin(Model):
    """``group_info.db`` -> ``group_bulletin`` (群公告)."""

    __tablename__ = "group_bulletin"
    __columns__ = {
        "group_uin": col(60001, "group_uin", primary_key=True),
        "bulletin": col(64205, "bulletin", "bytes"),
    }


# ---------------------------------------------------------------------------
# profile_info.db
# ---------------------------------------------------------------------------


class BuddyProfile(Model):
    """``profile_info.db`` -> ``profile_info_v6`` (好友资料)."""

    __tablename__ = "profile_info_v6"
    __columns__ = {
        "uid": col(1000, "uid", "str", primary_key=True),
        "qid": col(1001, "qid", "str"),
        "uin": col(1002, "uin"),
        "nickname": col(20002, "nickname", "str"),
        "remark": col(20009, "remark", "str"),
        "signature": col(20011, "signature", "str"),
        "avatar_url": col(20004, "avatar_url", "str"),
        "f24106": col(24106, "f24106", "str"),
        "f24107": col(24107, "f24107", "str"),
        "f24108": col(24108, "f24108", "str"),
        "f24109": col(24109, "f24109", "str"),
        "f20003": col(20003, "f20003"),
        "f20005": col(20005, "f20005"),
        "f20006": col(20006, "f20006"),
        "f20007": col(20007, "f20007"),
        "f20008": col(20008, "f20008"),
        "f20010": col(20010, "f20010"),
        "f20012": col(20012, "f20012"),
    }


class Buddy(Model):
    """``profile_info.db`` -> ``buddy_list`` (好友列表)."""

    __tablename__ = "buddy_list"
    __columns__ = {
        "uid": col(1000, "uid", "str", primary_key=True),
        "qid": col(1001, "qid", "str"),
        "uin": col(1002, "uin"),
        "category": col(25007, "category"),
    }


class BuddyCategory(Model):
    """``profile_info.db`` -> ``category_list_v2`` (好友分组)."""

    __tablename__ = "category_list_v2"
    __columns__ = {
        "id": col(1000, "id", "str", primary_key=True),
        "name": col(25001, "name", "str"),
        "data": col(25011, "data", "bytes"),
        "f25006": col(25006, "f25006"),
        "f25012": col(25012, "f25012"),
        "f25013": col(25013, "f25013"),
        "f25015": col(25015, "f25015"),
    }


# ---------------------------------------------------------------------------
# emoji.db
# ---------------------------------------------------------------------------


class SystemEmoji(Model):
    """``emoji.db`` -> ``base_sys_emoji_table`` (系统表情)."""

    __tablename__ = "base_sys_emoji_table"
    __columns__ = {
        "id": col(81211, "id", "str", primary_key=True),
        "desc": col(81212, "desc", "str"),
        "f81213": col(81213, "f81213", "str"),
        "download_link": col(81218, "download_link", "str"),
        "emoji_type": col(81226, "emoji_type"),
        "type_desc": col(81266, "type_desc", "str"),
        "static_download_link": col(81229, "static_download_link", "str"),
        "apng_link": col(81230, "apng_link", "str"),
    }


class MarketSticker(Model):
    """``emoji.db`` -> ``market_emoticon_table`` (商城表情)."""

    __tablename__ = "market_emoticon_table"
    __columns__ = {
        "id": col(80920, "id", "str", primary_key=True),
        "pack_id": col(80943, "pack_id", "str", primary_key=True),
        "alt": col(80921, "alt", "str"),
        "keyword": col(80930, "keyword", "str"),
    }


class FavEmoji(Model):
    """``emoji.db`` -> ``fav_emoji_info_storage_table`` (收藏表情)."""

    __tablename__ = "fav_emoji_info_storage_table"
    __columns__ = {
        "filename": col(80002, "filename", "str", primary_key=True),
        "order": col(80001, "order"),
        "uin": col(1002, "uin"),
        "local_path": col(80012, "local_path", "str"),
        "download_url": col(80010, "download_url", "str"),
        "md5": col(80011, "md5", "str"),
        "original": col(80213, "original"),
        "desc": col(80223, "desc", "str"),
    }


# ---------------------------------------------------------------------------

#: 供 :class:`ntqq.orm.DatabaseManager` 使用的 ``{数据库文件名: [模型]}`` 映射。
DATABASES: dict[str, list[type[Model]]] = {
    "nt_msg.db": [
        GroupMessage,
        PrivateMessage,
        DatalineMessage,
        DiscussMessage,
        C2CTempMessage,
        ServiceAssistantMessage,
        AiAssistantMessage,
        AtMeMessage,
        UidMapping,
        RecentContact,
        UnreadInfo,
        KVStorage,
    ],
    "group_info.db": [
        GroupList,
        GroupMember,
        GroupDetail,
        GroupEssence,
        GroupBulletin,
    ],
    "profile_info.db": [
        BuddyProfile,
        Buddy,
        BuddyCategory,
    ],
    "emoji.db": [
        SystemEmoji,
        MarketSticker,
        FavEmoji,
    ],
}

#: 易读的表名 -> 模型类，与具体数据库无关。
MESSAGE_MODELS: dict[str, type[Model]] = {
    "group_msg_table": GroupMessage,
    "c2c_msg_table": PrivateMessage,
    "dataline_msg_table": DatalineMessage,
    "discuss_msg_table": DiscussMessage,
    "c2c_temp_msg_table": C2CTempMessage,
    "service_assistant_msg_table": ServiceAssistantMessage,
    "ai_assistant_msg_table": AiAssistantMessage,
    "group_at_me_msg": AtMeMessage,
}
