"""查询/解析库（ntqq.orm / ntqq.message / ntqq.world）的离线测试。

在临时目录中构建一个微型 QQ 数据库，使用的表名和列名与 QQ 相同，
因此测试既不需要真实配置目录，也不需要密钥。
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ntqq import protobuf
from ntqq.export import export_csv, export_html, export_jsonl, export_markdown
from ntqq.message import Message, parse_elements, unwrap_body
from ntqq.orm import DatabaseManager
from ntqq.world import QQNT, repair_file

# ---------------------------------------------------------------------------
# protobuf 辅助函数
# ---------------------------------------------------------------------------


def pb_varint(number: int, value: int) -> bytes:
    return protobuf.encode_varint((number << 3) | 0) + protobuf.encode_varint(value)


def pb_bytes(number: int, value: bytes) -> bytes:
    return protobuf.encode_varint((number << 3) | 2) + protobuf.encode_varint(len(value)) + value


def pb_text(number: int, value: str) -> bytes:
    return pb_bytes(number, value.encode("utf-8"))


def body(*fields: bytes, element_type: int = 1, msg_id: int = 1) -> bytes:
    inner = pb_varint(45001, msg_id) + pb_varint(45002, element_type) + b"".join(fields)
    return pb_bytes(40800, inner)


# ---------------------------------------------------------------------------
# 微型数据库
# ---------------------------------------------------------------------------

NT_MSG_SCHEMA = """
CREATE TABLE group_msg_table([40001] INTEGER PRIMARY KEY,[40002] INTEGER,[40003] INTEGER,
 [40010] INTEGER,[40011] INTEGER,[40012] INTEGER,[40013] INTEGER,[40020] TEXT,[40026] INTEGER,
 [40021] TEXT,[40027] INTEGER,[40040] INTEGER,[40041] INTEGER,[40050] INTEGER,[40052] INTEGER,
 [40090] TEXT,[40093] TEXT,[40800] BLOB,[40900] BLOB,[40105] INTEGER,[40005] INTEGER,
 [40058] INTEGER,[40006] INTEGER,[40100] INTEGER,[40600] BLOB,[40060] INTEGER,[40850] INTEGER,
 [40851] INTEGER,[40601] BLOB,[40801] BLOB,[40605] BLOB,[40030] INTEGER,[40033] INTEGER,
 [40062] BLOB,[40083] INTEGER,[40084] INTEGER,[40008] INTEGER,[40009] INTEGER,[40722] BLOB);
CREATE TABLE c2c_msg_table([40001] INTEGER PRIMARY KEY,[40002] INTEGER,[40003] INTEGER,
 [40010] INTEGER,[40020] TEXT,[40021] TEXT,[40027] INTEGER,[40033] INTEGER,[40050] INTEGER,
 [40090] TEXT,[40093] TEXT,[40800] BLOB,[40030] INTEGER);
CREATE TABLE nt_uid_mapping_table([48901] TEXT PRIMARY KEY,[48902] TEXT,[48912] TEXT,[1002] INTEGER);
CREATE TABLE recent_contact_v3_table([41102] INTEGER PRIMARY KEY,[40010] INTEGER,[40021] TEXT,
 [40027] INTEGER,[40050] INTEGER,[40090] TEXT,[40093] TEXT,[40094] TEXT,[40051] BLOB,[40001] INTEGER,
 [40020] TEXT,[40033] INTEGER,[40003] INTEGER);
"""

GROUP_INFO_SCHEMA = """
CREATE TABLE group_list([60001] INTEGER PRIMARY KEY,[60007] TEXT,[60026] TEXT,[60005] INTEGER,
 [60006] INTEGER,[60004] INTEGER);
CREATE TABLE group_member3([60001] INTEGER,[1000] TEXT,[1002] INTEGER,[20002] TEXT,[64003] TEXT,
 [64010] INTEGER,[64007] INTEGER,[64035] INTEGER, PRIMARY KEY([60001],[1000]));
"""

PROFILE_SCHEMA = """
CREATE TABLE buddy_list([1000] TEXT PRIMARY KEY,[1001] TEXT,[1002] INTEGER,[25007] INTEGER);
CREATE TABLE profile_info_v6([1000] TEXT PRIMARY KEY,[1001] TEXT,[1002] INTEGER,[20002] TEXT,
 [20009] TEXT,[20011] TEXT,[20004] TEXT);
"""


def build_databases(directory: Path) -> Path:
    nt = sqlite3.connect(directory / "nt_msg.db")
    nt.executescript(NT_MSG_SCHEMA)
    now = int(dt.datetime(2025, 9, 10, 12, 0, 0).timestamp())
    rows = [
        # 各字段依次为 (msg_id, seq, peer_uin, sender_uid, sender_uin, name, time, body)
        (1, 1, 1001, "u_alice", 11, "Alice", now, body(pb_text(45101, "hello world"))),
        (
            2,
            2,
            1001,
            "u_bob",
            22,
            "Bob",
            now + 60,
            body(
                pb_text(45402, "cat.jpg"),
                pb_varint(45411, 640),
                pb_varint(45412, 480),
                pb_text(45815, "一只猫"),
                element_type=2,
            ),
        ),
        (
            3,
            3,
            1001,
            "u_alice",
            11,
            "Alice",
            now + 120,
            body(
                pb_bytes(
                    47423, pb_text(45101, "hello world") + pb_varint(45002, 1) + pb_varint(45001, 1)
                ),
                pb_varint(47402, 1),
                pb_varint(47403, 11),
                element_type=7,
            ),
        ),
        (
            4,
            4,
            1002,
            "u_carol",
            33,
            "Carol",
            now + 180,
            body(pb_text(47705, "Carol"), pb_text(47707, "Bob"), element_type=8),
        ),
    ]
    for msg_id, seq, peer, uid, uin, name, ts, blob in rows:
        nt.execute(
            'INSERT INTO group_msg_table ("40001","40002","40003","40010","40020","40021",'
            '"40027","40030","40033","40041","40050","40090","40093","40800") '
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (msg_id, 0, seq, 2, uid, str(peer), peer, peer, uin, 2, ts, name, "", blob),
        )
    nt.execute(
        "INSERT INTO c2c_msg_table VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            10,
            0,
            1,
            1,
            "u_dave",
            "u_dave",
            2002,
            44,
            now + 300,
            "Dave",
            "",
            body(pb_text(45101, "hi group")),
            2002,
        ),
    )
    nt.execute("INSERT INTO nt_uid_mapping_table VALUES ('u_alice','alice',NULL,11)")
    nt.execute("INSERT INTO nt_uid_mapping_table VALUES ('u_bob','bob',NULL,22)")
    preview = pb_bytes(
        40051, pb_text(45101, "hello world") + pb_varint(45002, 1) + pb_varint(45001, 1)
    )
    nt.execute(
        "INSERT INTO recent_contact_v3_table VALUES (1,2,'1001',1,?, 'Alice','Alice','测试群',?,1,'u_alice',11,3)",
        (now + 60, preview),
    )
    nt.commit()
    nt.close()

    gi = sqlite3.connect(directory / "group_info.db")
    gi.executescript(GROUP_INFO_SCHEMA)
    gi.execute("INSERT INTO group_list VALUES (1001, '测试群', '备注', 500, 42, 1600000000)")
    gi.execute("INSERT INTO group_list VALUES (1002, '另一个群', '', 200, 3, 1600000001)")
    gi.execute(
        "INSERT INTO group_member3 VALUES (1001,'u_alice',11,'Alice','Alice',1,1600000000,5)"
    )
    gi.execute("INSERT INTO group_member3 VALUES (1001,'u_bob',22,'Bob','',0,1600000001,3)")
    gi.commit()
    gi.close()

    pi = sqlite3.connect(directory / "profile_info.db")
    pi.executescript(PROFILE_SCHEMA)
    pi.execute("INSERT INTO buddy_list VALUES ('u_dave','dave',44,0)")
    pi.execute(
        "INSERT INTO profile_info_v6 VALUES ('u_dave','dave',44,'Dave','阿呆','你好','http://a')"
    )
    pi.commit()
    pi.close()
    return directory


# ---------------------------------------------------------------------------


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.directory = build_databases(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()


class OrmTests(Fixture):
    def test_manager_and_aliases(self) -> None:
        with DatabaseManager(self.directory) as manager:
            self.assertEqual(manager.group_messages.count(), 4)
            self.assertEqual(manager.private_messages.count(), 1)
            self.assertEqual(manager.groups.count(), 2)
            self.assertEqual(manager.friends.count(), 1)
            self.assertIn("group_msg_table", manager.table_names())

    def test_query_building(self) -> None:
        with DatabaseManager(self.directory) as manager:
            table = manager.group_messages
            self.assertEqual(table.filter(peer_uin=1001).count(), 3)
            self.assertEqual(table.filter(peer_uin=[1001, 1002]).count(), 4)
            self.assertEqual(table.contains("sender_name", "Ali").count(), 2)
            self.assertEqual(table.between("msg_time", 0, 10**12).count(), 4)
            first = table.query().order_by("msg_time").first()
            self.assertEqual(first.msg_id, 1)
            names = [row.sender_name for row in table.query().order_by("-msg_time").all()]
            self.assertEqual(names[0], "Carol")
            self.assertEqual(names[-1], "Alice")

    def test_row_access(self) -> None:
        with DatabaseManager(self.directory) as manager:
            row = manager.group_messages.filter(msg_id=1).first()
            self.assertEqual(row.msg_seq, 1)
            self.assertEqual(row.peer_uin, 1001)
            self.assertEqual(row.sender_uid, "u_alice")
            self.assertEqual(row.values[40001], 1)
            self.assertTrue(row.to_dict()["msg_body"])
            self.assertEqual(row.to_dict(raw=True)["columns"]["40001"], 1)

    def test_unknown_column_is_rejected(self) -> None:
        with DatabaseManager(self.directory) as manager, self.assertRaises(KeyError):
            manager.group_messages.filter(nope=1)

    def test_write_is_refused_on_read_only(self) -> None:
        with DatabaseManager(self.directory) as manager, self.assertRaises(PermissionError):
            manager.group_messages.insert(msg_id=99)


class MessageTests(Fixture):
    def test_text_element(self) -> None:
        with QQNT(self.directory) as qq:
            message = next(iter(qq.messages(scope="group")))
            self.assertEqual(message.text, "hello world")
            self.assertEqual(message.type_name, "text")
            self.assertEqual(message.id, 1)
            self.assertEqual(message.sender_name, "Alice")
            self.assertTrue(message.time_str.startswith("2025-09-10"))

    def test_image_and_poke_and_reply(self) -> None:
        with QQNT(self.directory) as qq:
            messages = list(qq.messages(scope="group"))
            image = messages[1]
            self.assertEqual(image.type_name, "image")
            self.assertEqual(image.element("image").filename, "cat.jpg")
            self.assertEqual(image.element("image").width, 640)
            self.assertEqual(image.text, "一只猫")

            reply = messages[2]
            self.assertEqual(reply.type_name, "reply")
            self.assertIsNotNone(reply.quote)
            self.assertEqual(reply.quote.quoted.text, "hello world")

            poke = messages[3]
            self.assertEqual(poke.type_name, "poke")
            self.assertIn("Carol", poke.text)

    def test_empty_body_is_not_an_error(self) -> None:
        with DatabaseManager(self.directory) as manager:
            manager.group_messages.insert(msg_id=5) if manager.writable else None
        with QQNT(self.directory) as qq:
            self.assertIsInstance(next(iter(qq.messages(scope="c2c"))), Message)

    def test_element_registry_keeps_raw_fields(self) -> None:
        elements = parse_elements(protobuf.decode_tree(unwrap_body(body(pb_text(45101, "x")))))
        self.assertEqual(elements[0].kind, "text")
        self.assertTrue(elements[0].raw)
        self.assertIn("fields", elements[0].to_dict())


class ElementRegistryTests(unittest.TestCase):
    """注册表与元素类型表必须保持一致，避免出现“无主解码器”。"""

    def test_every_element_name_has_a_decoder(self) -> None:
        from ntqq import message as m

        missing = sorted(set(m.ELEMENT_NAMES) - set(m._REGISTRY))
        self.assertEqual(missing, [], "这些元素类型没有解码器，会退化为 _decode_unsupported")

    def test_no_dead_decoders(self) -> None:
        from ntqq import message as m

        used = set(m._REGISTRY.values()) | {m._decode_unsupported}
        dead = sorted(
            name
            for name, obj in vars(m).items()
            if name.startswith("_decode_") and callable(obj) and obj not in used
        )
        self.assertEqual(dead, [], "这些解码器从未被注册，属于死代码")

    def test_registry_types_are_documented(self) -> None:
        from ntqq import message as m

        undocumented = sorted(set(m._REGISTRY) - set(m.ELEMENT_NAMES))
        self.assertEqual(undocumented, [], "注册表里有 ELEMENT_NAMES 未记录的类型")

    def test_menu_element(self) -> None:
        """类型 43（内嵌按钮菜单）：应用 id、按钮 id 与按钮文字都要解出来。"""

        def button(button_id: str, label: str) -> bytes:
            return pb_bytes(48753, pb_text(48754, button_id) + pb_text(48755, label))

        fields = protobuf.decode_tree(
            protobuf.encode_varint((45002 << 3) | 0)
            + protobuf.encode_varint(43)
            + pb_bytes(48751, button("b1", "面板") + button("b2", "菜单"))
            + pb_varint(48752, 102600645)
        )
        element = parse_elements(fields)[0]
        self.assertEqual(element.kind, "menu")
        self.assertEqual(element.app_id, 102600645)
        self.assertEqual(
            [(item.id, item.label) for item in element.items],
            [("b1", "面板"), ("b2", "菜单")],
        )
        self.assertEqual(str(element), "面板 | 菜单")
        self.assertEqual(element.to_dict()["items"][0]["label"], "面板")

    def test_unknown_type_falls_back(self) -> None:
        fields = protobuf.decode_tree(
            protobuf.encode_varint((45002 << 3) | 0)
            + protobuf.encode_varint(999)
            + pb_text(45101, "兜底文本")
        )
        element = parse_elements(fields)[0]
        self.assertEqual(element.kind, "unsupported")
        self.assertEqual(str(element), "兜底文本")


class WorldTests(Fixture):
    def test_contacts(self) -> None:
        with QQNT(self.directory) as qq:
            groups = qq.groups()
            self.assertEqual(len(groups), 2)
            group = qq.group(1001)
            self.assertEqual(group.name, "测试群")
            self.assertEqual(group.remark, "备注")
            self.assertEqual(group.member_count, 42)

            friends = qq.friends()
            self.assertEqual(len(friends), 1)
            self.assertEqual(friends[0].uin, 44)
            self.assertEqual(friends[0].display_name, "阿呆")

            self.assertEqual(qq.contact("1001").uin, 1001)
            self.assertEqual(qq.contact("u_dave").uin, 44)
            self.assertEqual(qq.contact("测试").uin, 1001)
            self.assertIsNone(qq.contact("nope"))

            members = qq.members(group)
            self.assertEqual(len(members), 2)
            self.assertEqual(members[0]["nickname"], "Alice")

    def test_history_ordering(self) -> None:
        with QQNT(self.directory) as qq:
            newest = qq.history(1001, limit=2)
            self.assertEqual([m.id for m in newest], [2, 3])
            newest_desc = qq.history(1001, limit=2, order="desc")
            self.assertEqual([m.id for m in newest_desc], [3, 2])

    def test_search(self) -> None:
        with QQNT(self.directory) as qq:
            # 回复消息会渲染其引用的消息，因此它也会匹配。
            hits = qq.search("hello")
            self.assertEqual([m.id for m in hits], [1, 3])
            self.assertEqual([m.id for m in qq.search("hello", kinds=["text"])], [1])
            self.assertEqual([m.id for m in qq.search("hello", chat=1001, kinds=["text"])], [1])
            self.assertEqual(len(qq.search("hello", chat=1002)), 0)
            self.assertEqual(len(qq.search("HELLO", case_sensitive=True)), 0)
            self.assertEqual(len(qq.search("hello", case_sensitive=False)), 2)
            self.assertEqual([m.id for m in qq.search("猫")], [2])
            self.assertEqual([m.id for m in qq.search("hello", sender="Alice")], [1, 3])
            self.assertEqual([m.id for m in qq.search("hello", sender="Bob")], [])
            since = dt.datetime(2025, 9, 10, 12, 1, 0)
            self.assertEqual([m.id for m in qq.search("hello", since=since)], [3])
            self.assertEqual(len(qq.search("hello", kinds=["image"])), 0)
            self.assertEqual(len(qq.search("hello", limit=1)), 1)

    def test_stats(self) -> None:
        with QQNT(self.directory) as qq:
            stats = qq.stats()
            self.assertEqual(stats["tables"]["group_msg_table"], 4)
            self.assertEqual(stats["groups"], 2)
            self.assertEqual(stats["friends"], 1)

    def test_exports(self) -> None:
        with QQNT(self.directory) as qq:
            messages = qq.history(1001, limit=10)
            tmp = Path(tempfile.mkdtemp())

            self.assertEqual(export_jsonl(messages, tmp / "a.jsonl"), 3)
            first = json.loads((tmp / "a.jsonl").read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(first["text"], "hello world")
            self.assertEqual(first["type"], "text")

            self.assertEqual(export_csv(messages, tmp / "a.csv"), 3)
            self.assertIn("hello world", (tmp / "a.csv").read_text(encoding="utf-8"))

            self.assertEqual(export_markdown(messages, tmp / "a.md", title="T"), 3)
            self.assertIn("## 2025-09-10", (tmp / "a.md").read_text(encoding="utf-8"))

            self.assertEqual(export_html(messages, tmp / "a.html", title="T"), 3)
            page = (tmp / "a.html").read_text(encoding="utf-8")
            self.assertIn("hello world", page)
            self.assertIn("一只猫", page)

            self.assertEqual(qq.export_html(1001, tmp / "b.html", limit=10), 3)


class RepairTests(Fixture):
    def test_repair_leaves_healthy_database_alone(self) -> None:
        actions = repair_file(self.directory / "nt_msg.db")
        self.assertEqual(actions, ["quick_check: ok"])


if __name__ == "__main__":
    unittest.main()
