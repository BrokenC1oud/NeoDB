"""全库穷举解析测试：逐行读取每一条数据并完整解析，验证代码可用性。

与 ``test_library.py``（自造的小库）不同，这里的测试跑在**真实数据**上：
默认使用仓库的 ``work/plain``，或用 ``$NTQQ_TEST_DB`` 指向任意已解密目录；
两者都不存在时整个文件自动跳过（CI 不需要真实数据库）。

    pytest tests/test_full_scan.py                      # 全量（500 万行，约 10 分钟）
    NTQQ_TEST_LIMIT=20000 pytest tests/test_full_scan.py  # 每表抽样 2 万行
    NTQQ_TEST_DB=/path/to/plain pytest tests/test_full_scan.py

通过的标准是：库里**每一条**数据都能被读出并解析成消息/JSON ——
不允许出现任何一行解析失败、任何一张表读取失败、任何一次解码器抛错。
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ntqq.world import QQNT

REPO_ROOT = Path(__file__).resolve().parent.parent


def _find_database() -> Path | None:
    override = os.environ.get("NTQQ_TEST_DB")
    if override:
        path = Path(override).expanduser()
        return path if path.exists() else None
    for candidate in (REPO_ROOT / "work" / "plain", REPO_ROOT / "work"):
        if (candidate / "nt_msg.db").is_file():
            return candidate
    return None


DATABASE = _find_database()
#: 每张表处理的最大行数；0/未设置表示全量。
LIMIT = int(os.environ.get("NTQQ_TEST_LIMIT", "0")) or None


@unittest.skipUnless(DATABASE, "未找到已解密数据库（设置 NTQQ_TEST_DB 或先解密到 work/plain）")
class FullScanTests(unittest.TestCase):
    """逐条解析全库，确认没有一行读不出来。"""

    report = None

    @classmethod
    def setUpClass(cls) -> None:
        cls._qq = QQNT(str(DATABASE))
        # 全量扫描很慢，整个测试类共用一份结果。
        cls.report = cls._qq.scan(limit=LIMIT, samples=3)
        print("\n" + cls.report.summary())

    @classmethod
    def tearDownClass(cls) -> None:
        cls._qq.close()

    def test_no_row_failed_to_parse(self) -> None:
        self.assertEqual(self.report.failures_total, 0, f"有行解析失败：{self.report.failures[:5]}")
        self.assertEqual(self.report.failures, [])

    def test_every_table_was_readable(self) -> None:
        self.assertEqual(self.report.table_failures, {}, "有表读取失败")

    def test_no_decoder_crashed(self) -> None:
        """元素解码器不得抛错（未知类型可以走兜底，但崩溃就是 bug）。"""
        self.assertEqual(
            self.report.decoder_errors, {}, f"解码器抛错：{self.report.decoder_errors}"
        )

    def test_unknown_element_types_are_reported(self) -> None:
        """未支持的元素类型不算失败，但必须在报告里可见。"""
        if self.report.unsupported_types:
            print(
                "\n未支持的元素类型（已按兜底渲染，原始字段仍在 raw 中）:",
                self.report.unsupported_types,
            )

    def test_scan_covered_real_data(self) -> None:
        self.assertGreater(self.report.rows, 0, "一行都没读到")
        self.assertGreater(self.report.decoded, 0, "一条消息都没解析到")
        self.assertEqual(self.report.rows, sum(self.report.tables.values()))

    def test_reported_statistics_are_consistent(self) -> None:
        # 每种元素类型都应有名字（不会出现 "type_<未知数字>" 之外的空串）。
        for kind, count in self.report.kinds.items():
            self.assertTrue(kind, "元素类型为空")
            self.assertGreater(count, 0)
        # 空消息体是允许的（删除/系统行），但不能全是空。
        self.assertLess(self.report.empty_bodies, self.report.decoded)

    def test_samples_are_json_serialisable(self) -> None:
        for sample in self.report.samples:
            json.dumps(sample, ensure_ascii=False)
            self.assertIn("elements", sample)
            self.assertIn("type", sample)

    def test_every_row_can_be_dumped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "dump.jsonl"
            # 抽样即可：验证"逐条落盘 → 逐行读回"这条路径通畅。
            small = self._qq.scan(limit=LIMIT or 2000, samples=0, dump=target)
            lines = target.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), small.decoded)
            for index, line in enumerate(lines[:50]):
                payload = json.loads(line)
                self.assertIn("type", payload, f"第 {index} 行缺少 type")
                self.assertIn("text", payload, f"第 {index} 行缺少 text")


@unittest.skipUnless(DATABASE, "未找到已解密数据库")
class OrmCoverageTests(unittest.TestCase):
    """ORM 层面：每张已映射表都要能计数、取首行、逐行读。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls._qq = QQNT(str(DATABASE))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._qq.close()

    def test_every_mapped_table_is_readable(self) -> None:
        problems: list[str] = []
        for name, table in sorted(self._qq.manager.tables.items()):
            try:
                count = table.count()
                row = table.query().limit(1).first()
                if row is not None:
                    row.to_dict()  # 触发所有映射列的读取
                    self.assertIsInstance(row.values, dict)
                if count == 0:
                    continue
                # 逐行读到末尾（抽样上限，避免测试过慢）。
                seen = sum(1 for _ in table.query().limit(LIMIT or 5000).iterate())
                self.assertGreater(seen, 0)
            # 汇总所有问题后一次性报出
            except Exception as error:
                problems.append(f"{name}: {type(error).__name__}: {error}")
        self.assertEqual(problems, [], "以下表读取失败：\n" + "\n".join(problems))

    def test_no_table_has_all_columns_missing(self) -> None:
        broken = [
            name for name, table in self._qq.manager.tables.items() if not table.columns_present
        ]
        self.assertEqual(broken, [], "这些表的映射列号与真实表完全不匹配")


if __name__ == "__main__":
    unittest.main(verbosity=2)
