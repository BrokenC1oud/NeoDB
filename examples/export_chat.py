#!/usr/bin/env python3
"""将单个 QQ 聊天导出为 HTML / Markdown / CSV / JSONL。

python3 examples/export_chat.py 1145141919810 -o os-group.html
python3 examples/export_chat.py '操作系统' --source work/plain --format markdown -o os.md
python3 examples/export_chat.py --list            # 列出可导出的聊天
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ntqq import QQNT, export


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("chat", nargs="?", help="群号/QQ 号、uid，或名字片段")
    parser.add_argument("-o", "--output", help="输出文件路径")
    parser.add_argument(
        "--format", default="html", choices=("html", "markdown", "csv", "jsonl"), help="导出格式"
    )
    parser.add_argument("--source", help="QQ 账号目录，或已解密数据库目录")
    parser.add_argument("--key", help="数据库口令（默认取 $NTQQ_DB_KEY）")
    parser.add_argument("--limit", type=int, default=100_000, help="最多导出的条数")
    parser.add_argument("--since", help="起始日期，如 2025-09-01")
    parser.add_argument("--until", help="结束日期，如 2025-09-30")
    parser.add_argument("--list", action="store_true", help="列出有消息的会话")
    args = parser.parse_args()

    source = Path(args.source).expanduser() if args.source else Path("work/plain")
    qq = QQNT.open(source, key=args.key or os.environ.get("NTQQ_DB_KEY"))

    if args.list:
        table = qq.manager.group_messages
        rows = table.connection.execute(
            'SELECT "40027", count(*) FROM group_msg_table NOT INDEXED GROUP BY 1 ORDER BY 2 DESC'
        ).fetchall()
        for uin, count in rows:
            chat = qq.group(uin)
            print(f"  {uin:>12}  {count:>8}  {chat.name if chat else ''}")
        qq.close()
        return 0

    if not args.chat or not args.output:
        parser.error("a chat and -o/--output are required (or use --list)")

    chat = qq.contact(args.chat)
    if chat is None:
        print(f"unknown chat: {args.chat}", file=sys.stderr)
        qq.close()
        return 1
    messages = qq.history(chat, limit=args.limit, since=args.since, until=args.until)
    title = chat.display_name

    if args.format == "html":
        count = qq.export_html(messages, args.output, title=title)
    elif args.format == "markdown":
        count = export.export_markdown(messages, args.output, title=title)
    elif args.format == "csv":
        count = export.export_csv(messages, args.output)
    else:
        count = export.export_jsonl(messages, args.output)
    print(f"wrote {count} messages to {args.output}")
    qq.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
