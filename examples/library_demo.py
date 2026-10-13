#!/usr/bin/env python3
"""使用 ntqq 库浏览 QQ 配置目录。

    python3 examples/library_demo.py 1145141919810
    python3 examples/library_demo.py '操作系统' --source work/plain

配置目录/密钥来自 ``--source`` / ``--key`` 或环境变量
（``NTQQ_DB_KEY``）。未指定 ``--source`` 时，使用
``~/.config/QQ`` 中最新的配置目录。
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ntqq import QQNT


def newest_profile() -> Path:
    candidates = [p for p in Path.home().glob(".config/QQ/nt_qq_*") if (p / "nt_db").is_dir()]
    if not candidates:
        raise SystemExit("no QQ profile found; pass --source")
    return max(candidates, key=lambda p: (p / "nt_db").stat().st_mtime)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("chat", nargs="?", help="群号/QQ 号、uid，或名字片段")
    parser.add_argument("--source", help="QQ 账号目录，或已解密数据库目录")
    parser.add_argument("--key", help="数据库口令（默认取 $NTQQ_DB_KEY）")
    parser.add_argument("--limit", type=int, default=10, help="显示的条数")
    parser.add_argument("--search", help="改为按关键词检索，而不是列历史消息")
    args = parser.parse_args()

    source = Path(args.source).expanduser() if args.source else newest_profile()
    print(f"source: {source}")
    qq = QQNT.open(source, key=args.key or os.environ.get("NTQQ_DB_KEY"))

    groups, friends = qq.groups(), qq.friends()
    print(f"{len(groups)} groups, {len(friends)} friends")

    if not args.chat:
        for group in groups[: args.limit]:
            print(f"  {group.uin:>12}  {group.name}")
        qq.close()
        return 0

    chat = qq.contact(args.chat)
    if chat is None:
        print(f"unknown chat: {args.chat}", file=sys.stderr)
        qq.close()
        return 1
    print(f"chat: {chat.display_name} ({chat.kind})")

    if args.search:
        messages = qq.search(args.search, chat=chat, limit=args.limit)
        print(f"{len(messages)} hit(s) for {args.search!r}")
    else:
        messages = qq.history(chat, limit=args.limit)

    for message in messages:
        kind = f"[{message.type_name}]" if message.type_name != "text" else ""
        print(f"  {message.time_str}  {message.display_sender}: {message.text[:80]} {kind}")

    qq.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
