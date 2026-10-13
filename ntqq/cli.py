"""``ntqq`` 工具集的命令行界面。

示例
--------
解密数据库（密钥也可来自 ``$NTQQ_DB_KEY``）::

    python -m ntqq decrypt nt_msg.db nt_msg.plain.db --key '<passphrase>'

查看已解密的数据库::

    python -m ntqq info nt_msg.plain.db

将所有群消息导出为 JSON Lines::

    python -m ntqq export nt_msg.plain.db --table group_msg_table -o group.jsonl

美化打印单条消息的 protobuf::

    python -m ntqq dump nt_msg.plain.db --table group_msg_table --id 1145141919810
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import sys
from pathlib import Path

from . import elements as elements_mod
from . import header as header_mod
from . import protobuf, sqlcipher
from .reader import MessageDatabase, column_name, unwrap_column


def _key_from_args(args) -> bytes:
    if getattr(args, "key_hex", None):
        return bytes.fromhex(args.key_hex)
    key = getattr(args, "key", None) or os.environ.get("NTQQ_DB_KEY")
    if not key:
        raise SystemExit("no key supplied: use --key, --key-hex or $NTQQ_DB_KEY")
    return key.encode("utf-8")


def cmd_header(args) -> int:
    data = Path(args.database).read_bytes()[: header_mod.HEADER_SIZE]
    head = header_mod.parse_header(data)
    print(
        json.dumps(
            {
                "version": head.version,
                "hmac_algorithm": head.hmac_algorithm,
                "rand": head.rand,
                "marker_length": head.marker_length,
                "flags": head.flags.hex(),
            },
            indent=2,
        )
    )
    return 0


def _config_from_args(args) -> sqlcipher.CipherConfig | None:
    """根据显式的 CLI 覆盖项构建加密配置，否则返回 ``None``。"""
    hmac = getattr(args, "hmac", None)
    page_size = getattr(args, "page_size", None)
    kdf_prf = getattr(args, "kdf_prf", None)
    kdf_iter = getattr(args, "kdf_iter", None)
    if not any((hmac, page_size, kdf_prf, kdf_iter)):
        return None
    base = sqlcipher.DEFAULT_CONFIG
    return sqlcipher.CipherConfig(
        page_size=page_size or base.page_size,
        kdf_prf=kdf_prf or base.kdf_prf,
        kdf_iter=kdf_iter or base.kdf_iter,
        key_size=base.key_size,
        hmac_prf=hmac or base.hmac_prf,
        hmac_mask=base.hmac_mask,
    )


def _print_cipher(config) -> None:
    summary = config.summary()
    print(
        "cipher: "
        f"page_size={summary['page_size']} "
        f"kdf={summary['kdf']}({summary['kdf_iter']}) "
        f"hmac={summary['hmac']} "
        f"reserve={summary['reserve']}"
    )


def _resolve_config(args, source: Path, key: bytes):
    """返回要使用的加密配置，未覆盖时自动检测。"""
    config = _config_from_args(args)
    if config is not None:
        return config
    detected = sqlcipher.detect_config(source, key)
    if detected is None:
        print(
            "warning: could not auto-detect the cipher from the first pages; "
            "assuming the default (HMAC-SHA1)",
            file=sys.stderr,
        )
        return sqlcipher.DEFAULT_CONFIG
    return detected


def cmd_decrypt(args) -> int:
    source = Path(args.source)
    key = _key_from_args(args)
    config = _resolve_config(args, source, key)

    def progress(done: int, total: int) -> None:
        pct = done * 100 // max(total, 1)
        print(f"  {done:,}/{total:,} pages ({pct}%)", file=sys.stderr)

    if args.verify_only:
        header, salt, stats = sqlcipher.verify_file(source, key, progress=progress, config=config)
        print(f"QQ NT header: version={header.version!r} hmac={header.hmac_algorithm!r}")
        _print_cipher(config)
        print(f"salt: {salt.hex()}")
        print(f"pages: {stats.good_pages:,} ok / {stats.total_pages:,} total")
        if stats.sparse_zero_pages:
            print(f"sparse zero pages: {len(stats.sparse_zero_pages):,}")
        if stats.hmac_failures:
            print(f"HMAC failures: {len(stats.hmac_failures):,}")
            print(f"  first: {stats.hmac_failures[:8]}")
        ok = not stats.hmac_failures
        print("key is valid" if ok else "key is INVALID or the file is damaged")
        return 0 if ok else 2

    if args.output is None:
        raise SystemExit("an output path is required unless --verify-only is used")
    output = Path(args.output)
    header, salt = sqlcipher.read_header_and_salt(source)
    print(f"QQ NT header: version={header.version!r} hmac={header.hmac_algorithm!r}")
    _print_cipher(config)
    print(f"salt: {salt.hex()}")

    result = sqlcipher.decrypt_file(
        source, output, key, verify=not args.no_verify, progress=progress, config=config
    )
    stats = result.stats
    print(f"pages: {stats.good_pages:,} ok / {stats.total_pages:,} total")

    wal = source.with_name(source.name + "-wal")
    if wal.exists() and wal.stat().st_size and not args.no_wal:
        print(f"applying WAL {wal} ...")
        pages, db_size = sqlcipher.decrypt_wal(wal, result.keys, verify=not args.no_verify)
        if pages:
            sqlcipher.apply_wal(output, pages, db_size, page_size=result.config.page_size)
            print(f"  overlaid {len(pages):,} pages (db size {db_size} pages)")
        else:
            print("  no committed WAL frames found")

    if stats.sparse_zero_pages:
        print(f"sparse zero pages: {len(stats.sparse_zero_pages):,}")
    if stats.hmac_failures:
        print(f"HMAC failures (zeroed): {len(stats.hmac_failures):,}")

    if args.report:
        Path(args.report).write_text(json.dumps(result.report(), indent=2))
        print(f"report written to {args.report}")
    print(f"wrote {output}")
    return 0


def cmd_decrypt_dir(args) -> int:
    """解密目录中（某个账号的 ``nt_db``）的每个 QQ NT 数据库。"""
    source_dir = Path(args.source_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    key = _key_from_args(args)

    databases = sorted(source_dir.glob("*.db"))
    if not databases:
        print(f"no .db files in {source_dir}", file=sys.stderr)
        return 1

    failures = 0
    for db in databases:
        output = output_dir / db.name
        with open(db, "rb") as handle:
            magic = handle.read(16)
        if magic.startswith(sqlcipher.SQLITE_MAGIC):
            print(f"{db.name}: plain SQLite, copying")
            shutil.copyfile(db, output)
            continue
        if not magic.startswith(header_mod.MAGIC):
            print(f"{db.name}: unrecognised format, skipping")
            continue
        if db.stat().st_size <= header_mod.HEADER_SIZE:
            print(f"{db.name}: container header only, no data pages")
            continue

        config = _config_from_args(args) or sqlcipher.detect_config(db, key)
        if config is None:
            print(f"{db.name}: could not detect the cipher (wrong key or damage?)")
            failures += 1
            continue

        result = sqlcipher.decrypt_file(db, output, key, verify=not args.no_verify, config=config)
        stats = result.stats
        note = ""
        wal = db.with_name(db.name + "-wal")
        if wal.exists() and wal.stat().st_size and not args.no_wal:
            pages, db_size = sqlcipher.decrypt_wal(wal, result.keys, verify=not args.no_verify)
            if pages:
                sqlcipher.apply_wal(output, pages, db_size, page_size=config.page_size)
                note = f", +{len(pages):,} wal pages"
        print(
            f"{db.name}: {stats.good_pages:,}/{stats.total_pages:,} pages, "
            f"hmac={config.hmac_prf}{note}"
        )
        if stats.hmac_failures:
            failures += 1
    return 0 if not failures else 2


def cmd_info(args) -> int:
    with MessageDatabase(args.database) as db:
        print(f"database: {args.database}")
        tables = db.tables()
        print(f"tables: {len(tables)}")
        for table in tables:
            try:
                count = db.count(table)
            except Exception as exc:  # pragma: no cover - 损坏的表
                count = f"error: {exc}"
            print(f"  {table}: {count}")
        if args.columns:
            for table in db.message_tables():
                print(f"\ncolumns of {table}:")
                for number in db.columns(table):
                    print(f"  {number}: {column_name(number)}")
    return 0


def cmd_export(args) -> int:
    with MessageDatabase(args.database) as db:
        tables = args.table or db.message_tables()
        with contextlib.ExitStack() as stack:
            if args.output in (None, "-"):
                out = sys.stdout
            else:
                out = stack.enter_context(open(args.output, "w", encoding="utf-8"))
            for table in tables:
                if table not in db.tables():
                    print(f"skipping missing table {table}", file=sys.stderr)
                    continue
                print(f"exporting {table} ...", file=sys.stderr)
                for record in db.iter_messages(
                    table, where=args.where, limit=args.limit, order_by=args.order_by
                ):
                    out.write(
                        json.dumps(
                            record.to_dict(include_raw_columns=not args.no_raw),
                            ensure_ascii=False,
                        )
                    )
                    out.write("\n")
    return 0


def _print_fields(fields: list[protobuf.Field], indent: int = 0) -> None:
    pad = "  " * indent
    for fld in fields:
        name = elements_mod.FIELD_NAMES.get(fld.number, "")
        label = f"{fld.number}" + (f" ({name})" if name else "")
        if fld.message is not None:
            print(f"{pad}{label}: message")
            _print_fields(fld.message, indent + 1)
        elif fld.wire_type == protobuf.WIRE_LEN:
            text = protobuf.try_decode_utf8(fld.value)
            if text is not None:
                print(f"{pad}{label}: {text!r}")
            else:
                print(f"{pad}{label}: bytes({len(fld.value)}) {fld.value.hex()}")
        else:
            print(f"{pad}{label}: {fld.value}")


def cmd_dump(args) -> int:
    where = args.where
    if args.id is not None:
        where = f"[40001]={int(args.id)}"

    with MessageDatabase(args.database) as db:
        for record in db.iter_messages(args.table, where=where, limit=args.limit, decode=False):
            print("=" * 78)
            print(f"msg_id={record.msg_id} table={record.table} time={record.time_str}")
            for key, value in sorted(record.columns.items()):
                if isinstance(value, (bytes, bytearray)):
                    inner = unwrap_column(value, key)
                    print(f"--- column {key} ({column_name(key)}) ---")
                    if inner is None:
                        continue
                    try:
                        fields = protobuf.decode_tree(inner)
                    except protobuf.ProtobufError:
                        print(f"    bytes {bytes(value).hex()}")
                        continue
                    _print_fields(fields, 1)
    return 0


def _add_cipher_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--hmac",
        choices=("sha1", "sha256", "sha512"),
        help="覆盖页面 HMAC 算法（默认：自动检测）",
    )
    parser.add_argument("--page-size", type=int, help="覆盖页大小（默认：4096）")
    parser.add_argument(
        "--kdf-prf",
        choices=("sha1", "sha256", "sha512"),
        help="覆盖 KDF PRF（默认：自动检测）",
    )
    parser.add_argument("--kdf-iter", type=int, help="覆盖 KDF 迭代次数（默认：4000）")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ntqq",
        description="读取 QQ NT（nt_msg.db）数据库：解密、查看、导出。",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_header = sub.add_parser("header", help="显示 QQ 容器头")
    p_header.add_argument("database")
    p_header.set_defaults(func=cmd_header)

    p_dec = sub.add_parser("decrypt", help="解密加密的 QQ NT 数据库")
    p_dec.add_argument("source")
    p_dec.add_argument("output", nargs="?", help="明文 SQLite 输出（使用 --verify-only 时不需要）")
    p_dec.add_argument("--key", help="口令（或设置 $NTQQ_DB_KEY）")
    p_dec.add_argument("--key-hex", help="以十六进制表示的原始密钥（用于 x'...' 密钥）")
    p_dec.add_argument("--no-verify", action="store_true", help="跳过 HMAC 校验")
    p_dec.add_argument("--no-wal", action="store_true", help="不应用 -wal 文件")
    p_dec.add_argument("--report", help="将 JSON 报告写入该路径")
    _add_cipher_args(p_dec)
    p_dec.add_argument(
        "--verify-only",
        action="store_true",
        help="仅校验页面 HMAC（检查密钥是否正确），不写入任何内容",
    )
    p_dec.set_defaults(func=cmd_decrypt)

    p_dir = sub.add_parser("decrypt-dir", help="解密某账号 nt_db 目录下的每个数据库")
    p_dir.add_argument("source_dir", help="包含加密 *.db 文件的目录")
    p_dir.add_argument("output_dir", help="写入明文数据库的目录")
    p_dir.add_argument("--key", help="口令（或设置 $NTQQ_DB_KEY）")
    p_dir.add_argument("--key-hex", help="以十六进制表示的原始密钥（用于 x'...' 密钥）")
    p_dir.add_argument("--no-verify", action="store_true", help="跳过 HMAC 校验")
    p_dir.add_argument("--no-wal", action="store_true", help="不应用 -wal 文件")
    _add_cipher_args(p_dir)
    p_dir.set_defaults(func=cmd_decrypt_dir)

    p_info = sub.add_parser("info", help="列出表及行数")
    p_info.add_argument("database")
    p_info.add_argument("--columns", action="store_true", help="同时打印列名")
    p_info.set_defaults(func=cmd_info)

    p_exp = sub.add_parser("export", help="将消息导出为 JSON Lines")
    p_exp.add_argument("database")
    p_exp.add_argument("--table", action="append", help="要导出的表（可重复指定）")
    p_exp.add_argument("-o", "--output", help="输出文件（默认标准输出）")
    p_exp.add_argument("--where", help="SQL WHERE 子句")
    p_exp.add_argument("--limit", type=int, help="每张表的最大行数")
    p_exp.add_argument("--order-by", help="SQL ORDER BY 子句")
    p_exp.add_argument("--no-raw", action="store_true", help="省略原始列")
    p_exp.set_defaults(func=cmd_export)

    p_dump = sub.add_parser("dump", help="美化打印消息 protobuf")
    p_dump.add_argument("database")
    p_dump.add_argument("--table", default="group_msg_table")
    p_dump.add_argument("--id", help="消息 id（第 40001 列）")
    p_dump.add_argument("--where", help="SQL WHERE 子句")
    p_dump.add_argument("--limit", type=int, default=1)
    p_dump.set_defaults(func=cmd_dump)

    _add_library_commands(sub)

    return parser


# ---------------------------------------------------------------------------
# 库命令（ntqq.world）：群、好友、会话、历史消息、检索……
# ---------------------------------------------------------------------------


def _open_library(args):
    from .world import QQNT

    key = getattr(args, "key", None) or os.environ.get("NTQQ_DB_KEY")
    return QQNT.open(args.source, key=key, cache=getattr(args, "cache", None))


def cmd_groups(args) -> int:
    with _open_library(args) as qq:
        groups = qq.groups()
        if args.json:
            print(json.dumps([g.to_dict() for g in groups], ensure_ascii=False, indent=2))
            return 0
        print(f"{len(groups)} groups")
        for group in groups:
            mark = " " if args.all else ("*" if _last_message_time(qq, group) else " ")
            print(
                f"{mark} {group.uin:>12}  {group.name or '':<32} "
                f"members={group.member_count or 0:<6} created={group.create_time_str}"
            )
    return 0


def cmd_friends(args) -> int:
    with _open_library(args) as qq:
        friends = qq.friends()
        if args.json:
            print(json.dumps([f.to_dict() for f in friends], ensure_ascii=False, indent=2))
            return 0
        print(f"{len(friends)} friends")
        for friend in friends:
            print(f"  {friend.uin:>12}  {friend.display_name:<28} {(friend.signature or '')[:40]}")
    return 0


def cmd_chats(args) -> int:
    """最近的会话，最新的在前。"""
    with _open_library(args) as qq:
        table = qq.manager.tables.get("recent_contact_v3_table")
        if table is None:
            print("recent_contact_v3_table not present", file=sys.stderr)
            return 1
        rows = table.query().order_by("-msg_time").limit(args.limit).all()
        out = []
        for row in rows:
            chat = qq.contact(row.peer)
            name = row.chat_name or (chat.display_name if chat else None) or row.peer or "?"
            out.append(
                {
                    "peer": row.peer,
                    "name": name,
                    "kind": chat.kind if chat else "unknown",
                    "chat_type": row.chat_type,
                    "msg_time": row.msg_time,
                    "sender": row.sender_card or row.sender_name or "",
                    "text": _preview(row.preview),
                }
            )
        if args.json:
            print(json.dumps(out, ensure_ascii=False, indent=2))
            return 0
        for item in out:
            sender = f" {item['sender']}:" if item["sender"] else ""
            print(f"  {item['msg_time']:>12}  {item['name']:<28} {sender} {item['text'][:40]}")
    return 0


def cmd_history(args) -> int:
    with _open_library(args) as qq:
        chat = qq.contact(args.chat)
        if chat is None:
            print(f"unknown chat {args.chat!r}", file=sys.stderr)
            return 1
        messages = qq.history(
            chat, limit=args.limit, since=args.since, until=args.until, order=args.order
        )
        if args.json:
            for message in messages:
                print(json.dumps(message.to_dict(), ensure_ascii=False))
            return 0
        for message in messages:
            print(f"[{message.time_str}] {message.display_sender}: {message.text}")
    return 0


def cmd_search(args) -> int:
    with _open_library(args) as qq:
        hits = qq.search(
            args.keyword,
            chat=args.chat,
            scope=args.scope,
            since=args.since,
            until=args.until,
            sender=args.sender,
            kinds=args.kind,
            limit=args.limit,
        )
        if args.json:
            for message in hits:
                print(json.dumps(message.to_dict(), ensure_ascii=False))
        else:
            for message in hits:
                print(f"[{message.time_str}] {message.display_sender}: {message.text}")
        print(f"-- {len(hits)} hit(s)", file=sys.stderr)
    return 0


def cmd_export_chat(args) -> int:
    from . import export as exporters

    with _open_library(args) as qq:
        chat = qq.contact(args.chat)
        if chat is None:
            print(f"unknown chat {args.chat!r}", file=sys.stderr)
            return 1
        messages = qq.history(chat, limit=args.limit, since=args.since, until=args.until)
        title = args.title or chat.display_name
        output = args.output
        if args.format == "html":
            count = qq.export_html(messages, output, title=title)
        elif args.format == "markdown":
            count = exporters.export_markdown(messages, output, title)
        elif args.format == "csv":
            count = exporters.export_csv(messages, output)
        else:
            count = exporters.export_jsonl(messages, output, raw=args.raw)
        print(f"wrote {count} messages to {output}")
    return 0


def cmd_stats(args) -> int:
    with _open_library(args) as qq:
        stats = qq.stats()
        print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


def cmd_scan(args) -> int:
    """逐行解析整库：既给出统计，也验证代码对每条数据都可用。"""

    with _open_library(args) as qq:

        def progress(table: str, count: int) -> None:
            print(f"  {table}: 已处理 {count:,} 行", file=sys.stderr)

        report = qq.scan(
            limit=args.limit,
            samples=args.samples,
            dump=args.dump,
            progress=None if args.json else progress,
        )
        if args.dump:
            print(f"每条解析结果已写入 {args.dump}", file=sys.stderr)
        if args.json:
            print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        else:
            print(report.summary())
        return 0 if report.ok else 1


def _last_message_time(qq, group) -> int:
    table = qq.manager.tables.get("group_msg_table")
    if table is None or group.uin is None:
        return 0
    row = table.connection.execute(
        'SELECT max("40050") FROM group_msg_table NOT INDEXED WHERE "40027" = ?',
        (group.uin,),
    ).fetchone()
    return int(row[0]) if row and row[0] else 0


def _preview(blob) -> str:
    from .message import Message

    if not isinstance(blob, (bytes, bytearray)) or not blob:
        return ""
    try:
        placeholder = type("Row", (), {"values": {40051: bytes(blob)}})()
        return Message.from_row(placeholder, body_field=40051).text
    except Exception:
        return ""


def _add_library_commands(sub) -> None:
    def source_arg(parser):
        parser.add_argument("source", help="QQ 配置目录或已解密数据库所在目录")
        parser.add_argument("--key", help="数据库口令（或设置 $NTQQ_DB_KEY）")
        parser.add_argument("--cache", help="存放解密副本的目录")

    p = sub.add_parser("groups", help="列出群及其名称和成员数")
    source_arg(p)
    p.add_argument("--json", action="store_true")
    p.add_argument("--all", action="store_true", help="不标记含有消息的群")
    p.set_defaults(func=cmd_groups)

    p = sub.add_parser("friends", help="列出好友")
    source_arg(p)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_friends)

    p = sub.add_parser("chats", help="最近的会话，最新的在前")
    source_arg(p)
    p.add_argument("--limit", type=int, default=30)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_chats)

    p = sub.add_parser("history", help="打印某个会话的消息")
    source_arg(p)
    p.add_argument("chat", help="群 uin、好友 uin/uid 或名称片段")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--since", help="例如 2025-09-01")
    p.add_argument("--until", help="例如 2025-09-30")
    p.add_argument("--order", choices=("asc", "desc"), default="asc")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_history)

    p = sub.add_parser("search", help="检索消息体")
    source_arg(p)
    p.add_argument("keyword")
    p.add_argument("--chat", help="限定到单个会话（uin/uid/名称片段）")
    p.add_argument(
        "--scope", choices=("group", "c2c", "dataline", "discuss", "temp", "service", "ai")
    )
    p.add_argument("--since")
    p.add_argument("--until")
    p.add_argument("--sender", help="uin、uid 或名称片段")
    p.add_argument("--kind", action="append", help="元素类型，例如 --kind text")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("export-chat", help="将单个会话导出为 html/markdown/csv/jsonl")
    source_arg(p)
    p.add_argument("chat")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--format", choices=("html", "markdown", "csv", "jsonl"), default="html")
    p.add_argument("--limit", type=int, default=100000)
    p.add_argument("--since")
    p.add_argument("--until")
    p.add_argument("--title")
    p.add_argument("--raw", action="store_true", help="jsonl：包含原始列")
    p.set_defaults(func=cmd_export_chat)

    p = sub.add_parser("stats", help="每张已映射表的行数")
    source_arg(p)
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("scan", help="逐行解析整库：统计 + 验证每条数据都能解析")
    source_arg(p)
    p.add_argument("--limit", type=int, help="每张表最多处理的行数（默认全量）")
    p.add_argument("--samples", type=int, default=3, help="报告中附带的样例条数")
    p.add_argument("--dump", help="把每条解析结果以 JSON Lines 写入该文件")
    p.add_argument("--json", action="store_true", help="以 JSON 输出报告")
    p.set_defaults(func=cmd_scan)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
