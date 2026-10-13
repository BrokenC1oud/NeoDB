"""将会话历史消息导出为 JSONL、CSV、Markdown 和 HTML。

HTML 写出器会生成一个自包含的“聊天记录”页面，风格参照参考项目的
``template/``（按天分隔、引用回复、代码使用等宽字体），但不依赖任何模板引擎。
"""

from __future__ import annotations

import contextlib
import csv
import html
import io
import json
from collections.abc import Iterable
from pathlib import Path
from typing import TextIO

from .message import Message

_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{title}</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ margin: 0; background: #f4f4f5; font: 14px/1.55 -apple-system, "Segoe UI", "Noto Sans CJK SC", sans-serif; }}
.page {{ max-width: 900px; margin: 0 auto; background: #fff; min-height: 100vh; }}
header {{ position: sticky; top: 0; z-index: 2; background: #5288c1; color: #fff; padding: 14px 18px; font-weight: 600; }}
.day {{ text-align: center; margin: 18px 0 10px; }}
.day span {{ background: rgba(0,0,0,.06); border-radius: 12px; padding: 3px 12px; font-size: 12px; color: #666; }}
.msg {{ display: flex; gap: 10px; padding: 6px 18px; }}
.msg.consecutive {{ margin-top: -10px; }}
.who {{ width: 110px; flex: none; text-align: right; color: #5288c1; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
.who .t {{ display: block; color: #9aa0a6; font-weight: 400; font-size: 11px; }}
.body {{ flex: 1; min-width: 0; }}
.quote {{ border-left: 3px solid #5288c1; background: rgba(82,136,193,.08); margin: 2px 0 4px; padding: 3px 8px; font-size: 12px; color: #555; border-radius: 0 6px 6px 0; }}
.text {{ white-space: pre-wrap; word-wrap: break-word; }}
.media {{ color: #0b7285; }}
.meta {{ color: #9aa0a6; font-size: 11px; margin-left: 8px; }}
code {{ background: rgba(0,0,0,.06); border-radius: 4px; padding: 1px 4px; font-family: ui-monospace, monospace; }}
</style>
</head>
<body>
<div class="page">
<header>{title}</header>
{messages}
</div>
</body>
</html>
"""


def _media_tag(text: str, kind: str) -> str:
    if kind in ("image", "video", "voice", "file") or text.startswith("["):
        return f'<span class="media">{html.escape(text)}</span>'
    return html.escape(text).replace("\n", "<br/>")


def export_jsonl(
    messages: Iterable[Message], target: str | Path | TextIO, *, raw: bool = False
) -> int:
    """每行写入一个 JSON 对象；返回消息条数。"""
    count = 0
    with contextlib.ExitStack() as stack:
        if isinstance(target, (str, Path)):
            handle = stack.enter_context(open(target, "w", encoding="utf-8"))
        else:
            handle = target
        for message in messages:
            handle.write(json.dumps(message.to_dict(raw=raw), ensure_ascii=False))
            handle.write("\n")
            count += 1
    return count


def export_csv(messages: Iterable[Message], target: str | Path) -> int:
    """写入扁平化的 CSV（时间、发送者、类型、文本、id）。"""
    count = 0
    with open(target, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["time", "datetime", "sender", "uid", "uin", "type", "text", "id", "seq"])
        for message in messages:
            writer.writerow(
                [
                    message.time,
                    message.time_str,
                    message.display_sender,
                    message.sender_uid,
                    message.sender_uin,
                    message.type_name,
                    message.text,
                    message.id,
                    message.seq,
                ]
            )
            count += 1
    return count


def export_markdown(
    messages: Iterable[Message], target: str | Path, title: str = "聊天记录"
) -> int:
    """写入易读的 Markdown 记录。"""
    count = 0
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(f"# {title}\n\n")
        last_day = None
        for message in messages:
            day = message.time_str[:10]
            if day != last_day:
                handle.write(f"\n## {day}\n\n")
                last_day = day
            quote = message.quote
            if quote and quote.quoted:
                handle.write(f"> 回复 {quote.quoted.display_sender}: {quote.quoted.text}\n\n")
            stamp = message.time_str[11:16]
            handle.write(f"- `{stamp}` **{message.display_sender}**: {message.text}\n")
            count += 1
    return count


def export_html(
    messages: Iterable[Message], target: str | Path, *, title: str = "聊天记录", title_of=None
) -> int:
    """写入自包含的 HTML 聊天记录。"""
    out = io.StringIO()
    count = 0
    last_day = None
    last_sender = None
    for message in messages:
        day = message.time_str[:10]
        if day and day != last_day:
            out.write(f'<div class="day"><span>{html.escape(day)}</span></div>\n')
            last_day = day
            last_sender = None
        sender = message.display_sender or "?"
        consecutive = " consecutive" if sender == last_sender else ""
        last_sender = sender
        stamp = message.time_str[11:16]
        who = html.escape(sender)
        headline = title_of(sender) if title_of else None
        if headline and headline != sender:
            who = f'{html.escape(headline)}<span class="t">{html.escape(sender)}</span>'
        out.write(f'<div class="msg{consecutive}">')
        out.write(f'<div class="who">{who}</div>')
        out.write('<div class="body">')
        quote = message.quote
        if quote and quote.quoted:
            out.write(
                f'<div class="quote">{html.escape(quote.quoted.display_sender)}: '
                f"{html.escape(quote.quoted.text)}</div>"
            )
        kind = message.elements[0].kind if message.elements else "text"
        out.write(
            f'<div class="text">{_media_tag(message.text, kind)}'
            f'<span class="meta">{stamp}</span></div>'
        )
        out.write("</div></div>\n")
        count += 1
    page = _TEMPLATE.format(title=html.escape(title), messages=out.getvalue())
    Path(target).write_text(page, encoding="utf-8")
    return count
