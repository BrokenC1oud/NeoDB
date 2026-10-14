# 用 Python 查询 QQ NT 数据库

`ntqq` 附带一个无依赖的库，用于**查找、解析和导出**解密后数据库中的内容。它以参考项目 `nt_msg.py` 为蓝本（面向 QQ 数字列的 ORM、每种消息元素类型对应一个解码器、一个聊天记录导出器），但仅使用标准库，并且可以直接作用于*加密的*账号配置。

| 模块 | 用途 |
|:--|:--|
| `ntqq.orm` | 微型 ORM：`Model`、`Table`、`Query`、`DatabaseManager` |
| `ntqq.schema` | 消息 / 群 / 资料 / 表情表的具名列映射 |
| `ntqq.message` | 类型化元素（`Text`、`Image`、`Reply`、…）与 `Message` |
| `ntqq.world` | 门面：`QQNT`、`Group`、`Friend`、`Contact`、搜索、历史 |
| `ntqq.export` | JSONL / CSV / Markdown / HTML 写入器 |

## 快速开始

```python
from ntqq import QQNT

# A profile directory (encrypted) or a directory of decrypted databases.
qq = QQNT.open("~/.config/QQ/nt_qq_<profile>", key="<passphrase>")
# or: QQNT.open("work/plain")

for group in qq.groups():
    print(group.uin, group.name, group.member_count, group.create_time_str)

chat = qq.group(1145141919810)            # or qq.contact("名字片段") / qq.friend(123)
for message in qq.history(chat, limit=50):
    print(message.time_str, message.display_sender, message.text)

for message in qq.search("关键词", chat=chat, since="2025-09-01", until="2025-09-30"):
    print("[命中]", message)

qq.export_html(chat, "group.html", limit=10_000)
qq.close()
```

`QQNT.open` 可以接受一个加密的账号配置（它会解密并把 WAL 应用到 `~/.cache/ntqq-py/<profile-hash>`，同时修复 QQ 损坏的索引），也可以接受一个已经解密好的目录。

## 浏览联系人

```python
qq.groups()          # [Group(uin, name, remark, member_count, create_time, bulletin, owner_uid)]
qq.friends()         # [Friend(uin, uid, nickname, remark, signature, category)]
qq.contact(1145141919810)      # by uin
qq.contact("u_xxxxxxxx")   # by uid
qq.contact("操作系统")      # by name / remark fragment
qq.members(group)    # [{'uid','uin','nickname','card','admin','level',...}]
```

备注名通过 `nt_uid_mapping_table`、`profile_info_v6` 和 `buddy_list` 解析；`contact.uin_of(uid)` / `uid_of(uin)` / `name_of(...)` 直接暴露这些映射。

## 消息与元素

`Message` 同时携带解码后的元素和原始列：

```python
m = next(iter(qq.messages(chat=chat)))
m.id, m.seq, m.time, m.time_str, m.type_name, m.text
m.display_sender          # group card, then nickname, then uin
m.elements                # [Text('你好')], [Image(filename=..., width=...)], ...
m.element("reply").quoted # the quoted Message, if this is a reply
m.columns[40800]          # the untouched protobuf body (nothing is lost)
m.to_dict(raw=True)       # JSON-ready, raw columns as hex
```

元素种类：`text`、`image`、`file`、`voice`、`video`、`face`、`reply`、`poke`、`gift`、`share`、`ark`、`markdown`、`forward`、`bot_markdown`、`call`、`menu`、`unsupported`。每种元素的 `raw` 都保留完整原始字段；`unsupported` 表示该类型尚无专用解码器（仍会尽量取出可读文本），`menu` 是内嵌按钮菜单（类型 43）。

### 判断元素是否为文本、取它的内容

元素是带类型的：`Element.kind` 就是类型字符串（`element.type_name` 是它的
别名）。文本元素为 `kind == "text"`，内容在 `content`：

```python
m.type_name                       # 首个元素的类型；"empty" 表示没有消息体
for element in m.elements:
    if element.kind == "text":
        print(element.content)    # 纯文本；str(element) 等价
m.text                            # 全部元素拼接（图片等为 "[图片]" 这类占位符）
m.element("text")                 # 第一个文本元素，没有则 None
```

一条消息可能由多段组成（正文 + 图片 + 引用…），`Message.elements` 已经包含**全部**
段；被引用的消息在 `m.quote.quoted.elements`。若想收集"所有可读文本"（例如做词云），
除了 `kind == "text"` 还可取图片摘要（`Image.summary`）、文件名（`File.filename`）、
红包/卡片文字（`Gift.title`、`Share.title`、`Ark.summary`）等。

### 去掉 @ 提及

@ 提及在 `content` 里是**纯文本**（`"@昵称"`，没有位置标记），目标只记在
`at_uins`/`at_uids` 中，`at_type` 则标明性质：`2` = @某人、`1` = @全体成员、
`0` 或缺失 = 没有提及（此时文本里的 `@` 是发言人手打的，不应删除）。

```python
element.at_type        # 2 / 1 / 0 / None
element.mentions       # 是否真的 @ 了谁（@某人 或 @全体成员）
element.plain()        # 去掉 @ 提及；不含空格的昵称由正则处理
names = qq.member_names(group)     # {uid|uin: 群名片或昵称}
element.plain(names)               # 含空格的昵称也能精确去除
```

昵称在文本里是**发送当时**的样子，而 `member_names()` 给的是当前值，成员改名或
退群时匹配不到会退化为按空白切分的近似删除（例如 `"@Patchouli alcohol"` 只去掉
`"@Patchouli"`）。

传入映射时会**只按本次 @ 的目标**（`at_uids`/`at_uins`）查名字，所以不会被同群
更短或同名的其他成员截断：目标把昵称从 `"某某某（备注）"` 改成 `"某某某（新名）"`
后，即使群里还有一位叫 `"某"` 的成员，也不会错误地删成 `"某某（备注）"`；
匹配不到目标当前名时整段提及由兜底正则删掉。

为新类型 id 注册一个解码器只需一次调用：

```python
from ntqq.message import Element, register

@register(23)
def decode(fields):
    return Element(raw=fields)
```

## 搜索

```python
qq.search(
    "关键词",
    chat=None,          # Contact | uin | uid | name fragment
    scope=None,         # 'group' | 'c2c' | 'dataline' | 'discuss' | 'temp' | 'service' | 'ai'
    since=None,         # datetime | date | '2025-09-01' | '2025-09' | epoch
    until=None,         # date-only values mean the whole day
    sender=None,        # uin, uid or name fragment
    kinds=None,         # ['text', 'image', ...]
    limit=None,
    case_sensitive=False,
)
```

搜索在解码前先对原始 protobuf 运行廉价的字节级预过滤，因此扫描整个五百多万条消息的数据库仍然可行；按会话、发送者和时间进行的 SQL 预过滤会进一步缩小范围。

## 全库校验与导出每一条

`scan()` 会逐表、逐行读取整个数据库，并对每条消息做完整解析，返回
:class:`ScanReport`。它既给出统计，也是"代码对每一条数据都可用"的验证：

```python
report = qq.scan()                       # 全量（约 11100 条/秒）
report = qq.scan(limit=20000)            # 每表抽样
report = qq.scan(dump="all.jsonl")       # 顺便把每一条写成 JSON Lines

print(report.summary())                  # 中文报告：行数、元素分布、时间范围、样例
print(report.ok, report.failures_total, report.table_failures)
report.to_dict()                         # 结构化报告，便于二次处理
```

报告字段的含义：

| 字段 | 含义 |
|:--|:--|
| `tables` / `rows` | 每张表读到的行数、总行数 |
| `decoded` / `empty_bodies` | 成功解析的消息数、其中不含消息体的（删除/系统行） |
| `kinds` | 元素类型分布 |
| `unsupported_types` | **未支持**的元素类型（走兜底渲染，原始字段仍在 `raw`），属数据现状 |
| `decoder_errors` | **解码器抛错**（代码 bug），非空即 `report.ok == False` |
| `table_failures` | 整张表读不出来（如模型列号与真实表完全不匹配），不中断其余表 |
| `failures` | 单行解析失败明细（默认最多留 200 条，`failures_total` 记总数） |
| `missing_columns` | 该表缺少哪些映射列（QQ 版本差异，属正常） |

`strict=True` 时首个错误立即抛出。`ok` 为真要求：没有坏行、没有读表失败、
没有解码器抛错。

对应的命令行：

```bash
python -m ntqq scan work/plain --limit 20000        # 抽样扫描
python -m ntqq scan work/plain --dump all.jsonl     # 导出每一条解析结果
python -m ntqq scan work/plain --json               # 输出 JSON 报告
```

仓库里的 `tests/test_full_scan.py` 就是基于同一实现的端到端测试。

## 原始 ORM 访问

对于门面未覆盖的任何内容，ORM 都会以具名的数字列暴露每一张已映射的表：

```python
from ntqq import DatabaseManager

db = DatabaseManager("work/plain")
db.group_messages.filter(peer_uin=1145141919810).count()
db.group_messages.filter(peer_uin=1145141919810, msg_time=[...]).order_by("-msg_time").limit(10)
db.group_messages.contains("sender_name", "猫").between("msg_time", a, b).all()
db.groups.all()                     # group_list
db.uid_mapping.all()                # nt_uid_mapping_table
db.table("group_member3").filter(group_uin=1145141919810).all()
db.nt_msg.connection.execute(...)   # raw sqlite3 connection
```

缺失的列会被检测到并跳过，因此同一个模型在增删字段的不同 QQ 版本之间仍可正常工作。

## 导出

```python
from ntqq import export

export.export_jsonl(messages, "chat.jsonl", raw=False)
export.export_csv(messages, "chat.csv")
export.export_markdown(messages, "chat.md", title="测试群")
export.export_html(messages, "chat.html", title="测试群")   # self-contained page
```

## 命令行

以上全部功能无需编写代码即可使用：

```bash
export NTQQ_DB_KEY='<passphrase>'

python -m ntqq groups   ~/.config/QQ/nt_qq_<profile>          # names + member counts
python -m ntqq friends  ~/.config/QQ/nt_qq_<profile>
python -m ntqq chats    ~/.config/QQ/nt_qq_<profile> --limit 30
python -m ntqq history  ~/.config/QQ/nt_qq_<profile> 1145141919810 --limit 50
python -m ntqq search   ~/.config/QQ/nt_qq_<profile> "关键词" --chat 1145141919810
python -m ntqq export-chat ~/.config/QQ/nt_qq_<profile> 1145141919810 -o chat.html
python -m ntqq stats    ~/.config/QQ/nt_qq_<profile>
```

（`groups`/`friends`/`history`/… 也接受一个已解密数据库的目录，例如 `work/plain`。）

## 修复解密后的数据库

原生 SQLite 在刚解密出的 `nt_msg.db` 上会报告 `database disk image is malformed`，因为 QQ 留下了一处索引 b-tree 不一致（见主 README）。该库会就地修复它——先 `REINDEX`，否则 `DROP INDEX`，再否则移除索引行——而不触碰任何行数据：

```python
from ntqq import repair_file
repair_file("work/plain/nt_msg.db")
```

`QQNT.open` 会对它解密的数据库自动执行此操作。
