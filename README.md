# 聊天软件数据库工具包（洁净室）

> [!WARNING]
> VIBE-CODED by deepseek

本仓库中的全部内容，均通过阅读 聊天软件 自身的二进制文件，并借助 `gdb` 对运行中的进程进行分析而得出——未使用任何第三方文档或现有的解密工具。它负责解密并解析 Linux 客户端保存在 `~/.config/QQ/nt_qq_<profile>/nt_db/` 下的数据库。

```
ntqq/                     整套流程的 Python 实现
  header.py                1024 字节 QQ 容器头
  sqlcipher.py             SQLCipher 页解密 + HMAC 自动探测
  protobuf.py              通用、无损的 protobuf 线格式解码器
  elements.py              消息元素语义（文本/图片/文件/...）
  reader.py                已解密数据库的底层访问
  orm.py                   针对 QQ 数字列的微型 ORM
  schema.py                具名列映射（消息、群、资料、表情）
  message.py               有类型的元素 + Message
  world.py                 QQNT 门面：联系人、历史、检索
  export.py                JSONL / CSV / Markdown / HTML 写出器
  cli.py                   python -m ntqq <命令>
tools/get_db_key.py       从运行中的 QQ 进程恢复数据库密钥（gdb）
tools/recovered_keys.*    恢复出的密钥存放位置（真实文件已被 gitignore）
jdbc/                     DataGrip 用的 JDBC 驱动（见 jdbc/README.md）
examples/                 可运行的库与导出示例
tests/                    离线单元测试（无需真实配置目录）
docs/library.md           查询 / 解析 / 导出库指南
work/                     已解密数据库（生成物，已被 gitignore）
```

## 环境要求

* Python 3.10+ 以及 [`cryptography`](https://pypi.org/project/cryptography/)
  （`pip install cryptography`），用于 AES-256-CBC 后端。
* 可选：`gdb`（用于恢复密钥），`sqlite3`（用于临时检查）。

无需 protobuf 运行时——解码器完全自包含。

## 1. 存储布局

聊天软件 将 SQLite 克隆为 *WCDB*，并用 SQLCipher 加密每一个数据库。一个数据库文件的结构为

```
+---------------------------+------------------------------------------+
| 1024 字节容器头           | SQLCipher 数据库（页大小 4096）          |
+---------------------------+------------------------------------------+
  偏移 0                       偏移 1024
```

### 容器头（明文，1024 字节）

`nt_msg.db` 的实测布局：

| 偏移   | 大小 | 含义                                                 |
|-------:|-----:|:-----------------------------------------------------|
| 0x000  | 16   | 魔数 `SQLite header 3\0`（伪装成 SQLite 的魔数）      |
| 0x010  | 16   | 标志 — `04 00 10 00 00 …`                            |
| 0x020  | 8    | 标记 `QQ_NT DB`                                      |
| 0x028  | 4    | 后随 protobuf 的小端长度                             |
| 0x02c  | …    | protobuf：字段 2 = 128 个十六进制字符（64 字节 `rand`）， |
|        |      | 字段 3 = 格式版本 `1.1.0.1`，                        |
|        |      | 字段 4 = HMAC 算法 `HMAC_SHA1`                       |

开头 16 字节刻意做得像 SQLite 头部，但其实*并不是*：真正的 SQLite 头部位于加密后的第 1 页内部（见下文）。

### SQLCipher 参数

所有数据库的密钥派生方式完全相同，只有 **页 HMAC 算法**不同。容器头中的 `HMAC_SHA1` 字符串只是一个提示：大多数数据库确实使用 HMAC-SHA1，但 `guild1.db` 使用 HMAC-SHA512，且用的是**同一个账号密钥**。

| 参数             | 值                                                        |
|:-----------------|:----------------------------------------------------------|
| 加密算法          | AES-256-CBC                                               |
| KDF              | PBKDF2-HMAC-SHA512，**4000** 次迭代，32 字节密钥          |
| salt             | 位于文件偏移 **1024** 处的 16 字节                        |
| 页大小            | 4096                                                      |
| 页 HMAC          | HMAC-**SHA1**（20 字节）或 HMAC-**SHA512**（64 字节）     |
| 页保留区（reserve）| 48 字节（SHA1）或 80 字节（SHA512）                       |

保留区（reserve）为 IV（16 字节）加上 HMAC 摘要，并向上取整到 16 的倍数（`16 + 20 = 36 -> 48`；`16 + 64 = 80`）。`ntqq.sqlcipher.detect_config` 通过校验前几页的 HMAC 来恢复真实算法，因此无需手工调整。

单页布局（页号 `pgno`，从 1 开始，`R` = 保留区（reserve））：

```
0    16（仅第 1 页）  page_size-R    +16      +hmac_size   page_size
+----+------------------+-----------+-----------+------------+
|salt| 加密内容         | IV（16）  | HMAC      | 填充       |
+----+------------------+-----------+-----------+------------+
```

* 第 1 页：16 字节 salt 占据该页的前 16 字节；此处的明文始终是 SQLite 魔数 `SQLite format 3\0`，解密器会将其还原。内容 = `page[16 : page_size-R]`。
* 其他页：内容 = `page[0 : page_size-R]`。
* 加密密钥：`PBKDF2-HMAC-SHA512(key, salt, 4000, 32)`
* HMAC 密钥：`PBKDF2-HMAC-SHA512(enc_key, salt XOR 0x3a, 2, 32)`
* HMAC 输入：`content || IV || little-endian u32 pgno`，与存储的摘要相比较。

在测试所用的账号配置中，每个加密数据库的每一页都通过了该 HMAC 校验，因此上述格式是精确无误的。

### `-first.material` / `-last.material`

每个数据库都伴随两个 16 KiB 的附属文件。它们是*第 1–4 页的加密快照*，使用相同的页格式和相同的 salt：

* `X.db-first.material` — 数据库创建时这四页的样子；
* `X.db-last.material`  — 最近一次写入时这四页的样子。

它们解密后均为有效页，并与主文件的第 1–4 页相互校验通过。

### 写前日志（WAL）

`X.db-wal` 文件使用相同的页加密。每个已提交的帧都用相同的 HMAC 校验通过（帧的页号用作 `pgno`）。CLI 会将已提交的帧叠加到解密后的主数据库之上。

## 2. 密钥

* 每个数据库都使用**同一个 16 字节账号密钥**（在测试所用的客户端上为 16 个可打印 ASCII 字节）。恢复出的密钥保存在本地的 `tools/recovered_keys.json` 中，该文件已被 gitignore——切勿提交。文件格式参见 `tools/recovered_keys.example.json`。
* 该密钥在登录时向服务器请求（`kNTCmdGetDbKey`），并通过 `wrapper.node` 中的 `nt_sqlite3_key_v2(sqlite3 *db, const void *key, int key_len)` 交给内嵌的 SQLCipher。它绝不会以明文形式写入磁盘。
* `guild1.db`（QQ 频道）使用**同一个账号密钥**，但用 HMAC-SHA512（保留区（reserve）80）校验页面；其头部中的 `HMAC_SHA1` 字段已过时。HMAC 自动检测会处理它。
* `bc_09.db` **完全未加密**——它是一个普通的 SQLite 数据库（`beacon_events`）。
* `global/nt_db/login.db` 使用**相同的文件格式和加密算法**，但用的是*不同的*密钥——在测试所用的客户端上为 20 字节（由同一个工具恢复）。其头部的 `rand` 字面值就是 `ABCDEFG`。工具包像处理其他数据库一样解密它：

  ```bash
  python3 -m ntqq decrypt ~/.config/QQ/global/nt_db/login.db login.plain.db \
      --key '<login key>'
  ```

`tools/get_db_key.py` 在 `gdb` 下恢复密钥：

```bash
python3 tools/get_db_key.py              # launches QQ under gdb
export NTQQ_DB_KEY='<the key>'
```

该工具以静态方式定位密钥函数（参见 `--static-only`），在 `gdb` 下启动 QQ，记录交给密钥函数以及 SQLCipher 的 `set_pass` 的每一个数据块，然后用 `detect_config` 针对真实数据库*验证*每个候选值。正是这种验证把账号密钥与 QQ 传递的其他 token 区分开来（例如某个 20 字节的、按数据库区分的值，它解密不了任何东西）。`--timeout` 控制监视进程的时长。

## 3. 数据模型

这些表是 WCDB 表，其**列名就是协议字段号**，例如

```sql
CREATE TABLE group_msg_table([40001] INTEGER PRIMARY KEY,[40002] INTEGER, …,
                             [40800] BLOB, [40900] BLOB, …);
```

消息表（列布局完全相同）：

| 表                           | 内容                              |
|:-----------------------------|:----------------------------------|
| `c2c_msg_table`              | 一对一聊天                        |
| `group_msg_table`            | 群聊                              |
| `discuss_msg_table`          | 讨论组                            |
| `dataline_msg_table`         | “我的设备”/数据线                 |
| `c2c_temp_msg_table`         | 临时（陌生人）会话                |
| `service_assistant_msg_table`| 服务号聊天                        |
| `ai_assistant_msg_table`     | AI 助手                           |

关键列（已针对真实数据行验证）：

| 列     | 含义                                     |
|-------:|:-----------------------------------------|
| 40001  | 消息 id（主键，= 消息体 45001）          |
| 40002  | 消息序号                                 |
| 40003  | 每个会话内的计数器                       |
| 40010  | 聊天类型（2 = 群）                       |
| 40020  | 发送者 uid（`u_…`）                      |
| 40021  | 对端 uid（字符串）                       |
| 40027  | 对端/群 uin                              |
| 40030  | 对端 uin（副本）                         |
| 40033  | 发送者 uin                               |
| 40050  | 时间戳（Unix 秒）                        |
| 40058  | 服务器时间戳                             |
| 40090  | 发送者显示名                             |
| 40093  | 发送者群名片                             |
| 40800  | 消息体（protobuf，见下文）               |
| 40600 / 40801 / 40900 | 辅助元数据 blob              |

### 消息体

`40800` 存放 protobuf，其外层字段号等于列号。**一条消息可以有多个 `40800` 段**——
正文、图片、引用等各占一段（实测约 18% 的群消息不止一段），每段自带元素类型：

```
40800 { 45001: msg_id, 45002: element_type, 45003: sub_type, …elements… }   # 第 1 段
40800 { 45001: msg_id, 45002: element_type, … }                             # 第 2 段（可有可无）
```

因此必须逐段解码再拼接（`decode_elements()` / `unwrap_bodies()`）：只取第一段会
丢掉其余元素。引用消息内部的 `47423` 同理（实测约 22% 的引用不止一段）。

元素类型族（基于证据；未知字段无论如何都会保留）：

| 类型 | 名称          | 载荷字段                   |
|-----:|:--------------|:---------------------------|
| 1    | 文本          | 45101 text, 45103/45105 @  |
| 2    | 图片          | 45402 名称, 45503 uuid, 45802–04 url |
| 3    | 文件          | 45402 文件名, 45405 大小, 45503 uuid |
| 4    | 语音          | 45402 `.amr`, 459xx 其他    |
| 5    | 视频          | 45402 `.mp4`, 458xx 预览    |
| 6    | 表情          | 476xx                      |
| 7    | 回复          | 47423 被引用的消息体        |
| 8    | 拍一拍        | 47705/47707 名称, 47703/47704 uid |
| 10   | 分享（图文）  | 47901 JSON                 |
| 11   | ark           | 80810 id, 80900 摘要       |
| 16   | 合并转发      | 48602 聊天记录 XML         |
| 17   | bot markdown  | 48751 负载                 |

## 4. 用法

```bash
# decrypt the whole profile at once (key from $NTQQ_DB_KEY or --key)
python3 -m ntqq decrypt-dir \
    ~/.config/QQ/nt_qq_<profile>/nt_db work/plain --key '…'

# decrypt a single database (auto-detects the page HMAC algorithm)
python3 -m ntqq decrypt ~/.config/QQ/nt_qq_<profile>/nt_db/nt_msg.db work/plain/nt_msg.db

# check a key without writing anything
python3 -m ntqq decrypt nt_msg.db --verify-only --key '…'

# list tables and row counts
python3 -m ntqq info work/plain/nt_msg.db

# export messages to JSON Lines
python3 -m ntqq export work/plain/nt_msg.db --table group_msg_table -o group.jsonl

# pretty-print one message's protobuf
python3 -m ntqq dump work/plain/nt_msg.db --table group_msg_table --id 1145141919810

# browse and search the library (see docs/library.md)
python3 -m ntqq groups   ~/.config/QQ/nt_qq_<profile>
python3 -m ntqq chats    ~/.config/QQ/nt_qq_<profile> --limit 30
python3 -m ntqq history  ~/.config/QQ/nt_qq_<profile> 1145141919810 --limit 50
python3 -m ntqq search   ~/.config/QQ/nt_qq_<profile> '关键词' --chat 1145141919810
python3 -m ntqq export-chat ~/.config/QQ/nt_qq_<profile> 1145141919810 -o chat.html
python3 -m ntqq stats    ~/.config/QQ/nt_qq_<profile>
python3 -m ntqq scan     ~/.config/QQ/nt_qq_<profile>            # 逐行解析全库并校验
python3 -m ntqq scan     ~/.config/QQ/nt_qq_<profile> --dump all.jsonl   # 导出每一条
```

`scan` 会**逐表、逐行**读取并完整解析每一条数据，最后给出统计（行数、元素类型
分布、时间范围、样例）与问题清单：坏行、整表读取失败、解码器抛错都会列出并以
非零状态码退出；未被支持的元素类型会单独列出（走兜底渲染，原始字段仍保留）。
加 `--dump` 可把每一条解析结果写成 JSON Lines。

实测（本机 5,450,851 行 / 5,078,889 条消息，约 6~10 分钟）：0 行解析失败、
0 张表读取失败、0 次解码器抛错，元素类型也已**全部覆盖**（含内嵌按钮菜单 `menu`，
即类型 43）。顺带发现并修掉了三个会让整表不可读的问题 —— `group_member3.64023`
有行是被 QQ 按字节截断的 UTF-8（现在按 U+FFFD 兜底，不再中断整表）、两个模型的
列号与真实表不符、以及类型 43 此前没有解码器。

### 测试

```bash
pytest                                  # 全部测试；存在 work/plain 时会跑全库穷举
NTQQ_TEST_LIMIT=20000 pytest tests/test_full_scan.py   # 每表抽 2 万行（快速）
NTQQ_TEST_DB=/path/to/plain pytest      # 指定已解密目录
```

注意：`tests/test_full_scan.py` 默认**全量**（本机约 505 万条消息，需 8 分钟
左右）；不想等就用 `NTQQ_TEST_LIMIT` 限制每表行数。没有可用数据库时它会自动
跳过，所以 CI 不需要真实数据、也不会变慢。

`tests/test_full_scan.py` 是端到端的可用性验证：它把库里**每一条**记录读出并
解析，断言零失败；没有可用数据库时自动跳过，因此 CI 无需真实数据。

`decrypt`/`decrypt-dir` 是无损的：每一页都经过 HMAC 校验，校验失败的页会被写成零页（这样 SQLite 仍能打开文件）并予以报告。稀疏的全零页按原样保留，每个 `-wal` 文件都会被自动解密并叠加。传入 `--hmac`/`--page-size`/`--kdf-prf`/`--kdf-iter` 可覆盖自动检测出的加密参数。

这些命令背后的 Python API——面向数字列的 ORM、类型化消息元素、联系人解析、搜索以及各类导出器——记录在 [`docs/library.md`](docs/library.md) 中：

```python
from ntqq import QQNT

qq = QQNT.open("~/.config/QQ/nt_qq_<profile>", key="<passphrase>")
for group in qq.groups():
    print(group.uin, group.name, group.member_count)
chat = qq.group(1145141919810)
for message in qq.search("关键词", chat=chat, since="2025-09-01"):
    print(message.time_str, message.display_sender, message.text)
qq.export_html(chat, "chat.html")
```

## 5. 注意事项与警示

* **损坏的二级索引。** `nt_msg.db` 包含一个由 QQ 自身写入的全零页（第 262144 页）；其加密源在该处本就为零，因此无法恢复任何内容。其副作用是 `PRAGMA quick_check` 会报告某个 `group_msg_table` 索引中存在重复的页引用，而该表的 b-tree 完好无损。因此 `ntqq.reader` 使用 `NOT INDEXED` 进行扫描；全部 5,051,633 条群消息均可读取。`jdbc/` 会修复该索引（见下文）。
* **自定义 FTS tokenizer。** 若干数据库（例如 `misc.db`、`group_info.db`）使用 WCDB 的 `pinyin_letter` tokenizer 声明了 FTS5 虚拟表。3.51 之前的 SQLite 拒绝解析此类 schema，因此*每一条*查询都会以 `no such tokenizer` 失败；3.51+ 会延迟 tokenizer 解析，从而能够正常读取。这也是原生 SQLite 工具即便在解密之后仍无法打开 QQ 数据库的第二个原因。
* **SQLCipher 配置并非库的默认值。** QQ 将 KDF 迭代次数改写为 4000，并让页 HMAC 可配置（通常为 SHA1/保留区（reserve）48，`guild1.db` 为 SHA512/保留区（reserve）80），这就是原生 `sqlcipher` CLI 默认值（256 000 / HMAC-SHA512）打不开这些文件的原因。请使用 `detect_config` / `--hmac`，而不要依赖 CLI 默认值。
* **`login.db` 使用它自己的密钥。** 全局登录数据库具有相同的格式和加密算法，但密钥不同（见 §2）。
* **`ptrace_scope=1`。** 不允许附加到正在运行的 QQ；请改为在 `gdb` 下运行 QQ（密钥工具正是这样做的）。

## 6. JDBC 驱动（DataGrip）

`jdbc/` 包含 `qqnt-jdbc.jar`，这是一个 JDBC 驱动，可直接打开加密数据库并将其暴露给 DataGrip（或任意 JDBC 客户端）：

```
jdbc:qqnt:/home/me/.config/QQ/nt_qq_<profile>/nt_db/nt_msg.db?key=<passphrase>
```

它的解密方式与 `ntqq` 完全一致（相同的密钥派生、页布局和 WAL 处理），然后通过重建或移除损坏的索引使文件可被原生 SQLite 读取，将明文副本缓存到 `~/.cache/qqnt-jdbc/` 下，并把 SQL 执行委托给内置的 SQLite 3.51 引擎（这是 QQ 的 `pinyin_letter` FTS 表所必需的）。DataGrip 的配置方法，以及标准 `sqlite3`/`sqlcipher` 为何报告 *"database disk image is malformed"* 的完整解释，请参见 `jdbc/README.md`。

## 7. 许可与法律声明

基于 [MIT 许可](LICENSE)发布。

* 这是一个用于互操作/数据恢复的工具，面向**你自己的**机器上**你自己的**账号数据。请仅对你被允许读取的数据库使用它。
* 解密后的数据库和恢复出的密钥属于个人数据：仓库的 `.gitignore` 已将 `work/`、`*.db` 和 `tools/recovered_keys.json` 排除在 git 之外——推送前请务必复查。
* 此处不再分发任何腾讯代码；`jdbc/build.sh` 会下载采用 Apache-2.0 许可的 [xerial sqlite-jdbc](https://github.com/xerial/sqlite-jdbc) 并将其打包进驱动 jar。
