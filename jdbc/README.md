# qqnt-jdbc —— 面向 QQ NT 数据库的 JDBC 驱动

`qqnt-jdbc.jar` 让 **DataGrip**（或任意 JDBC 工具）能够打开 Linux QQ NT 客户端的加密数据库，读取其**全部**内容，并像操作普通 SQLite 数据库一样使用它们。

它是 QQ 自有存储栈（WCDB）在打开文件时所做行为的*洁净室*重新实现；其推导过程见 `../README.md`。

```
jdbc/ src/qqnt/jdbc/SqlCipher.java   SQLCipher 页加密（AES-256-CBC + HMAC）
      src/qqnt/jdbc/Preparer.java    解密 + WAL + 索引修复 + 缓存
      src/qqnt/jdbc/Driver.java      java.sql.Driver、URL 解析、密钥查找
      src/qqnt/jdbc/Tool.java        命令行前端
      build.sh                       javac + jar，内嵌 SQLite 引擎
      dist/qqnt-jdbc.jar             驱动（fat jar，约 14 MB）
```

内置引擎是 xerial `sqlite-jdbc` 3.51.1（SQLite 3.51.1）。这个版本很关键：较旧的 SQLite 构建拒绝解析 QQ 的 `pinyin_letter` FTS schema，即便解密正确，整个数据库也无法使用。

## 为什么会出现 "The database disk image is malformed"

这其实是**两**个不同的问题，且都不是密钥损坏：

1. **加密。** 原生 SQLite 根本无法解密该文件，原生 *SQLCipher* 也不行，因为 QQ 覆盖了库的默认值：

   | parameter | SQLCipher default | QQ |
   |:--|:--|:--|
   | KDF 迭代次数 | 256 000 | **4 000** |
   | 页 HMAC | SHA-512 | **SHA-1**（`guild1.db` 为 SHA-512） |
   | 页大小 | 4096 | 4096 |
   | 容器 | 无 | **在第 1 页前添加 1024 字节头部** |

   1024 字节的容器头是明文，但它会*整体偏移*每一页，因此 SQLCipher 自身的 `salt`/页处理会错位一个块，从而报告数据库损坏，而不是密钥错误。

2. **一处真正不一致的索引 b-tree。** 即便解密正确，SQLite 仍会拒绝某些查询。在 `nt_msg.db` 中：

   ```
   quick_check:
   *** in database main ***
   Tree 11 page 87484 cell 71: 2nd reference to page 262145
   Page 262144: never used
   wrong # of entries in index group_msg_table_idx40027_40058
   ```

   Tree 11 就是 `group_msg_table_idx40027_40058`。它的叶子节点两次包含同一个子页号，且单元格计数与索引条目数不匹配。

3. **自定义全文 tokenizer。** QQ 的 FTS 表使用它自己的 tokenizer 创建，例如

   ```sql
   CREATE VIRTUAL TABLE search_guild_table_fts
       USING fts5(tokenize = 'pinyin_letter 1', content=search_guild_table, ...)
   ```

   `pinyin_letter` 由 WCDB 注册，而非原生 SQLite。较旧的 SQLite 完全拒绝解析此类 schema（`no such tokenizer: pinyin_letter`），使*整个数据库*无法使用——每一条查询都会失败，而不仅仅是搜索表。SQLite 3.51 及更新版本会延迟 tokenizer 解析，能够正常读取这类文件，因此驱动内置了较新的引擎（见 `build.sh`）。不会有任何搜索数据丢失：FTS 影子表（`*_fts_data`、`*_fts_idx`、`*_fts_docsize`、`*_fts_config`）都是普通表，仍然可读。

**那么 QQ 为什么还能读取全部内容：** QQ 从不遍历那个索引。它的消息查询由行 id 驱动（`WHERE [40027] = ? AND [40003] BETWEEN ? AND ?`），而 WCDB 对其自身查询模式触及不到的缺陷采取*尽力而为*的容忍态度。相比之下，SQLite 会乐于为 `SELECT count(*)` 选择 `group_msg_table_idx40027_40058`（它是最廉价的索引），然后在遍历损坏的树时报错——于是普通的 `SELECT count(*)` 失败，而 `SELECT ... FROM group_msg_table NOT INDEXED` 能成功返回全部 5 051 633 行；QQ（其数据访问始终通过行 id 或其完好的索引）则能看到一切。

表的 b-tree 完好无损；**没有任何消息数据损坏**。损坏的只有那一个索引。

## 驱动做了什么

对于 `jdbc:qqnt:<path>?key=<passphrase>`，它会

1. 读取 1024 字节的容器头和 16 字节的 salt；
2. 使用 PBKDF2-HMAC-SHA512/4000 派生密钥（精确到字节，刻意避开 JCE 的 `PBEKeySpec`，因为它会破坏非 ASCII 口令）；
3. 通过试校验自动检测页 HMAC 算法；
4. 解密每一页（第 1 页保留其 salt 前缀，并还原 `SQLite format 3\0` 魔数），将保留区（reserve）写为零；
5. 解密 `-wal` 并叠加当前代的*已提交*帧——即 QQ 当前所见的确切状态；
6. 使文件可被原生 SQLite 读取（见下文）；
7. 以源路径 + 大小 + mtime + 密钥哈希 + 选项为键，将结果缓存到 `~/.cache/qqnt-jdbc/` 下，因此重连是瞬时的；
8. 用内置的 SQLite 引擎打开明文文件。

### 使文件可读（`repair=`）

| 模式 | 动作 | 说明 |
|:--|:--|:--|
| `auto`（默认） | 对损坏的索引执行 `REINDEX`，若失败则回退到 `schema` | 从完好的表数据重建一个有效索引——完全无损 |
| `reindex` | 仅执行 `REINDEX` | |
| `drop` | `DROP INDEX` | 文件最小，在 5 GB 数据库上约 1 秒 |
| `schema` | 从 `sqlite_master` 中移除索引行（通过 `writable_schema`） | 对**数据**无损；孤立的页仍留在文件中 |
| `none` | 不修改文件 | 此时你的查询中需要使用 `NOT INDEXED` |

`auto` 最安全。在测试所用的账号配置中，对损坏索引执行 `REINDEX` 并不可行（SQLite 必须读取损坏页才能重建），`DROP` 也不行，因此 `auto` 会回退到 `schema` 途径；其余三个索引保持有效，`count(*)`/索引扫描重新可用。

该途径有两个后果，都无伤大雅：

* 被移除的树的页不会归还给 SQLite 的空闲列表，因此 `PRAGMA quick_check` 会把它们报告为 `Page N: never used`。QQ 自身的文件本就包含这类页（例如全零页 262144），修复之前它也已报告 `never used`。查询不受影响。
* 文件不会缩小。若想收回这些空间，请使用 SQLite 的 `VACUUM`（需要与数据库等大的空闲空间）。

自动释放这些页被刻意**未**实现：损坏的索引与活跃的 `group_msg_table` b-tree 共享同一页（`2nd reference to page 262145`），因此一个天真的“释放所有不可达页”过程可能破坏活跃数据。驱动因此只移除 schema 行，这是 SQLite 能安全完成的。

## 构建

```bash
cd jdbc
./build.sh          # downloads sqlite-jdbc from Maven Central once, then builds
```

需要 JDK（17+）。构建刻意以 **Java 17** 为目标（`javac --release 17`）：JetBrains IDE 运行在它们*自带的* JetBrains Runtime 上，而不是操作系统安装的 JDK。DataGrip 2026.2 附带 JBR 25（class-file 版本 69），因此由更新 JDK（例如系统 JDK 27，版本 71）编译的 jar 会以 `UnsupportedClassVersionError` 加载失败。目标设为 17，则所有当前 IDE 都能正常使用。若想匹配某个特定的运行时，可用 `JAVA_RELEASE=25 ./build.sh` 覆盖。

产物为 `jdbc/dist/qqnt-jdbc.jar`。

## DataGrip 配置

1. **File → Data Sources → + → Driver**。
2. **Driver Files → + → Custom JAR** → `jdbc/dist/qqnt-jdbc.jar`。
3. **Class**：`qqnt.jdbc.Driver`。
4. **URL template**：`jdbc:qqnt:{path}`。
5. 用 `jdbc:qqnt:/home/me/.config/QQ/nt_qq_<profile>/nt_db/nt_msg.db?key=<passphrase>` 创建一个数据源（或把密钥放进*密码*字段，DataGrip 会将其存入凭据保管库）。

然后点击 **Refresh**：DataGrip 会内省 schema，让你浏览全部 34 张表、运行 SQL、导出数据等。

### 两种 URL 形式

`qqnt.jdbc.Driver` 两者都接受：

| URL | 用途 |
|:--|:--|
| `jdbc:qqnt:<encrypted.db>[?key=…]` | **推荐**——先解密（并应用 `-wal`）、修复，然后读取 |
| `jdbc:sqlite:<plain.db>` | 已解密文件；直接交给内置的 SQLite 引擎 |
| `jdbc:sqlite:<plain.db>?repair=auto` | 同上，但文件会先被复制到缓存并修复（当文件仍含有 QQ 损坏的索引时需要） |

不带 `repair=` 的 `jdbc:sqlite:` URL 会原样交给引擎，因此诸如 `?open_mode=1` 或 `?immutable=1` 这类 SQLite 专有参数仍可正常使用。

> **"No suitable driver found for jdbc:sqlite:…"** 意味着驱动定义里只有我们的类（`qqnt.jdbc.Driver`），而我们的类未声明接管 `jdbc:sqlite:`（较旧的构建），或者该定义使用了另一个不在 classpath 上的类。要么更新到本构建，要么把驱动类设为 `org.sqlite.JDBC`，它已打包在 `qqnt-jdbc.jar` 内。

注意，*刚解密*的数据库仍含有 QQ 损坏的索引，因此在修复一次之前，`SELECT count(*)` 可能会报告 `database disk image is malformed`：

```bash
java -jar jdbc/dist/qqnt-jdbc.jar repair work/plain/nt_msg.db
```

### URL 参数

| 参数 | 含义 |
|:--|:--|
| `key` | 口令（与 `keyHex`/`keyFile` 互斥） |
| `keyHex` | 以十六进制表示的口令（用于不可打印的密钥） |
| `keyFile` | 包含 `"passphrase"` 的 JSON 文件，例如 `tools/recovered_keys.json` |
| `cache` | 解密副本的存放目录（默认 `~/.cache/qqnt-jdbc`） |
| `repair` | `auto` \| `reindex` \| `drop` \| `schema` \| `none` |
| `wal` | `true`（默认）/ `false` — 是否应用 `-wal` 文件 |
| `hmac` | `auto`（默认）\| `sha1` \| `sha512` |
| `force` | 设为 `true` 时即使已有缓存副本也重新解密 |

密钥也可以来自 JDBC 的**密码**属性、`$NTQQ_DB_KEY`，或数据库旁边的 `<database>.key` 文件。

路径可以指向账号配置目录（`.../nt_qq_<profile>/nt_db`），此时驱动会默认使用 `nt_msg.db`。

### 获取密钥

```bash
python3 ../tools/get_db_key.py     # launches QQ under gdb and reports it
```

账号密钥（16 字节）能打开该账号配置中除 `guild1.db` 以外的每一个数据库；`guild1.db` 需要同一个密钥配合 HMAC-SHA512——会自动处理。`global/nt_db/login.db` 使用另一个 20 字节密钥；把 URL 指向它并传入该密钥。

## 命令行

```bash
java -jar dist/qqnt-jdbc.jar decrypt <encrypted.db> [out-dir]   # + repair report
java -jar dist/qqnt-jdbc.jar info    <encrypted.db>             # tables + row counts
java -jar dist/qqnt-jdbc.jar check   <plain.db>                 # PRAGMA quick_check
java -jar dist/qqnt-jdbc.jar repair  <plain.db> [mode]
```

并需导出 `NTQQ_DB_KEY`。

## 性能

在测试所用的账号配置上（5.0 GB 的 `nt_msg.db`，1 285 412 页）：

* 首次连接：约 2–4 分钟（解密 + WAL + 修复），之后走缓存；
* 走缓存的连接：远低于一秒；
* 对 5 051 633 条群消息执行 `SELECT count(*)`：在冷页缓存下需要数十秒——这是 QQ 自身的数据规模，而非驱动开销。

## 限制

* 实质上只读：DataGrip 可以编辑*解密副本*，但写入不会回写到加密原文件。请把该数据源当作只读使用。
* 解密缓存中包含明文聊天记录——它位于 `~/.cache/qqnt-jdbc/`。用完后请删除。
* `REINDEX` 无法修复测试所用账号配置中的损坏索引（SQLite 必须读取损坏页）；`auto` 会回退到移除索引行，这对所有行数据都是无损的，之后该表及其余索引均全部校验通过。
