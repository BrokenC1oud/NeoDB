"""读取 QQ NT（``nt_msg.db``）数据库的净室（clean-room）工具集。

本工具包拆分为若干小而独立的层：

* :mod:`ntqq.header`    - 1024 字节的 QQ 容器头
* :mod:`ntqq.sqlcipher` - SQLCipher 页解密（纯 Python）
* :mod:`ntqq.protobuf`  - 通用 protobuf 线格式解码器
* :mod:`ntqq.elements`  - 消息元素的语义解码
* :mod:`ntqq.reader`    - 已解密数据库的高层访问接口
* :mod:`ntqq.orm`       - 建立在 QQ 数字列上的小型 ORM
* :mod:`ntqq.schema`    - 消息/联系人数据库的列映射
* :mod:`ntqq.message`   - 带类型的元素与消息
* :mod:`ntqq.world`     - 浏览联系人、历史消息、检索、导出
* :mod:`ntqq.export`    - JSONL / CSV / Markdown / HTML 写出器

快速开始::

    from ntqq import QQNT

    qq = QQNT.open("~/.config/QQ/nt_qq_<profile>", key="<passphrase>")
    for group in qq.groups():
        print(group.uin, group.name)
    for message in qq.search("关键词", chat=1145141919810, since="2025-09-01"):
        print(message)
"""

from .header import HEADER_SIZE, QQHeader, parse_header
from .message import (
    ELEMENT_NAMES,
    Element,
    Message,
    decode_elements,
    element_name,
    parse_elements,
    unwrap_bodies,
    unwrap_body,
)
from .orm import Column, Database, DatabaseManager, Model, Query, Table
from .sqlcipher import (
    DEFAULT_CONFIG,
    CipherConfig,
    DecryptedDatabase,
    Keys,
    apply_wal,
    decrypt_file,
    decrypt_page,
    decrypt_wal,
    derive_enc_key,
    derive_hmac_key,
    detect_config,
    keys_for,
    looks_encrypted,
    read_header_and_salt,
    verify_file,
    verify_page,
)
from .world import (
    QQNT,
    Contact,
    Friend,
    Group,
    ScanReport,
    prepare_profile,
    repair_file,
)

__all__ = [
    "DEFAULT_CONFIG",
    "ELEMENT_NAMES",
    "HEADER_SIZE",
    "QQNT",
    "CipherConfig",
    "Column",
    "Contact",
    "Database",
    "DatabaseManager",
    "DecryptedDatabase",
    "Element",
    "Friend",
    "Group",
    "Keys",
    "Message",
    "Model",
    "QQHeader",
    "Query",
    "ScanReport",
    "Table",
    "apply_wal",
    "decode_elements",
    "decrypt_file",
    "decrypt_page",
    "decrypt_wal",
    "derive_enc_key",
    "derive_hmac_key",
    "detect_config",
    "element_name",
    "keys_for",
    "looks_encrypted",
    "parse_elements",
    "parse_header",
    "prepare_profile",
    "read_header_and_salt",
    "repair_file",
    "unwrap_bodies",
    "unwrap_body",
    "verify_file",
    "verify_page",
]
