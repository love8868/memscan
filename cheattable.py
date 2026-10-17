#!/usr/bin/env python3
"""CT 表：地址列表存档。
- .ct / .xml：标准 Cheat Engine .CT (XML) 格式，CE 可直接打开（见 ct_xml.py）
- 其他扩展名：JSON（老格式，永远可读）
下次打开直接加载，不用重扫。"""
import json
import os

import ct_xml

# 最近一次 load() 跳过的条目原因（XML 解析用）
last_warnings = []


def save(path, entries):
    """entries: [{name, addr(16进制字符串), vtype, locked, lock_value}, ...]
    按扩展名分流：.ct/.xml 走标准 .CT (XML)，其他走 JSON。"""
    if os.path.splitext(path)[1].lower() in (".ct", ".xml"):
        return ct_xml.write_ct(path, entries)
    with open(path, "w") as f:
        json.dump({"entries": entries}, f, indent=2, ensure_ascii=False)
    return path


def load(path):
    """嗅探格式加载。返回 entries 列表；跳过原因记在 last_warnings。"""
    global last_warnings
    last_warnings = []
    if not os.path.exists(path):
        return []
    with open(path, "rb") as f:
        head = f.read(4096)
    if b"<CheatTable" in head:
        entries, last_warnings = ct_xml.parse_ct(path)
        return entries
    if head.decode("utf-8-sig", "ignore").lstrip().startswith("{"):  # utf-8-sig 去 BOM
        with open(path, encoding="utf-8-sig") as f:
            data = json.load(f)
        return data.get("entries", [])
    print(f"⚠️ {path}：无法识别的存档格式")
    return []


def entry(name, addr, vtype="i32", locked=False, lock_value=None,
          id=None, address_string=None, offsets=None):
    d = {"name": name,
         "addr": hex(addr),
         "vtype": vtype,
         "locked": locked,
         "lock_value": lock_value}
    if id is not None:
        d["id"] = id
    if address_string is not None:
        d["address_string"] = address_string
    if offsets is not None:
        d["offsets"] = offsets
    return d
