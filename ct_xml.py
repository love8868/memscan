#!/usr/bin/env python3
"""标准 .CT (XML) 存档读写。

改写自 bethington/cheat-engine-server-python
(server/cheatengine/table_parser.py) 的最小子集：
精简版 CheatEntry 数据模型 + XML 解析/生成。
原项目 MIT License，Copyright (c) bethington。
本文件同样以 MIT License 发布。

只用标准库（xml.etree.ElementTree + dataclasses），零依赖。
"""
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# 我们的 vtype → CE 的 VariableType
TO_CE = {
    "i32": "4 Bytes",
    "u32": "4 Bytes",
    "f32": "Float",
    "i64": "8 Bytes",
}

# CE 的 VariableType → 我们的 vtype（读外部 .CT 用）
FROM_CE = {
    "Byte": "u8",
    "2 Bytes": "u16",
    "4 Bytes": "i32",
    "8 Bytes": "i64",
    "Float": "f32",
    "Double": "f64",
    "String": "str",
    "Array of byte": "aob",
    "Binary": "bin",
}

# 我们实际支持的类型（FMT）
SUPPORTED_VTYPES = {"i32", "u32", "f32", "i64"}


@dataclass
class CheatEntry:
    """单条目（精简版，只留读写 .CT 需要的字段）。"""
    id: str
    description: str
    address: Optional[int] = None
    address_string: Optional[str] = None  # 模块+偏移，如 "D2GAME.dll+1107B8"
    offsets: List[int] = field(default_factory=list)
    variable_type: str = "4 Bytes"
    value: Any = None      # LastState Value（我们用来存 lock_value）
    enabled: bool = False  # 对应我们的 locked


def _parse_address(s):
    """解析地址字符串：0x 前缀 / $ 前缀 / 纯 hex。失败返回 None。"""
    if not s:
        return None
    s = s.strip()
    try:
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        if s.startswith("$"):
            return int(s[1:], 16)
        if all(c in "0123456789ABCDEFabcdef" for c in s):
            return int(s, 16)
    except ValueError:
        pass
    return None


def _text(elem, tag, default=""):
    child = elem.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return default


def parse_ct(path):
    """解析标准 .CT (XML) 文件。

    返回 (entries, warnings)：entries 是 cheattable.entry() 形状的 dict 列表，
    warnings 是跳过条目的原因列表。解析失败直接抛异常（调用方处理）。
    """
    entries = []
    warnings = []
    tree = ET.parse(path)
    root = tree.getroot()
    container = root.find("CheatEntries")
    if container is None:
        container = root  # 有些 .CT 把 CheatEntry 直接挂在根下
    for i, elem in enumerate(container.findall("CheatEntry")):
        eid = _text(elem, "ID", str(i))
        desc = _text(elem, "Description", "Unknown").strip("\"'")

        # 1. 地址
        addr_text = _text(elem, "Address")
        if addr_text and "+" in addr_text:
            warnings.append(f"ID {eid}「{desc}」：符号地址 {addr_text} 不支持（缺模块基址解析），已跳过")
            continue
        address = _parse_address(addr_text)
        if address is None:
            warnings.append(f"ID {eid}「{desc}」：地址 {addr_text!r} 解析失败，已跳过")
            continue

        # 2. 指针链：超出范围，跳过
        offsets_elem = elem.find("Offsets")
        if offsets_elem is not None and offsets_elem.findall("Offset"):
            warnings.append(f"ID {eid}「{desc}」：含指针链 Offsets，不支持，已跳过")
            continue

        # 3. 类型
        ce_type = _text(elem, "VariableType", "4 Bytes")
        vtype = FROM_CE.get(ce_type)
        if vtype is None:
            warnings.append(f"ID {eid}「{desc}」：未知类型 {ce_type!r}，已跳过")
            continue
        if ce_type == "4 Bytes":
            # ShowAsSigned=1 → 有符号(i32)，否则无符号(u32)。
            # 注意：缺省值 "0"（无符号）是我们的选择；CE 原生对缺失 ShowAsSigned
            # 的 4 Bytes 的真实缺省行为未经官方文档确认（只影响读第三方 .CT
            # 的边缘情况；我们自己写的文件 i32 总是显式写 ShowAsSigned=1）。
            vtype = "i32" if _text(elem, "ShowAsSigned", "0") == "1" else "u32"
        if vtype not in SUPPORTED_VTYPES:
            warnings.append(f"ID {eid}「{desc}」：类型 {ce_type}（{vtype}）暂不支持，已跳过")
            continue

        # 4. 锁定状态与锁定值
        locked = elem.get("Enabled", "0") == "1"
        lock_value = None
        last = elem.find("LastState")
        if last is not None and last.get("Value"):
            raw = last.get("Value")
            try:
                lock_value = int(raw)
            except ValueError:
                try:
                    lock_value = float(raw)
                except ValueError:
                    lock_value = None

        entries.append({
            "name": desc,
            "addr": hex(address),
            "vtype": vtype,
            "locked": locked,
            "lock_value": lock_value,
            "id": eid,
            "address_string": None,
            "offsets": [],
        })
    return entries, warnings


def write_ct(path, entries):
    """把我们的 entry dict 列表写成标准 .CT (XML)。返回 path。"""
    root = ET.Element("CheatTable")
    container = ET.SubElement(root, "CheatEntries")
    for i, e in enumerate(entries):
        vtype = e.get("vtype", "i32")
        ce_type = TO_CE.get(vtype)
        if ce_type is None:
            print(f"⚠️ 条目「{e.get('name', '')}」：vtype {vtype!r} 无法映射到 CE 类型，已跳过")
            continue  # 不支持的类型直接跳过（不写）
        addr = int(e["addr"], 16)
        locked = bool(e.get("locked"))

        ce = ET.SubElement(container, "CheatEntry")
        if locked:
            # CE 会忽略未知属性，互操作安全
            ce.set("Enabled", "1")
        ET.SubElement(ce, "ID").text = str(e.get("id", i))
        # CE 习惯用双引号包裹 Description，解析时 strip 引号，round-trip 安全
        ET.SubElement(ce, "Description").text = '"%s"' % e.get("name", "")
        ET.SubElement(ce, "Address").text = hex(addr)  # 小写 hex
        ET.SubElement(ce, "VariableType").text = ce_type
        if vtype == "i32":
            ET.SubElement(ce, "ShowAsSigned").text = "1"
        elif vtype == "u32":
            ET.SubElement(ce, "ShowAsSigned").text = "0"
        # 浮点类型省略 ShowAsSigned
        if locked and e.get("lock_value") is not None:
            ET.SubElement(ce, "LastState", {"Value": str(e["lock_value"])})
    _indent(root)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)
    return path


def _indent(elem, level=0):
    """美化缩进（改写自原项目的 _indent_xml）。"""
    i = "\n" + level * "  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
        for child in elem:
            _indent(child, level + 1)
        if not child.tail or not child.tail.strip():
            child.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i
