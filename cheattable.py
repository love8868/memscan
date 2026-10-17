#!/usr/bin/env python3
"""CT 表：地址列表存成 JSON（CE 的 .CT 文件的极简版）。
下次打开直接加载，不用重扫。"""
import json
import os


def save(path, entries):
    """entries: [{name, addr(16进制字符串), vtype, locked, lock_value}, ...]"""
    with open(path, "w") as f:
        json.dump({"entries": entries}, f, indent=2, ensure_ascii=False)
    return path


def load(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        data = json.load(f)
    return data.get("entries", [])


def entry(name, addr, vtype="i32", locked=False, lock_value=None):
    return {"name": name,
            "addr": hex(addr),
            "vtype": vtype,
            "locked": locked,
            "lock_value": lock_value}
