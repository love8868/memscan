#!/usr/bin/env python3
"""
未知初始值搜索（CE 的 "Unknown initial value"）。
适用场景：血条、进度条这种看不到具体数字的。
流程：快照 -> 去游戏里改变数值 -> 比较（变大了/变小了/变了/没变）-> 循环过滤
"""
import array
import math
import struct

from memscan import FMT


class UnknownScanner:
    def __init__(self, backend):
        self.backend = backend
        self.snapshots = []   # [(base_addr, bytes), ...]
        self.candidates = []  # 当前候选地址列表（多轮比较时用）

    def snapshot(self):
        """拍下当前可写内存快照。返回快照总字节数。
        按 1MB 分块读：区间里有个洞（guard page、未提交页）只丢
        这一块，而不是整个区间被静默丢弃。"""
        self.snapshots = []
        total = 0
        CHUNK = 1 << 20
        for start, end in self.backend.regions():
            addr = start
            while addr < end:
                chunk_end = min(addr + CHUNK, end)
                buf = self.backend.read(addr, chunk_end - addr)
                if buf and len(buf) == chunk_end - addr:
                    self.snapshots.append((addr, buf))
                    total += len(buf)
                # 短读/读失败：只跳过这一块
                addr = chunk_end
        self.candidates = []
        return total

    @staticmethod
    def _to_array(buf, vtype):
        """bytes -> array（C 速度解析，比逐个 struct 快一个数量级）"""
        fmt, _ = FMT[vtype]
        if vtype in ('i32', 'u32', 'i64'):
            typecode = {'i32': 'i', 'u32': 'I', 'i64': 'q'}[vtype]
            return array.array(typecode, buf)
        return None  # f32 走 struct（要过滤 inf/nan）

    def compare(self, mode, vtype='i32'):
        """与快照比较。mode: changed/unchanged/increased/decreased
        返回命中地址列表；同时更新 self.candidates（供多轮调用）。
        多轮时：第一次 compare 全量扫，之后只在 candidates 里过滤。
        """
        assert mode in ('changed', 'unchanged', 'increased', 'decreased')
        fmt, size = FMT[vtype]
        assert size == 4, "未知值搜索只支持 4 字节类型"

        # 确定本轮要检查的地址集合
        if self.candidates:
            check = [(a, None) for a in self.candidates]
            use_candidates = True
        else:
            check = None
            use_candidates = False

        hits = []
        if use_candidates:
            for addr in self.candidates:
                old_v = self._read_snapshot(addr, vtype)
                new_b = self.backend.read(addr, 4)
                if old_v is None or not new_b or len(new_b) != 4:
                    continue
                new_v = struct.unpack(fmt, new_b)[0]
                if self._match(mode, old_v, new_v, vtype):
                    hits.append(addr)
            # 候选轮：快照也要推进，不然下轮比较的还是老快照
            self._refresh_snapshot_addrs(self.candidates)
        else:
            for base, old_buf in self.snapshots:
                new_buf = self.backend.read(base, len(old_buf))
                if not new_buf or len(new_buf) != len(old_buf):
                    continue
                n = len(old_buf) // 4
                if vtype == 'f32':
                    for i in range(n):
                        old_v = struct.unpack_from('<f', old_buf, i * 4)[0]
                        new_v = struct.unpack_from('<f', new_buf, i * 4)[0]
                        if (math.isinf(old_v) or math.isnan(old_v)
                                or math.isinf(new_v) or math.isnan(new_v)):
                            continue
                        if self._match(mode, old_v, new_v, vtype):
                            hits.append(base + i * 4)
                else:
                    old_arr = self._to_array(old_buf, vtype)
                    new_arr = self._to_array(new_buf, vtype)
                    for i in range(n):
                        if self._match(mode, old_arr[i], new_arr[i], vtype):
                            hits.append(base + i * 4)
            # 全量轮：快照整体推进到最新
            self.snapshot()

        self.candidates = hits
        return hits

    @staticmethod
    def _match(mode, old_v, new_v, vtype):
        if vtype == 'f32':
            # 浮点比较加个极小 epsilon，防精度抖动
            if mode == 'unchanged':
                return abs(new_v - old_v) < 1e-6
            if mode == 'changed':
                return abs(new_v - old_v) >= 1e-6
            if mode == 'increased':
                return new_v > old_v + 1e-6
            if mode == 'decreased':
                return new_v < old_v - 1e-6
        else:
            if mode == 'changed':
                return new_v != old_v
            if mode == 'unchanged':
                return new_v == old_v
            if mode == 'increased':
                return new_v > old_v
            if mode == 'decreased':
                return new_v < old_v
        return False

    def _read_snapshot(self, addr, vtype):
        """从快照里读某地址的值（候选轮过滤用）。"""
        fmt, _ = FMT[vtype]
        for base, buf in self.snapshots:
            if base <= addr < base + len(buf):
                off = addr - base
                if off + 4 <= len(buf):
                    return struct.unpack_from(fmt, buf, off)[0]
        return None

    def _refresh_snapshot_addrs(self, addrs):
        """候选轮后，把快照中这些地址的值更新为最新（只改 4 字节）。"""
        for addr in addrs:
            new_b = self.backend.read(addr, 4)
            if not new_b or len(new_b) != 4:
                continue
            for i, (base, buf) in enumerate(self.snapshots):
                if base <= addr < base + len(buf):
                    off = addr - base
                    self.snapshots[i] = (base,
                                         buf[:off] + new_b + buf[off + 4:])
                    break
