#!/usr/bin/env python3
"""
memscan - 极简内存扫描器（CE 原理演示版）
================================================
把 Cheat Engine 的"搜数值→改数值→过滤"流程自动化。

双后端设计：
  * LinuxBackend   - 用 /proc/<pid>/mem 读写（本机实测用，需同用户或 root）
  * WindowsBackend  - 用 pymem（pip install pymem），给 Windows 实战用

核心逻辑（Scanner 类）与平台无关，两边共用同一份。

用途限定：单机游戏分析学习。网游改内存会被服务器纠正+封号，别试。
"""
import os
import re
import struct

# 支持的数据类型：小端序（x86/x64/ARM 默认都是小端）
FMT = {
    'i32': ('<i', 4),   # 4 字节有符号整数（血量、金币常用）
    'u32': ('<I', 4),   # 4 字节无符号整数
    'f32': ('<f', 4),   # 4 字节浮点数（坐标常用）
    'i64': ('<q', 8),   # 8 字节整数
}


def parse_transform(expr):
    """解析数值变换表达式，如 "*8"、"*8+10"、"/2-5"。
    很多游戏不存原值，存的是变换后的值（防内存修改的最简手段）。
    返回 (to_stored, to_display) 两个函数。

    注意："/" 是向下取整除法，单向有损，不可逆。
    如显示值 5、"/2" → 内存 2 → 显示回来是 4 ≠ 5。
    需要精确往返时别用 "/"。
    """
    tokens = re.findall(r'([*/+-])(\d+)', expr.replace(' ', ''))
    if not tokens or ''.join(o + n for o, n in tokens) != expr.replace(' ', ''):
        raise ValueError(f"变换格式错误: {expr}，示例：*8、*8+10、/2")
    ops = [(o, int(n)) for o, n in tokens]

    def to_stored(d):
        v = d
        for op, n in ops:
            if op == '*':
                v *= n
            elif op == '/':
                v //= n
            elif op == '+':
                v += n
            elif op == '-':
                v -= n
        return v

    def to_display(s):
        v = s
        for op, n in reversed(ops):
            if op == '*':
                v /= n
            elif op == '/':
                v *= n
            elif op == '+':
                v -= n
            elif op == '-':
                v += n
        return v

    return to_stored, to_display


def pack_value(value, vtype):
    fmt, _ = FMT[vtype]
    return struct.pack(fmt, value)


def unpack_value(buf, vtype):
    fmt, _ = FMT[vtype]
    return struct.unpack(fmt, buf)[0]


# 单次首搜命中上限：搜 0/1 这类常见值时，零页能产出上亿个命中，
# 全收进列表会吃掉几个 GB 内存。超了就停，提示用户先去游戏里改变数值。
MAX_FIRST_SCAN_HITS = 200_000


def normalize_value(value, vtype):
    """把用户输入按类型规整：整数类型且值是整数时转 int。
    CLI 传进来的是 float（如 500.0），直接 struct.pack('<i', 500.0)
    会抛 struct.error。"""
    if vtype != 'f32':
        f = float(value)
        if f.is_integer():
            return int(f)
    return value


def _scan_pointers(backend, target_addr, ptr_size=8):
    """指针扫描通用逻辑：在后端内存里找"值 == target_addr"的地址。
    返回的每个地址，读出来都是 target_addr——顺着它们能反推出
    "谁引用了目标"，是做指针链的第一步。"""
    needle = struct.pack('<Q' if ptr_size == 8 else '<I', target_addr)
    found = []
    for start, end in backend.regions():
        addr = start
        CHUNK = 1 << 20
        while addr < end:
            chunk_end = min(addr + CHUNK, end)
            buf = backend.read(addr, chunk_end - addr)
            if buf:
                off = 0
                while True:
                    idx = buf.find(needle, off)
                    if idx < 0:
                        break
                    # 指针按 ptr_size 对齐才算（减少误报）
                    if (addr + idx) % ptr_size == 0:
                        found.append(addr + idx)
                    off = idx + 1
            addr = chunk_end
    return found


class LinuxBackend:
    """Linux 后端：读写 /proc/<pid>/mem。root 或同用户一般可直接用。"""

    def __init__(self, pid):
        self.pid = pid
        self.fd = os.open(f"/proc/{pid}/mem", os.O_RDWR)
        # 开关：True 时 regions() 也返回文件映射（主程序/.so 的 .data/.bss）。
        # 默认 False 求快（动态数值一般在堆/匿名内存里）。
        self.include_mapped = False

    def regions(self):
        """解析 /proc/<pid>/maps，只返回可读写的内存区间。

        默认跳过 .so / 可执行文件等文件映射——要改的动态数值
        （血量、金币）一般都在堆 / 匿名内存里，这样扫得快。
        置 include_mapped=True 可把文件映射也纳入（会变慢，
        但能搜到主程序 .data/.bss 里的数值）。
        """
        out = []
        with open(f"/proc/{self.pid}/maps") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                addrs, perms = parts[0], parts[1]
                if 'r' not in perms or 'w' not in perms:
                    continue
                pathname = parts[5] if len(parts) > 5 else ''
                if (not self.include_mapped and pathname
                        and not pathname.startswith('[')):
                    continue  # 跳过文件映射
                s, e = addrs.split('-')
                start, end = int(s, 16), int(e, 16)
                if end > start:
                    out.append((start, end))
        return out

    def read(self, addr, size):
        try:
            data = os.pread(self.fd, size, addr)
            return data if len(data) == size else None
        except OSError:
            return None

    def write(self, addr, data):
        try:
            return os.pwrite(self.fd, data, addr) == len(data)
        except OSError:
            return False

    def find_pointers(self, target_addr, ptr_size=8):
        """找指向 target_addr 的指针（一级指针扫描）。
        在可写内存里搜"值 == target_addr"的地址。"""
        return _scan_pointers(self, target_addr, ptr_size)

    def close(self):
        os.close(self.fd)


class WindowsBackend:
    """Windows 后端：pymem。用法：

        pip install pymem
        backend = WindowsBackend("game.exe")  # 进程名
        # 之后 Scanner 用法与 Linux 完全一致

    注意：部分游戏需要"以管理员身份运行"才能 OpenProcess 成功。
    """

    def __init__(self, process_name):
        from pymem import Pymem
        self.pm = Pymem(process_name)
        # 与 LinuxBackend 对齐的开关；Windows 用 VirtualQueryEx 本来就
        # 覆盖全部已提交页，这里是 no-op，仅为接口一致。
        self.include_mapped = False

    def regions(self):
        """用 VirtualQueryEx 枚举可读写已提交内存页。"""
        import ctypes
        from ctypes import wintypes

        MEM_COMMIT = 0x1000
        PAGE_READWRITE = 0x04
        PAGE_READONLY = 0x02
        PAGE_WRITECOPY = 0x08
        PAGE_EXECUTE_READWRITE = 0x40

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", wintypes.LPVOID),
                ("AllocationBase", wintypes.LPVOID),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        kernel32 = ctypes.windll.kernel32
        handle = self.pm.process_handle
        out = []
        addr = 0
        mbi = MEMORY_BASIC_INFORMATION()
        while kernel32.VirtualQueryEx(handle, addr, ctypes.byref(mbi),
                                      ctypes.sizeof(mbi)):
            base = mbi.BaseAddress
            size = mbi.RegionSize
            if (mbi.State == MEM_COMMIT and mbi.Protect & (
                    PAGE_READWRITE | PAGE_READONLY |
                    PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)):
                out.append((base, base + size))
            addr = base + size
            if addr >= 0x7FFFFFFFFFFF:  # 用户空间上限
                break
        return out

    def read(self, addr, size):
        try:
            return self.pm.read_bytes(addr, size)
        except Exception:
            return None

    def write(self, addr, data):
        try:
            self.pm.write_bytes(addr, data, len(data))
            return True
        except Exception:
            return False

    def find_pointers(self, target_addr, ptr_size=8):
        """找指向 target_addr 的指针（一级指针扫描，分块读实现）。"""
        return _scan_pointers(self, target_addr, ptr_size)

    def close(self):
        self.pm.close_process()


class Scanner:
    """平台无关的扫描逻辑：首搜 -> 多轮过滤 -> 写入。"""

    def __init__(self, backend):
        self.backend = backend
        self.candidates = []
        self._last = {}  # addr -> 上轮扫描到的值（差值过滤用）

    def first_scan(self, value, vtype='i32'):
        """全内存首搜：找出所有"当前值 == value"的地址。
        命中超过 MAX_FIRST_SCAN_HITS 时提前停并提示
        （搜 0/1 这类值会内存爆炸）。"""
        needle = pack_value(value, vtype)
        size = len(needle)
        found = []
        overflow = False
        for start, end in self.backend.regions():
            addr = start
            CHUNK = 1 << 20  # 1MB 分块，避免单次读太大
            while addr < end and not overflow:
                chunk_end = min(addr + CHUNK, end)
                buf = self.backend.read(addr, chunk_end - addr)
                if buf:
                    off = 0
                    while True:
                        idx = buf.find(needle, off)
                        if idx < 0:
                            break
                        found.append(addr + idx)
                        if len(found) >= MAX_FIRST_SCAN_HITS:
                            overflow = True
                            break
                        off = idx + 1
                if chunk_end >= end:
                    break  # 已到区间末尾，不再回退（否则死循环）
                # 回退 size-1 字节，防止目标横跨两个块时漏检
                addr = chunk_end - (size - 1)
            if overflow:
                break
        if overflow:
            print(f"⚠️ 命中超过 {MAX_FIRST_SCAN_HITS} 个，已停止收集。"
                  "先去游戏里改变数值，再用 next_scan 过滤这批候选。")
        # 去重（回退导致重叠区会重复命中）
        seen, uniq = set(), []
        for a in found:
            if a not in seen:
                seen.add(a)
                uniq.append(a)
        self.candidates = uniq
        self._last = {a: value for a in uniq}
        return uniq

    def next_scan(self, value, vtype='i32'):
        """拿新值过滤上一轮候选：只保留"值也跟着变对了"的地址。"""
        needle = pack_value(value, vtype)
        size = len(needle)
        keep = []
        new_last = {}
        for addr in self.candidates:
            if self.backend.read(addr, size) == needle:
                keep.append(addr)
                new_last[addr] = value
        self.candidates = keep
        self._last = new_last
        return keep

    def next_scan_delta(self, delta, vtype='i32'):
        """差值过滤：只保留"变化量 == delta"的地址。
        比如"花了 50 金币" → next_scan_delta(-50)，比"变小了"精确得多。"""
        fmt, size = FMT[vtype]
        keep = []
        new_last = {}
        for addr, old_v in self._last.items():
            buf = self.backend.read(addr, size)
            if buf and len(buf) == size:
                new_v = struct.unpack(fmt, buf)[0]
                if new_v - old_v == delta:
                    keep.append(addr)
                    new_last[addr] = new_v
        self.candidates = keep
        self._last = new_last
        return keep

    def first_scan_transformed(self, display_value, expr, vtype='i32'):
        """混淆值搜索：游戏显示 display_value，但内存存的是变换后的值。
        如 findx 100 *8 → 实际搜索 800。"""
        to_stored, _ = parse_transform(expr)
        stored = to_stored(display_value)
        return self.first_scan(int(stored), vtype)

    def next_scan_delta_transformed(self, display_delta, expr, vtype='i32'):
        """差值过滤（混淆版）：显示值变化了 display_delta。
        如显示 +10、变换 *8 → 内存差值 +80。"""
        to_stored, _ = parse_transform(expr)
        stored_delta = to_stored(display_delta) - to_stored(0)
        return self.next_scan_delta(stored_delta, vtype)

    def write_transformed(self, addr, display_value, expr, vtype='i32'):
        """按显示值写入（自动换算成内存值）。"""
        to_stored, _ = parse_transform(expr)
        return self.write(addr, int(to_stored(display_value)), vtype)

    def set_candidates(self, addrs, vtype='i32'):
        """手动设定候选列表（向导收敛后用），同时重建差值跟踪状态。"""
        fmt, size = FMT[vtype]
        self.candidates = list(addrs)
        self._last = {}
        for a in addrs:
            buf = self.backend.read(a, size)
            if buf and len(buf) == size:
                self._last[a] = struct.unpack(fmt, buf)[0]
        return self.candidates

    def first_scan_multi(self, value):
        """向导用：对 i32/u32/f32/i64 首搜，返回 {类型: 候选}。
        用户不用猜类型，哪个收敛看哪个。
        - 用户输入是 float（如 500.0），整数类型先规整成 int，
          否则 struct.pack('<i', 500.0) 抛 struct.error
        - 字节完全相同的 needle（如 500 的 i32/u32）只扫一次，共享结果
        - 结束后清空 _last：它只剩最后一次扫描的类型快照，
          留下会让后续 next_scan_delta 用错基线"""
        result = {}
        done_needles = {}  # needle bytes -> 已扫过的 vtype
        for vtype in ('i32', 'u32', 'f32', 'i64'):
            v = normalize_value(value, vtype)
            try:
                needle = pack_value(v, vtype)
            except (struct.error, OverflowError):
                result[vtype] = []
                continue
            if needle in done_needles:
                result[vtype] = list(result[done_needles[needle]])
                continue
            done_needles[needle] = vtype
            try:
                result[vtype] = self.first_scan(v, vtype)
            except (struct.error, OverflowError):
                result[vtype] = []
        self._last = {}
        self.candidates = []  # 与 _last 保持一致，避免残留上一轮 i64 候选
        return result

    def next_scan_multi(self, prev, value):
        """向导用：对上一轮每种类型的候选做过滤。
        prev: {vtype: [addrs]}，返回同结构。"""
        result = {}
        for vtype, addrs in prev.items():
            self.candidates = list(addrs)
            try:
                result[vtype] = self.next_scan(
                    normalize_value(value, vtype), vtype)
            except (struct.error, OverflowError):
                result[vtype] = []
        self.candidates = []
        return result

    def first_scan_fuzzy(self, value, vtype='f32', epsilon=0.01):
        """模糊搜索：|内存值 - value| < epsilon 即命中。
        坐标这种浮点数，精确搜经常搜不到（3.14 存成 3.1400001）。"""
        fmt, size = FMT[vtype]
        found = []
        for start, end in self.backend.regions():
            addr = start
            CHUNK = 1 << 20
            while addr < end:
                chunk_end = min(addr + CHUNK, end)
                buf = self.backend.read(addr, chunk_end - addr)
                if buf:
                    # 按类型宽度步进（实际数值都是按自身宽度对齐存放的）
                    for off in range(0, len(buf) - size + 1, size):
                        v = struct.unpack_from(fmt, buf, off)[0]
                        if abs(v - value) < epsilon:
                            found.append(addr + off)
                if chunk_end >= end:
                    break
                addr = chunk_end - (size - 1)
        seen, uniq = set(), []
        for a in found:
            if a not in seen:
                seen.add(a)
                uniq.append(a)
        self.candidates = uniq
        return uniq

    def next_scan_fuzzy(self, value, vtype='f32', epsilon=0.01):
        """模糊过滤：在候选里保留约等于 value 的。"""
        fmt, size = FMT[vtype]
        keep = []
        for addr in self.candidates:
            buf = self.backend.read(addr, size)
            if buf and len(buf) == size:
                v = struct.unpack(fmt, buf)[0]
                if abs(v - value) < epsilon:
                    keep.append(addr)
        self.candidates = keep
        return keep

    def write(self, addr, value, vtype='i32'):
        """往地址写新值。返回 True/False。"""
        return self.backend.write(addr, pack_value(value, vtype))

    def read(self, addr, vtype='i32'):
        """读地址当前值（验证用）。"""
        fmt, size = FMT[vtype]
        buf = self.backend.read(addr, size)
        return unpack_value(buf, vtype) if buf else None
