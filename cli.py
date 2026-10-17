#!/usr/bin/env python3
"""
memscan 交互式命令行 —— CE 替代版的操作台。

核心设计：向导式自动化。用户只回答"现在是多少"、"变了没"，
类型猜测、多轮过滤、候选推荐全部自动。

命令：
  attach <pid|进程名>   附加目标进程（Linux 用 pid，Windows 用进程名）
  find                 向导：精确数值查找（自动试全部类型）
  ufind                向导：未知数值查找（血条看不到数字时用）
  list                 显示当前候选
  write <序号> <值>     修改候选地址的值
  lock <序号> <值>      锁定候选地址（定时重写）
  unlock <序号>         解除锁定
  locks                显示锁定列表
  save <文件>          保存 CT 表（JSON）
  load <文件>          加载 CT 表并自动锁定其中标记的项
  pointers <序号>      找指向该地址的指针
  type <类型>          设置默认类型（i32/u32/f32/i64）
  quit                 退出
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memscan import LinuxBackend, WindowsBackend, Scanner
import cheattable
from locker import Locker
from unknown_scan import UnknownScanner

PROMPT = "memscan> "


class Shell:
    def __init__(self):
        self.backend = None
        self.sc = None
        self.locker = None
        self.usc = None
        self.candidates = []      # [(addr, vtype), ...] 当前候选
        self.multi = {}           # 向导多类型中间态 {vtype: [addrs]}
        self.vtype = "i32"
        self.table_path = None
        self.transform = None     # (expr, to_display) 混淆变换（findx 用）

    # ---------- 基础 ----------
    def cmd_attach(self, arg):
        self._close()
        if os.name == "nt":
            self.backend = WindowsBackend(arg)
            print(f"已附加到进程 {arg}")
        else:
            pid = int(arg)
            self.backend = LinuxBackend(pid)
            print(f"已附加到 PID {pid}")
        self.sc = Scanner(self.backend)
        self.locker = Locker(self.backend)
        self.usc = UnknownScanner(self.backend)

    def _close(self):
        if self.locker:
            self.locker.clear()
        if self.backend:
            try:
                self.backend.close()
            except Exception:
                pass
        self.backend = self.sc = self.locker = self.usc = None
        self.candidates, self.multi = [], {}

    def _need(self):
        if not self.backend:
            print("先 attach 一个进程：attach <pid|进程名>")
            return False
        return True

    # ---------- 向导：精确查找 ----------
    def cmd_find(self, _arg):
        """向导式精确查找：自动试全部类型，用户只管报数。"""
        if not self._need():
            return
        try:
            v0 = float(input("现在的数值是多少？ "))
        except ValueError:
            print("输入数字")
            return
        print("正在并行扫描 i32/u32/f32/i64 ...")
        self.multi = self.sc.first_scan_multi(v0)
        for t, c in self.multi.items():
            print(f"  {t}: {len(c)} 个候选")
        self._find_round(v0)

    def _find_round(self, _v0):
        while True:
            # 哪个类型收敛得最好，推荐哪个
            best = min(self.multi.items(), key=lambda kv: len(kv[1]))
            total = sum(len(c) for c in self.multi.values())
            if total == 0:
                print("所有类型都没命中，数值输错了？重来：find")
                self.multi = {}
                return
            if len(best[1]) <= 3:
                self.candidates = [(a, best[0]) for a in best[1]]
                self.sc.set_candidates(best[1], best[0])  # 重建差值跟踪
                self.transform = None
                print(f"\n✅ 锁定类型 {best[0]}，剩 {len(best[1])} 个候选：")
                self.cmd_list("")
                print("用 write <序号> <值> 修改，或 lock <序号> <值> 锁定")
                self.multi = {}
                return
            print(f"\n当前最有希望：{best[0]}（{len(best[1])} 个），"
                  f"共 {total} 个候选")
            nxt = input("去游戏里改变数值，输入新数值后回车（q 退出）：").strip()
            if nxt.lower() == 'q':
                return
            try:
                v1 = float(nxt)
            except ValueError:
                print("输入数字")
                continue
            self.multi = self.sc.next_scan_multi(self.multi, v1)
            for t, c in self.multi.items():
                print(f"  {t}: {len(c)} 个候选")

    # ---------- 向导：未知数值查找 ----------
    def cmd_ufind(self, _arg):
        """未知数值（血条）查找：快照 -> 变 -> 比较，循环。"""
        if not self._need():
            return
        print("正在拍内存快照 ...")
        nbytes = self.usc.snapshot()
        print(f"快照完成（{nbytes // 1024} KB）。去游戏里改变数值（比如被打一下），")
        input("好了回车 ...")
        while True:
            print("\n数值怎么变的？ changed=变了 unchanged=没变 "
                  "increased=变大 decreased=变小 (q 退出)")
            mode = input("选择: ").strip().lower()
            if mode == 'q':
                return
            if mode not in ('changed', 'unchanged', 'increased', 'decreased'):
                print("输入 changed/unchanged/increased/decreased")
                continue
            t = input("类型？i32=整数 f32=小数 [i32]: ").strip() or "i32"
            if t not in ('i32', 'f32'):
                print("只支持 i32/f32")
                continue
            hits = self.usc.compare(mode, t)
            print(f"剩 {len(hits)} 个候选")
            if len(hits) <= 5:
                self.candidates = [(a, t) for a in hits]
                print("✅ 候选：")
                self.cmd_list("")
                print("用 write <序号> <值> 逐个试（改完看游戏里变没变）")
                return
            if len(hits) == 0:
                print("没命中，可能刚才数值其实没变，重来：ufind")
                return
            input("再去游戏里改变数值，好了回车 ...")

    # ---------- 混淆值 & 差值 ----------
    def cmd_findx(self, arg):
        """混淆值搜索：findx <显示值> <变换>，如 findx 100 *8。
        游戏显示 100，但内存存的是 800 时用。"""
        if not self._need():
            return
        parts = arg.split()
        if len(parts) != 2:
            print("用法：findx <显示值> <变换>，如 findx 100 *8")
            return
        try:
            disp = float(parts[0])
            expr = parts[1]
            from memscan import parse_transform
            _, to_display = parse_transform(expr)
        except ValueError as e:
            print(e)
            return
        print(f"正在搜索 显示值={disp} 变换={expr} ...")
        c = self.sc.first_scan_transformed(disp, expr, self.vtype)
        print(f"首搜 {len(c)} 个候选。去游戏里改变显示值，")
        nd = input("输入显示值变化量（如花了50金币就输 -50，q 退出）：").strip()
        if nd.lower() == 'q':
            return
        try:
            delta = float(nd)
        except ValueError:
            print("输入数字")
            return
        c2 = self.sc.next_scan_delta_transformed(delta, expr, self.vtype)
        print(f"差值过滤后剩 {len(c2)} 个候选")
        self.candidates = [(a, self.vtype) for a in c2]
        self.transform = (expr, to_display)
        self.cmd_list("")

    def cmd_writex(self, arg):
        """按显示值写入：writex <序号> <显示值>（自动换算）。"""
        if not self.transform:
            print("先用 findx 确定变换关系")
            return
        parts = arg.split()
        if len(parts) != 2:
            print("用法：writex <序号> <显示值>")
            return
        pick = self._pick(parts[0])
        if not pick:
            return
        addr, t = pick
        expr, _ = self.transform
        try:
            disp = float(parts[1])
        except ValueError:
            print("输入数字")
            return
        ok = self.sc.write_transformed(addr, disp, expr, t)
        print(f"{'✅' if ok else '❌'} 0x{addr:x} <- 显示值 {disp}")

    def cmd_by(self, arg):
        """差值过滤：by <差值>，如 by -50（花了50）。
        只保留"变化量正好等于差值"的候选，比"变小了"精确得多。"""
        if not self._need():
            return
        if not self.candidates:
            print("没有候选。先 find。")
            return
        try:
            delta = float(arg.strip())
        except ValueError:
            print("用法：by <差值>，如 by -50")
            return
        t = self.candidates[0][1]
        if self.transform:
            expr, _ = self.transform
            c = self.sc.next_scan_delta_transformed(delta, expr, t)
        else:
            # 整数差值转 int（浮点差值保持 float）
            d = int(delta) if t != 'f32' and delta == int(delta) else delta
            c = self.sc.next_scan_delta(d, t)
        print(f"差值过滤后剩 {len(c)} 个候选")
        self.candidates = [(a, t) for a in c]
        self.cmd_list("")

    # ---------- 候选操作 ----------
    def cmd_list(self, _arg):
        if not self.candidates:
            print("没有候选。先 find 或 ufind。")
            return
        for i, (a, t) in enumerate(self.candidates):
            cur = self.sc.read(a, t)
            if self.transform and cur is not None:
                _, to_display = self.transform
                print(f"  [{i}] 0x{a:x} ({t}) 显示值={to_display(cur):g} "
                      f"(内存值={cur})")
            else:
                print(f"  [{i}] 0x{a:x} ({t}) 当前值={cur}")

    def _pick(self, idx):
        try:
            i = int(idx)
            return self.candidates[i]
        except (ValueError, IndexError):
            print(f"序号 0~{len(self.candidates) - 1}")
            return None

    def cmd_write(self, arg):
        if not self._need():
            return
        parts = arg.split()
        if len(parts) != 2:
            print("用法：write <序号> <值>")
            return
        pick = self._pick(parts[0])
        if not pick:
            return
        addr, t = pick
        val = float(parts[1]) if t == 'f32' else int(float(parts[1]))
        ok = self.sc.write(addr, val, t)
        print(f"{'✅' if ok else '❌'} 0x{addr:x} <- {val} "
              f"(回读={self.sc.read(addr, t)})")

    def cmd_lock(self, arg):
        if not self._need():
            return
        parts = arg.split()
        if len(parts) != 2:
            print("用法：lock <序号> <值>")
            return
        pick = self._pick(parts[0])
        if not pick:
            return
        addr, t = pick
        val = float(parts[1]) if t == 'f32' else int(float(parts[1]))
        self.locker.add(addr, val, t)
        print(f"✅ 已锁定 0x{addr:x} = {val}（每 0.1s 重写）")

    def cmd_unlock(self, arg):
        if not self._need():
            return
        pick = self._pick(arg.strip())
        if not pick:
            return
        self.locker.remove(pick[0])
        print("已解除锁定")

    def cmd_locks(self, _arg):
        if not self._need():
            return
        locks = self.locker.list()
        if not locks:
            print("没有锁定项")
            return
        for a, (data, t) in locks.items():
            print(f"  0x{a:x} ({t})")

    def cmd_type(self, arg):
        if arg.strip() in ('i32', 'u32', 'f32', 'i64'):
            self.vtype = arg.strip()
            print(f"默认类型 -> {self.vtype}")
        else:
            print("用法：type <i32|u32|f32|i64>")

    # ---------- CT 表 ----------
    def cmd_save(self, arg):
        path = arg.strip() or "cheatable.json"
        entries = []
        for i, (a, t) in enumerate(self.candidates):
            entries.append(cheattable.entry(f"addr_{i}", a, t))
        for a, (data, t) in self.locker.list().items():
            entries.append(cheattable.entry(f"lock_{a:x}", a, t,
                                           locked=True))
        cheattable.save(path, entries)
        self.table_path = path
        print(f"✅ 已保存 {len(entries)} 项到 {path}")

    def cmd_load(self, arg):
        if not self._need():
            return
        path = arg.strip() or "cheatable.json"
        entries = cheattable.load(path)
        if not entries:
            print(f"{path} 为空或不存在")
            return
        self.candidates = [(int(e["addr"], 16), e.get("vtype", "i32"))
                           for e in entries]
        n_lock = 0
        for e in entries:
            if e.get("locked"):
                # lock_value 没存的话，读当前值锁定
                a = int(e["addr"], 16)
                t = e.get("vtype", "i32")
                v = self.sc.read(a, t)
                if v is not None:
                    self.locker.add(a, v, t)
                    n_lock += 1
        print(f"✅ 加载 {len(entries)} 项，其中 {n_lock} 个恢复锁定")
        self.cmd_list("")

    def cmd_pointers(self, arg):
        if not self._need():
            return
        pick = self._pick(arg.strip())
        if not pick:
            return
        addr, _t = pick
        print("正在扫描指针 ...")
        ptrs = self.backend.find_pointers(addr)
        print(f"找到 {len(ptrs)} 个指向 0x{addr:x} 的指针：")
        for p in ptrs[:10]:
            print(f"  0x{p:x}")
        if len(ptrs) > 10:
            print(f"  ... 还有 {len(ptrs) - 10} 个")

    # ---------- 主循环 ----------
    CMDS = ("attach find ufind findx list write writex lock unlock locks "
            "by save load pointers type quit help").split()

    def cmd_help(self, _arg):
        print("命令: " + ", ".join(self.CMDS))

    def run(self):
        print("memscan —— 输入 help 看命令，quit 退出")
        while True:
            try:
                line = input(PROMPT).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            cmd, _, arg = line.partition(" ")
            fn = getattr(self, "cmd_" + cmd, None)
            if cmd == "quit":
                break
            if fn:
                try:
                    fn(arg)
                except Exception as e:
                    print(f"出错：{e}")
            else:
                print(f"未知命令 {cmd}，输入 help")
        self._close()
        print("bye")


if __name__ == "__main__":
    Shell().run()
