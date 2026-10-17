#!/usr/bin/env python3
"""新功能测试：未知值搜索 / 锁定 / CT表 / 模糊浮点"""
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memscan import LinuxBackend, Scanner
import cheattable
from locker import Locker
from unknown_scan import UnknownScanner

STATUS = "/tmp/fakegame_status.json"
HERE = os.path.dirname(os.path.abspath(__file__))


def read_status():
    with open(STATUS) as f:
        return json.load(f)


def wait_change(key, old, timeout=20):
    t0 = time.time()
    while time.time() - t0 < timeout:
        v = read_status()[key]
        if v != old:
            return v
        time.sleep(0.3)
    raise TimeoutError(f"{key} 没变化")


def main():
    if os.path.exists(STATUS):
        os.remove(STATUS)
    game = subprocess.Popen(
        [sys.executable, "fakegame.py"],
        stdout=subprocess.PIPE, text=True, bufsize=1, cwd=HERE)
    try:
        pid = truth_h = truth_x = None
        while not (pid and truth_h and truth_x):
            line = game.stdout.readline()
            m = re.search(r"PID=(\d+)", line)
            if m:
                pid = int(m.group(1))
            m = re.search(r"TRUTH_HEALTH=(0x[0-9a-f]+)", line)
            if m:
                truth_h = int(m.group(1), 16)
            m = re.search(r"TRUTH_POSX=(0x[0-9a-f]+)", line)
            if m:
                truth_x = int(m.group(1), 16)
        print(f"[t2] PID={pid}")

        while not os.path.exists(STATUS):
            time.sleep(0.2)

        be = LinuxBackend(pid)
        sc = Scanner(be)

        # ---- 1. 未知值搜索 ----
        us = UnknownScanner(be)
        nbytes = us.snapshot()
        print(f"[t2] 快照 {nbytes // 1024} KB")
        h0 = read_status()["health"]
        h1 = wait_change("health", h0)
        mode = "increased" if h1 > h0 else "decreased"
        print(f"[t2] 血量 {h0} -> {h1}，用 {mode} 过滤")
        hits = us.compare(mode, "i32")
        print(f"[t2] {mode}: 剩 {len(hits)} 个候选，真地址在其中: {truth_h in hits}")
        assert truth_h in hits, "未知值搜索没找到真地址"
        # 反向验证：等值真变了，unchanged 不应包含它
        us2 = UnknownScanner(be)
        us2.snapshot()
        h_a = read_status()["health"]
        wait_change("health", h_a)
        hits2 = us2.compare("unchanged", "i32")
        assert truth_h not in hits2, "unchanged 误报了变化的地址"
        print("[t2] 未知值搜索 ✅（正向命中 + 反向排除）")

        # ---- 2. 锁定 ----
        lk = Locker(be, interval=0.05)
        lk.add(truth_h, 9999, "i32")
        time.sleep(2.6)  # 覆盖至少一次游戏 tick
        cur = sc.read(truth_h, "i32")
        print(f"[t2] 锁定中读回血量={cur}（应为9999）")
        assert cur == 9999, "锁定失效，游戏把值改回去了"
        lk.remove(truth_h)
        h2 = wait_change("health", 9999)
        print(f"[t2] 解除锁定后血量变为 {h2}，锁定/解锁 ✅")
        lk.stop()

        # ---- 3. CT 表 ----
        entries = [cheattable.entry("血量", truth_h, "i32", locked=True),
                   cheattable.entry("坐标X", truth_x, "f32")]
        p = "/tmp/test_ct.json"
        cheattable.save(p, entries)
        back = cheattable.load(p)
        assert len(back) == 2 and back[0]["addr"] == hex(truth_h)
        print("[t2] CT表存取 ✅")

        # ---- 4. 模糊浮点 ----
        x0 = read_status()["pos_x"]
        c = sc.first_scan_fuzzy(x0, "f32", epsilon=0.05)
        print(f"[t2] 模糊搜坐标 {x0}: {len(c)} 个候选，真地址在其中: {truth_x in c}")
        assert truth_x in c, "模糊搜索没找到坐标"
        print("[t2] 模糊浮点 ✅")

        be.close()
        print("\n新功能全部通过 ✅")
    finally:
        game.terminate()
        game.wait()


if __name__ == "__main__":
    main()
