#!/usr/bin/env python3
"""核心精度测试：混淆值搜索 / 差值过滤 / 混淆写入"""
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memscan import LinuxBackend, Scanner, parse_transform

STATUS = "/tmp/fakegame_status.json"
HERE = os.path.dirname(os.path.abspath(__file__))


def read_status():
    with open(STATUS) as f:
        return json.load(f)


def wait_change(key, old, timeout=25):
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
        vals = {}
        while not all(k in vals for k in ("pid", "secret")):
            line = game.stdout.readline()
            m = re.match(r"PID=(\d+)", line)
            if m:
                vals["pid"] = int(m.group(1))
            m = re.match(r"TRUTH_SECRET=(0x[0-9a-f]+)", line)
            if m:
                vals["secret"] = int(m.group(1), 16)
        pid, truth = vals["pid"], vals["secret"]
        print(f"[t3] PID={pid}，混淆值真地址=0x{truth:x}")

        while not os.path.exists(STATUS):
            time.sleep(0.2)

        be = LinuxBackend(pid)
        sc = Scanner(be)

        # ---- 1. 变换解析 ----
        to_stored, to_display = parse_transform("*8")
        assert to_stored(100) == 800 and to_display(800) == 100
        to_stored2, to_display2 = parse_transform("*8+10")
        assert to_stored2(100) == 810 and to_display2(810) == 100
        print("[t3] 变换解析 ✅（*8，*8+10）")

        # ---- 2. 混淆值首搜：显示 100，实际搜 800 ----
        s0 = read_status()["secret_display"]
        c = sc.first_scan_transformed(s0, "*8", "i32")
        print(f"[t3] 混淆首搜（显示={s0}→内存={s0 * 8}）: {len(c)} 个候选，"
              f"真地址在其中: {truth in c}")
        assert truth in c, "混淆搜索没找到真地址"

        # ---- 3. 混淆差值过滤 ----
        s1 = wait_change("secret_display", s0)
        d = s1 - s0
        c2 = sc.next_scan_delta_transformed(d, "*8", "i32")
        print(f"[t3] 显示 {s0}->{s1}（差值{d}），内存差值{d * 8}，"
              f"剩 {len(c2)} 个候选，真地址在其中: {truth in c2}")
        assert truth in c2, "混淆差值过滤丢了真地址"

        # ---- 4. 混淆写入：按显示值写 ----
        assert sc.write_transformed(truth, 200, "*8", "i32")
        raw = sc.read(truth, "i32")
        assert raw == 1600, f"内存应为1600，读到{raw}"
        print(f"[t3] write_transformed 显示值200 → 内存{raw} ✅")

        # ---- 5. 普通差值过滤（金币） ----
        g0 = read_status()["gold"]
        sc2 = Scanner(be)
        sc2.first_scan(g0, "i32")
        g1 = wait_change("gold", g0)
        c3 = sc2.next_scan_delta(g1 - g0, "i32")
        print(f"[t3] 金币 {g0}->{g1}（差值{g1 - g0}），剩 {len(c3)} 个候选")
        assert len(c3) >= 1, "差值过滤全灭了"
        print("[t3] 普通差值过滤 ✅")

        be.close()
        print("\n核心精度测试全过 ✅")
    finally:
        game.terminate()
        game.wait()


if __name__ == "__main__":
    main()
