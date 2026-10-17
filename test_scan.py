#!/usr/bin/env python3
"""
自动化测试：完整跑一遍 CE 式流程
  首搜 -> N 轮窄化 -> 定位真实地址 -> 写入 -> 验证游戏逻辑消费了注入值
"""
import json
import os
import re
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memscan import LinuxBackend, Scanner

STATUS = "/tmp/fakegame_status.json"
HERE = os.path.dirname(os.path.abspath(__file__))


def read_status():
    with open(STATUS) as f:
        return json.load(f)


def wait_health_change(old, timeout=20):
    t0 = time.time()
    while time.time() - t0 < timeout:
        h = read_status()["health"]
        if h != old:
            return h
        time.sleep(0.3)
    raise TimeoutError("血量一直没变，假游戏是不是挂了？")


def main():
    if os.path.exists(STATUS):
        os.remove(STATUS)
    game = subprocess.Popen(
        [sys.executable, "fakegame.py"],
        stdout=subprocess.PIPE, text=True, bufsize=1, cwd=HERE)
    try:
        pid = truth = None
        while not (pid and truth):
            line = game.stdout.readline()
            m = re.search(r"PID=(\d+)", line)
            if m:
                pid = int(m.group(1))
            m = re.search(r"TRUTH_HEALTH=(0x[0-9a-f]+)", line)
            if m:
                truth = int(m.group(1), 16)
        print(f"[test] 假游戏 PID={pid}，真实血量地址=0x{truth:x}")

        while not os.path.exists(STATUS):
            time.sleep(0.2)
        cur = read_status()["health"]
        print(f"[test] 当前血量={cur}")

        be = LinuxBackend(pid)
        sc = Scanner(be)

        t0 = time.time()
        c = sc.first_scan(cur, "i32")
        print(f"[test] 首搜: {len(c)} 个候选 (用时 {time.time() - t0:.1f}s)")

        rounds = 0
        while len(c) > 3 and rounds < 8:
            rounds += 1
            new_h = wait_health_change(cur)
            cur = new_h
            c = sc.next_scan(new_h, "i32")
            print(f"[test] 第{rounds}轮过滤 (血量={new_h}): 剩 {len(c)} 个候选")

        in_list = truth in c
        print(f"[test] 真实地址在候选列表中: {in_list}")
        assert in_list, "扫描器没找到真实地址，逻辑有 bug！"
        assert len(c) <= 5, f"候选太多 ({len(c)})，窄化不充分"

        # --- 写入测试 ---
        assert sc.write(truth, 9999, "i32"), "写入失败"
        back = struct.unpack("<i", be.read(truth, 4))[0]
        assert back == 9999, f"回读={back}，不一致"
        print("[test] 写入 9999 并回读验证通过")

        # --- 端到端：等游戏自己 tick，看它是否基于注入值继续算 ---
        time.sleep(2.5)
        h_after = read_status()["health"]
        print(f"[test] 游戏 tick 后血量={h_after}"
              f"（应为 9999±几十，证明游戏逻辑消费了注入值）")
        assert abs(h_after - 9999) < 100, "游戏没消费注入值？"
        print("[test] 端到端验证通过")

        # --- 指针扫描 smoke test（不强断言，只看能不能跑） ---
        ptrs = be.find_pointers(truth)
        print(f"[test] 指向血量地址的指针找到 {len(ptrs)} 个"
              f"（示例: {[hex(p) for p in ptrs[:3]]}）")

        be.close()
        print("\n全部测试通过 ✅")
    finally:
        game.terminate()
        game.wait()


if __name__ == "__main__":
    main()
