#!/usr/bin/env python3
"""
假游戏：模拟一个单机游戏进程，供扫描器测试/练手用。

内存布局（GameData 结构）：
  health          血量（int，会波动）
  gold            金币（int，会波动）
  pos_x           X 坐标（float，漂移）
  tech_points     科研点数（int，每 3 tick 消耗 10 点）
  research_timer  研究剩余秒数（int，每 tick -2，归零则随机科技升级）
  tech_levels[4]  4 个科技等级（int 数组，连续存放）

练手路线：
  1. 科研点数 → find 精确搜索（500 → 等变成 490 → 过滤 → lock）
  2. 研究计时器 → ufind 未知搜索（decreased，一路变小）
  3. 科技等级 → find 某个等级数字 → 找到后看相邻地址（数组规律）
"""
import ctypes
import json
import os
import random
import time

STATUS = "/tmp/fakegame_status.json"


class GameData(ctypes.Structure):
    _fields_ = [
        ("health", ctypes.c_int32),
        ("gold", ctypes.c_int32),
        ("pos_x", ctypes.c_float),
        ("tech_points", ctypes.c_int32),
        ("research_timer", ctypes.c_int32),
        ("tech_levels", ctypes.c_int32 * 4),
        ("secret", ctypes.c_int32),  # 混淆值：内存存的是 显示值*8
    ]


data = GameData(100, 500, 10.5, 500, 30, (3, 2, 5, 1), 800)
base = ctypes.addressof(data)


def dump_status():
    with open(STATUS, "w") as f:
        json.dump({"health": data.health,
                   "gold": data.gold,
                   "pos_x": data.pos_x,
                   "tech_points": data.tech_points,
                   "research_timer": data.research_timer,
                   "tech_levels": list(data.tech_levels),
                   "secret_display": data.secret // 8,  # 显示值
                   "pid": os.getpid()}, f)


print(f"PID={os.getpid()}", flush=True)
print(f"TRUTH_HEALTH=0x{base + GameData.health.offset:x}", flush=True)
print(f"TRUTH_GOLD=0x{base + GameData.gold.offset:x}", flush=True)
print(f"TRUTH_POSX=0x{base + GameData.pos_x.offset:x}", flush=True)
print(f"TRUTH_TECH_POINTS=0x{base + GameData.tech_points.offset:x}", flush=True)
print(f"TRUTH_TIMER=0x{base + GameData.research_timer.offset:x}", flush=True)
print(f"TRUTH_TECH0=0x{base + GameData.tech_levels.offset:x}", flush=True)
print(f"TRUTH_SECRET=0x{base + GameData.secret.offset:x}", flush=True)
dump_status()

random.seed(1234)  # 固定种子，行为可复现
tick = 0
while True:
    time.sleep(2)
    tick += 1
    # 注意：这里读的是 data.health 的"当前值"再加减——
    # 如果外部往内存写了新值，下一 tick 就会基于新值继续算，
    # 这正是"注入值被游戏逻辑消费"的证明点。
    data.health = max(1, data.health + random.choice([-15, -10, -5, 25]))
    data.gold += random.choice([-50, 100])
    data.pos_x += 0.5

    # --- 科技系统 ---
    if data.research_timer > 0:
        data.research_timer = max(0, data.research_timer - 2)
        if data.research_timer == 0:
            idx = random.randrange(4)
            data.tech_levels[idx] += 1
            data.tech_points = max(0, data.tech_points - 50)
            print(f"[game] 研究完成！科技[{idx}] 升到 "
                  f"Lv.{data.tech_levels[idx]}", flush=True)
            data.research_timer = 30  # 开始下一项
    if tick % 3 == 0:
        # 每 3 tick 消耗 10 点科研点（维持研究开销）
        data.tech_points = max(0, data.tech_points - 10)
    if tick % 4 == 0:
        # 混淆值：显示值变化，内存按 *8 存
        data.secret += 8 * random.choice([-5, 10])

    dump_status()
    print(f"[game] health={data.health} gold={data.gold} "
          f"tech_pts={data.tech_points} timer={data.research_timer}s "
          f"techs={list(data.tech_levels)} secret~{data.secret // 8}",
          flush=True)
