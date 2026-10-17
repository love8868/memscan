#!/usr/bin/env python3
"""地址锁定：后台线程定时重写，防止游戏把值改回去（CE 的 freeze 功能）。"""
import threading
import time

from memscan import pack_value


class Locker:
    def __init__(self, backend, interval=0.1):
        self.backend = backend
        self.interval = interval
        self._locks = {}  # addr -> (bytes, vtype)
        self._stop = threading.Event()
        self._thread = None
        self._mtx = threading.Lock()

    def add(self, addr, value, vtype='i32'):
        """锁定地址：每 interval 秒写一次 value。"""
        with self._mtx:
            self._locks[addr] = (pack_value(value, vtype), vtype)
        self._ensure_running()
        return True

    def remove(self, addr):
        with self._mtx:
            self._locks.pop(addr, None)
            empty = not self._locks
        if empty:
            self.stop()

    def list(self):
        with self._mtx:
            return dict(self._locks)

    def clear(self):
        self.stop()
        with self._mtx:
            self._locks.clear()

    def _ensure_running(self):
        if self._thread is None or not self._thread.is_alive():
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()

    def _loop(self):
        while not self._stop.wait(self.interval):
            with self._mtx:
                items = list(self._locks.items())
            for addr, (data, _vtype) in items:
                try:
                    self.backend.write(addr, data)
                except OSError:
                    pass

    def stop(self):
        self._stop.set()
        t, self._thread = self._thread, None
        if t and t.is_alive():
            t.join(timeout=1.0)
