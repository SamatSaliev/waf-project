"""
rate_limiter.py — скользящее окно (sliding window) 60 запросов / минута на IP.

Хранит счётчики в памяти (dict), что достаточно для одного процесса uvicorn.
При необходимости масштабирования замените на Redis.
"""

from __future__ import annotations

import time
from collections import deque
from threading import Lock


class RateLimiter:
    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self.max_requests   = max_requests
        self.window_seconds = window_seconds
        # ip -> deque of timestamps
        self._windows: dict[str, deque] = {}
        self._lock = Lock()

    def is_allowed(self, ip: str) -> tuple[bool, int]:
        """
        Проверяет, не превысил ли IP лимит запросов.

        Возвращает (allowed, remaining):
          allowed   — True если запрос разрешён
          remaining — сколько запросов ещё осталось в текущем окне
        """
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            if ip not in self._windows:
                self._windows[ip] = deque()

            window = self._windows[ip]

            # Удаляем устаревшие метки
            while window and window[0] < cutoff:
                window.popleft()

            count = len(window)

            if count >= self.max_requests:
                return False, 0

            window.append(now)
            return True, self.max_requests - count - 1

    def get_stats(self, ip: str) -> dict:
        """Возвращает текущую статистику для IP (для логов и дашборда)."""
        now    = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            window = self._windows.get(ip, deque())
            recent = sum(1 for ts in window if ts >= cutoff)

        return {
            "ip":           ip,
            "requests":     recent,
            "max_requests": self.max_requests,
            "window_sec":   self.window_seconds,
        }

    def reset(self, ip: str) -> None:
        """Сбрасывает счётчик для IP (для ручного снятия блокировки)."""
        with self._lock:
            self._windows.pop(ip, None)
