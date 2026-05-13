"""
ip_filter.py — управление IP allowlist и blocklist.

Списки хранятся в SQLite и кэшируются в памяти.
Обновление через дашборд вызывает reload().
"""

from __future__ import annotations

import asyncio
from typing import Literal

import aiosqlite

IpAction = Literal["allow", "block"]


class IpFilter:
    def __init__(self, db_path: str) -> None:
        self.db_path   = db_path
        self._blocklist: set[str] = set()
        self._allowlist: set[str] = set()
        self._lock = asyncio.Lock()

    async def load(self) -> None:
        """Загружает IP-листы из БД в память."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT ip, action FROM ip_lists WHERE enabled = 1"
            ) as cur:
                rows = await cur.fetchall()

        async with self._lock:
            self._blocklist.clear()
            self._allowlist.clear()
            for ip, action in rows:
                if action == "block":
                    self._blocklist.add(ip)
                elif action == "allow":
                    self._allowlist.add(ip)

    async def check(self, ip: str) -> tuple[str, str]:
        """
        Проверяет IP против списков.

        Возвращает (action, reason):
          action: 'block' | 'allow' | 'pass'
          reason: описание причины
        """
        async with self._lock:
            if ip in self._allowlist:
                return "allow", "IP в allowlist"
            if ip in self._blocklist:
                return "block", "IP в blocklist"
        return "pass", ""

    async def add_ip(self, ip: str, action: IpAction, comment: str = "") -> None:
        """Добавляет IP в список и перезагружает кэш."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """INSERT INTO ip_lists (ip, action, comment, enabled)
                   VALUES (?, ?, ?, 1)
                   ON CONFLICT(ip) DO UPDATE SET
                     action  = excluded.action,
                     comment = excluded.comment,
                     enabled = 1""",
                (ip, action, comment),
            )
            await db.commit()
        await self.load()

    async def remove_ip(self, ip: str) -> None:
        """Удаляет IP из любого списка."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM ip_lists WHERE ip = ?", (ip,))
            await db.commit()
        await self.load()

    async def get_all(self) -> list[dict]:
        """Возвращает все записи для отображения в дашборде."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT ip, action, comment, enabled, created_at FROM ip_lists ORDER BY created_at DESC"
            ) as cur:
                rows = await cur.fetchall()
        return [dict(r) for r in rows]
