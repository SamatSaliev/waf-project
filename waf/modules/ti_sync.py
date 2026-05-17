"""
ti_sync.py — синхронизация WAF blocklist с Threat Intelligence платформой POKS.

Каждые TI_SYNC_INTERVAL секунд запрашивает /api/feed из TI,
фильтрует IP с score > TI_SCORE_THRESHOLD и добавляет их в blocklist WAF.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("waf.ti_sync")

TI_BASE_URL       = os.getenv("TI_BASE_URL", "http://TI_IP:8000")
TI_SYNC_INTERVAL  = int(os.getenv("TI_SYNC_INTERVAL", "300"))   # секунд (5 минут)
TI_SCORE_THRESHOLD= int(os.getenv("TI_SCORE_THRESHOLD", "50"))   # минимальный score для блокировки
TI_ENABLED        = os.getenv("TI_ENABLED", "true").lower() == "true"


class TISync:
    def __init__(self, ip_filter, db_path: str) -> None:
        self.ip_filter  = ip_filter
        self.db_path    = db_path
        self._running   = False
        self._synced: set[str] = set()   # уже добавленные IP (кэш)

    async def start(self) -> None:
        """Запускает фоновую задачу синхронизации."""
        if not TI_ENABLED:
            logger.info("TI Sync отключён (TI_ENABLED=false)")
            return
        self._running = True
        logger.info(
            "TI Sync запущен | URL: %s | интервал: %ds | порог score: %d",
            TI_BASE_URL, TI_SYNC_INTERVAL, TI_SCORE_THRESHOLD,
        )
        asyncio.create_task(self._loop())

    async def _loop(self) -> None:
        while self._running:
            try:
                await self._sync()
            except Exception as e:
                logger.error("TI Sync ошибка: %s", e)
            await asyncio.sleep(TI_SYNC_INTERVAL)

    async def _sync(self) -> None:
        """Один цикл синхронизации."""
        logger.info("TI Sync: запрос к %s/api/feed ...", TI_BASE_URL)
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
                resp = await client.get(f"{TI_BASE_URL}/api/feed")
                resp.raise_for_status()
                feed: list[dict] = resp.json()
        except Exception as e:
            logger.error("TI Sync: не удалось получить feed: %s", e)
            return

        added   = 0
        skipped = 0

        for item in feed:
            ip    = item.get("ip", "").strip()
            score = int(item.get("score", 0))

            if not ip or score < TI_SCORE_THRESHOLD:
                skipped += 1
                continue

            if ip in self._synced:
                skipped += 1
                continue

            comment = (
                f"TI auto-block | score={score} | "
                f"events={item.get('events','?')} | "
                f"country={item.get('country','?')} | "
                f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
            )

            try:
                await self.ip_filter.add_ip(ip, "block", comment)
                self._synced.add(ip)
                added += 1
                logger.warning(
                    "TI Sync: БЛОКИРОВАН %s (score=%d, country=%s)",
                    ip, score, item.get("country", "?"),
                )
            except Exception as e:
                logger.error("TI Sync: ошибка добавления %s: %s", ip, e)

        logger.info(
            "TI Sync завершён: добавлено=%d, пропущено=%d, всего в feed=%d",
            added, skipped, len(feed),
        )

    async def sync_now(self) -> dict:
        """Принудительная синхронизация (вызывается через API)."""
        await self._sync()
        return {
            "status":    "ok",
            "synced_ips": len(self._synced),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def stop(self) -> None:
        self._running = False
