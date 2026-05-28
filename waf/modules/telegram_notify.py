"""
telegram_notify.py — отправка уведомлений об инцидентах WAF в Telegram.

Уведомления отправляются при:
  - создании нового инцидента correlator'ом
  - блокировке IP через TI sync
  - превышении rate limit (опционально)
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("waf.telegram")

TG_TOKEN      = os.getenv("TG_BOT_TOKEN", "")
TG_CHAT_ID    = os.getenv("TG_CHAT_ID", "")
TG_ENABLED    = os.getenv("TG_ENABLED", "true").lower() == "true"
TG_API_URL    = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"

# Иконки по severity
SEVERITY_ICONS = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
}

# Иконки по типу инцидента
INCIDENT_ICONS = {
    "BRUTE_FORCE":        "🔨",
    "SQLI_ATTACK":        "💉",
    "XSS_ATTACK":         "⚡",
    "SCANNING":           "🔍",
    "DISTRIBUTED_ATTACK": "🌐",
}


class TelegramNotifier:
    def __init__(self) -> None:
        self._enabled = TG_ENABLED and bool(TG_TOKEN) and bool(TG_CHAT_ID)
        if not self._enabled:
            logger.warning(
                "Telegram уведомления отключены. "
                "Проверьте TG_BOT_TOKEN и TG_CHAT_ID."
            )
        else:
            logger.info(
                "Telegram уведомления включены → chat_id=%s", TG_CHAT_ID
            )

    async def send_incident(self, incident: dict) -> None:
        """Отправляет уведомление о новом инциденте."""
        if not self._enabled:
            return

        sev_icon  = SEVERITY_ICONS.get(incident.get("severity", ""), "⚠️")
        inc_icon  = INCIDENT_ICONS.get(incident.get("rule_id", ""), "🚨")
        ts        = incident.get("timestamp", "")[:19].replace("T", " ")

        text = (
            f"{inc_icon} *ИНЦИДЕНТ WAF* {sev_icon}\n"
            f"{'─' * 30}\n"
            f"*Тип:* {incident.get('name', '—')}\n"
            f"*Severity:* `{incident.get('severity', '—').upper()}`\n"
            f"*{incident.get('group_by', 'IP').upper()}:* `{incident.get('group_value', '—')}`\n"
            f"*Событий:* {incident.get('event_count', 0)} / порог {incident.get('threshold', 0)}\n"
            f"*Окно:* {incident.get('window_sec', 0)} сек\n"
            f"*Время:* {ts} UTC\n"
            f"{'─' * 30}\n"
            f"_{incident.get('description', '')}_\n"
            f"\n🛡 *WAF* | Кафедра ПОКС КГТУ"
        )

        await self._send(text)

    async def send_ti_block(self, ip: str, score: int, country: str) -> None:
        """Уведомление о блокировке IP через TI."""
        if not self._enabled:
            return

        text = (
            f"🔒 *TI AUTO-BLOCK*\n"
            f"{'─' * 30}\n"
            f"*IP:* `{ip}`\n"
            f"*Score:* `{score}`\n"
            f"*Страна:* {country}\n"
            f"*Источник:* POKS Threat Intelligence\n"
            f"*Время:* {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC\n"
            f"\n🛡 *WAF* | Кафедра ПОКС КГТУ"
        )

        await self._send(text)

    async def send_rate_limit(self, ip: str, limit: int) -> None:
        """Уведомление о превышении rate limit."""
        if not self._enabled:
            return

        text = (
            f"⚡ *RATE LIMIT EXCEEDED*\n"
            f"{'─' * 30}\n"
            f"*IP:* `{ip}`\n"
            f"*Лимит:* {limit} запросов/мин\n"
            f"*Время:* {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC\n"
            f"\n🛡 *WAF* | Кафедра ПОКС КГТУ"
        )

        await self._send(text)

    async def send_startup(self, mode: str, rate_limit: int) -> None:
        """Уведомление о запуске WAF."""
        if not self._enabled:
            return

        text = (
            f"🟢 *WAF ЗАПУЩЕН*\n"
            f"{'─' * 30}\n"
            f"*Режим:* `{mode.upper()}`\n"
            f"*Rate limit:* {rate_limit} req/min\n"
            f"*Время:* {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC\n"
            f"\n🛡 *WAF* | Кафедра ПОКС КГТУ"
        )

        await self._send(text)

    async def _send(self, text: str) -> None:
        """Отправляет сообщение в Telegram."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(TG_API_URL, json={
                    "chat_id":    TG_CHAT_ID,
                    "text":       text,
                    "parse_mode": "Markdown",
                })
                if resp.status_code != 200:
                    logger.error(
                        "Telegram ошибка %d: %s",
                        resp.status_code, resp.text[:200],
                    )
                else:
                    logger.info("Telegram уведомление отправлено")
        except Exception as e:
            logger.error("Telegram: не удалось отправить: %s", e)
