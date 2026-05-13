"""
correlator.py — модуль корреляции событий и выявления инцидентов WAF.

Логика корреляции:
  1. Брутфорс-атака      — 10+ заблокированных запросов с одного IP за 60 сек
  2. Сканирование        — 3+ разных типа атак с одного IP за 5 минут
  3. SQL Injection атака — 5+ SQLi событий с одного IP за 2 минуты
  4. XSS атака           — 5+ XSS событий с одного IP за 2 минуты
  5. Распределённая атака— 10+ разных IP атакуют один эндпоинт за 5 минут
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any

import aiosqlite

logger = logging.getLogger("waf.correlator")


# ── Правила корреляции ────────────────────────────────────────────────────────
CORRELATION_RULES = [
    {
        "id":          "BRUTE_FORCE",
        "name":        "Брутфорс-атака",
        "description": "Более 10 заблокированных запросов с одного IP за 60 секунд",
        "severity":    "high",
        "window_sec":  60,
        "threshold":   10,
        "filter":      lambda e: e["action"] == "block",
        "group_by":    "client_ip",
    },
    {
        "id":          "SQLI_ATTACK",
        "name":        "SQL Injection атака",
        "description": "5+ SQLi событий с одного IP за 2 минуты",
        "severity":    "high",
        "window_sec":  120,
        "threshold":   5,
        "filter":      lambda e: e.get("rule_name", "").startswith("SQLi"),
        "group_by":    "client_ip",
    },
    {
        "id":          "XSS_ATTACK",
        "name":        "XSS атака",
        "description": "5+ XSS событий с одного IP за 2 минуты",
        "severity":    "high",
        "window_sec":  120,
        "threshold":   5,
        "filter":      lambda e: e.get("rule_name", "").startswith("XSS"),
        "group_by":    "client_ip",
    },
    {
        "id":          "SCANNING",
        "name":        "Сканирование уязвимостей",
        "description": "3+ разных типа атак с одного IP за 5 минут",
        "severity":    "critical",
        "window_sec":  300,
        "threshold":   3,
        "filter":      lambda e: e["action"] in ("block", "detect"),
        "group_by":    "client_ip",
        "unique_rules": True,  # считаем уникальные правила, а не запросы
    },
    {
        "id":          "DISTRIBUTED_ATTACK",
        "name":        "Распределённая атака",
        "description": "10+ разных IP атакуют один эндпоинт за 5 минут",
        "severity":    "critical",
        "window_sec":  300,
        "threshold":   10,
        "filter":      lambda e: e["action"] == "block",
        "group_by":    "path",
        "unique_ips":  True,  # считаем уникальные IP
    },
]


class Correlator:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock   = asyncio.Lock()
        # Кэш недавних событий: ip -> list of events
        self._cache: dict[str, list[dict]] = defaultdict(list)

    async def process_event(self, event: dict[str, Any]) -> list[dict]:
        """
        Принимает новое событие, прогоняет через все правила корреляции.
        Возвращает список новых инцидентов (может быть пустым).
        """
        async with self._lock:
            # Добавляем событие в кэш
            ip = event.get("client_ip", "unknown")
            self._cache[ip].append(event)

            # Чистим устаревшие записи (старше 10 минут)
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=10)
            for key in list(self._cache.keys()):
                self._cache[key] = [
                    e for e in self._cache[key]
                    if self._parse_ts(e.get("timestamp", "")) > cutoff
                ]
                if not self._cache[key]:
                    del self._cache[key]

        incidents = []
        for rule in CORRELATION_RULES:
            incident = await self._check_rule(rule, event)
            if incident:
                incidents.append(incident)
                await self._save_incident(incident)

        return incidents

    async def _check_rule(self, rule: dict, trigger_event: dict) -> dict | None:
        """Проверяет одно правило корреляции."""
        now     = datetime.now(timezone.utc)
        cutoff  = now - timedelta(seconds=rule["window_sec"])
        group_key = rule["group_by"]
        group_val = trigger_event.get(group_key, "")

        if not group_val:
            return None

        # Собираем релевантные события из кэша
        relevant = []
        async with self._lock:
            for events_list in self._cache.values():
                for e in events_list:
                    if (e.get(group_key) == group_val
                            and rule["filter"](e)
                            and self._parse_ts(e.get("timestamp", "")) > cutoff):
                        relevant.append(e)

        if not relevant:
            return None

        # Считаем метрику в зависимости от типа правила
        if rule.get("unique_rules"):
            count = len({e.get("rule_name", "") for e in relevant})
        elif rule.get("unique_ips"):
            count = len({e.get("client_ip", "") for e in relevant})
        else:
            count = len(relevant)

        if count < rule["threshold"]:
            return None

        # Проверяем не создавали ли уже такой инцидент недавно
        already = await self._incident_exists(rule["id"], group_val, cutoff)
        if already:
            return None

        return {
            "rule_id":     rule["id"],
            "name":        rule["name"],
            "description": rule["description"],
            "severity":    rule["severity"],
            "group_by":    group_key,
            "group_value": group_val,
            "event_count": count,
            "threshold":   rule["threshold"],
            "window_sec":  rule["window_sec"],
            "timestamp":   now.isoformat(),
            "status":      "open",
        }

    async def _incident_exists(
        self, rule_id: str, group_value: str, since: datetime
    ) -> bool:
        """Проверяет существует ли уже открытый инцидент такого типа."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute(
                    """SELECT COUNT(*) FROM incidents
                       WHERE rule_id = ? AND group_value = ?
                         AND timestamp > ? AND status = 'open'""",
                    (rule_id, group_value, since.isoformat()),
                ) as cur:
                    count = (await cur.fetchone())[0]
            return count > 0
        except Exception:
            return False

    async def _save_incident(self, incident: dict) -> None:
        """Сохраняет инцидент в БД."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    """INSERT INTO incidents
                       (rule_id, name, description, severity, group_by,
                        group_value, event_count, threshold, window_sec,
                        timestamp, status)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        incident["rule_id"],
                        incident["name"],
                        incident["description"],
                        incident["severity"],
                        incident["group_by"],
                        incident["group_value"],
                        incident["event_count"],
                        incident["threshold"],
                        incident["window_sec"],
                        incident["timestamp"],
                        incident["status"],
                    ),
                )
                await db.commit()
            logger.warning(
                "ИНЦИДЕНТ [%s] %s | %s=%s | событий: %d",
                incident["severity"].upper(),
                incident["name"],
                incident["group_by"],
                incident["group_value"],
                incident["event_count"],
            )
        except Exception as e:
            logger.error("Ошибка сохранения инцидента: %s", e)

    @staticmethod
    def _parse_ts(ts: str) -> datetime:
        try:
            if ts.endswith("Z"):
                ts = ts[:-1] + "+00:00"
            return datetime.fromisoformat(ts)
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)


async def get_recent_incidents(db_path: str, limit: int = 200) -> list[dict]:
    """Возвращает последние инциденты для дашборда."""
    try:
        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """SELECT id, timestamp, rule_id, name, severity,
                          group_by, group_value, event_count,
                          threshold, window_sec, status
                   FROM incidents
                   ORDER BY id DESC LIMIT ?""",
                (limit,),
            ) as cur:
                rows = await cur.fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


async def update_incident_status(db_path: str, incident_id: int, status: str) -> bool:
    """Обновляет статус инцидента (open / resolved / false_positive)."""
    try:
        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                "UPDATE incidents SET status=? WHERE id=?",
                (status, incident_id),
            )
            await db.commit()
        return True
    except Exception:
        return False
