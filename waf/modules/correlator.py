"""
correlator.py — модуль корреляции событий и выявления инцидентов WAF.
Этап 5 (исправленный): читает события из SQLite вместо in-memory кэша.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

import aiosqlite

logger = logging.getLogger("waf.correlator")

CORRELATION_RULES = [
    {
        "id":          "BRUTE_FORCE",
        "name":        "Брутфорс-атака",
        "description": "Более 10 заблокированных запросов с одного IP за 60 секунд",
        "severity":    "high",
        "window_sec":  60,
        "threshold":   10,
        "sql":         """
            SELECT COUNT(*) FROM events
            WHERE client_ip = ?
              AND action IN ('block','detect')
              AND timestamp > ?
        """,
        "group_by":    "client_ip",
    },
    {
        "id":          "SQLI_ATTACK",
        "name":        "SQL Injection атака",
        "description": "5+ SQLi событий с одного IP за 2 минуты",
        "severity":    "high",
        "window_sec":  120,
        "threshold":   5,
        "sql":         """
            SELECT COUNT(*) FROM events
            WHERE client_ip = ?
              AND action IN ('block','detect')
              AND (rule_name LIKE 'SQLi%' OR rule_name LIKE 'SQL%')
              AND timestamp > ?
        """,
        "group_by":    "client_ip",
    },
    {
        "id":          "XSS_ATTACK",
        "name":        "XSS атака",
        "description": "5+ XSS событий с одного IP за 2 минуты",
        "severity":    "high",
        "window_sec":  120,
        "threshold":   5,
        "sql":         """
            SELECT COUNT(*) FROM events
            WHERE client_ip = ?
              AND action IN ('block','detect')
              AND rule_name LIKE 'XSS%'
              AND timestamp > ?
        """,
        "group_by":    "client_ip",
    },
    {
        "id":          "SCANNING",
        "name":        "Сканирование уязвимостей",
        "description": "3+ разных типа атак с одного IP за 5 минут",
        "severity":    "critical",
        "window_sec":  300,
        "threshold":   3,
        "sql":         """
            SELECT COUNT(DISTINCT rule_name) FROM events
            WHERE client_ip = ?
              AND action IN ('block','detect')
              AND rule_name IS NOT NULL
              AND timestamp > ?
        """,
        "group_by":    "client_ip",
    },
    {
        "id":          "DISTRIBUTED_ATTACK",
        "name":        "Распределённая атака",
        "description": "10+ разных IP атакуют один эндпоинт за 5 минут",
        "severity":    "critical",
        "window_sec":  300,
        "threshold":   10,
        "sql":         """
            SELECT COUNT(DISTINCT client_ip) FROM events
            WHERE path = ?
              AND action IN ('block','detect')
              AND timestamp > ?
        """,
        "group_by":    "path",
    },
]


class Correlator:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    async def process_event(self, event: dict[str, Any]) -> list[dict]:
        """Проверяет новое событие против всех правил корреляции."""
        incidents = []
        for rule in CORRELATION_RULES:
            incident = await self._check_rule(rule, event)
            if incident:
                incidents.append(incident)
                await self._save_incident(incident)
        return incidents

    async def _check_rule(self, rule: dict, event: dict) -> dict | None:
        now    = datetime.now(timezone.utc)
        cutoff = (now - timedelta(seconds=rule["window_sec"])).isoformat()

        group_key = rule["group_by"]
        group_val = event.get(group_key, "")
        if not group_val:
            return None

        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Считаем события из БД
                async with db.execute(rule["sql"], (group_val, cutoff)) as cur:
                    row = await cur.fetchone()
                    count = row[0] if row else 0

                if count < rule["threshold"]:
                    return None

                # Проверяем не создавали ли уже такой инцидент
                async with db.execute(
                    """SELECT COUNT(*) FROM incidents
                       WHERE rule_id = ? AND group_value = ?
                         AND timestamp > ? AND status = 'open'""",
                    (rule["id"], group_val, cutoff),
                ) as cur:
                    exists = (await cur.fetchone())[0]

                if exists:
                    return None

        except Exception as e:
            logger.error("Ошибка correlator._check_rule: %s", e)
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

    async def _save_incident(self, incident: dict) -> None:
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


async def get_recent_incidents(db_path: str, limit: int = 200) -> list[dict]:
    try:
        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """SELECT id, timestamp, rule_id, name, severity,
                          group_by, group_value, event_count,
                          threshold, window_sec, status
                   FROM incidents ORDER BY id DESC LIMIT ?""",
                (limit,),
            ) as cur:
                rows = await cur.fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


async def update_incident_status(db_path: str, incident_id: int, status: str) -> bool:
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
