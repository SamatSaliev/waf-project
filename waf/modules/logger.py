"""
logger.py — записывает события WAF в JSON-лог и в SQLite.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Any

import aiosqlite


class EventLogger:
    def __init__(self, log_path: str, db_path: str) -> None:
        self.log_path = log_path
        self.db_path  = db_path
        self._lock    = asyncio.Lock()

        # Создаём директорию для лога если нужно
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

    async def log(
        self,
        request: dict[str, Any],
        action: str,
        rule: dict[str, Any] | None,
    ) -> None:
        """Асинхронно пишет событие в файл и в БД."""
        ts = datetime.now(timezone.utc).isoformat()

        event = {
            "timestamp":   ts,
            "client_ip":   request.get("client_ip"),
            "method":      request.get("method"),
            "path":        request.get("path"),
            "query":       request.get("query"),
            "action":      action,
            "rule_id":     rule["rule_id"] if rule else None,
            "rule_name":   rule["name"]    if rule else None,
            "severity":    rule["severity"] if rule else None,
            "target":      rule["target"]  if rule else None,
            "matched":     rule["matched"] if rule else None,
            "user_agent":  request.get("user_agent"),
        }

        await asyncio.gather(
            self._write_jsonl(event),
            self._write_db(event),
        )

    async def _write_jsonl(self, event: dict) -> None:
        async with self._lock:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event, ensure_ascii=False) + "\n")
            except OSError:
                pass

    async def _write_db(self, event: dict) -> None:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    """INSERT INTO events
                       (timestamp, client_ip, method, path, query,
                        action, rule_id, rule_name, severity, target,
                        matched, user_agent)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        event["timestamp"],
                        event["client_ip"],
                        event["method"],
                        event["path"],
                        event["query"],
                        event["action"],
                        event["rule_id"],
                        event["rule_name"],
                        event["severity"],
                        event["target"],
                        event["matched"],
                        event["user_agent"],
                    ),
                )
                await db.commit()
        except Exception:
            pass
