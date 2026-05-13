"""
rule_engine.py — хранит правила и сопоставляет их с разобранным запросом.

Этап 2: расширенный набор правил (SQLi, XSS, Command Injection,
Path Traversal, SSRF, XXE, HTTP Header Injection).
"""

from __future__ import annotations

import re
from typing import Any

import aiosqlite


DEFAULT_RULES: list[dict] = [
    # ── SQL Injection ──────────────────────────────────────────────────────────
    {
        "id": 1, "name": "SQLi — UNION-based",
        "description": "UNION SELECT атаки",
        "pattern": r"(?i)\bUNION\b.{0,30}\bSELECT\b",
        "targets": ["query", "body", "uri"],
        "severity": "high", "enabled": True,
    },
    {
        "id": 2, "name": "SQLi — Boolean/Tautology",
        "description": "Тавтологии OR 1=1",
        "pattern": r"(?i)(\bOR\b|\bAND\b)\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+[\'\"]?",
        "targets": ["query", "body", "uri"],
        "severity": "high", "enabled": True,
    },
    {
        "id": 3, "name": "SQLi — Comment sequences",
        "description": "SQL-комментарии для обхода условий",
        "pattern": r"(--|#|\/\*.*?\*\/)",
        "targets": ["query", "body"],
        "severity": "medium", "enabled": True,
    },
    {
        "id": 4, "name": "SQLi — Stacked queries",
        "description": "Составные запросы через точку с запятой",
        "pattern": r"(?i);\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b",
        "targets": ["query", "body"],
        "severity": "high", "enabled": True,
    },
    {
        "id": 5, "name": "SQLi — SLEEP/BENCHMARK",
        "description": "Time-based blind SQLi",
        "pattern": r"(?i)\b(SLEEP|BENCHMARK|WAITFOR\s+DELAY)\s*\(",
        "targets": ["query", "body"],
        "severity": "high", "enabled": True,
    },
    # ── XSS ───────────────────────────────────────────────────────────────────
    {
        "id": 6, "name": "XSS — Script tag",
        "description": "Инъекция тега <script>",
        "pattern": r"(?i)<\s*script[\s>]",
        "targets": ["query", "body", "uri"],
        "severity": "high", "enabled": True,
    },
    {
        "id": 7, "name": "XSS — Event handler",
        "description": "Атрибуты-обработчики событий on*=",
        "pattern": r"(?i)\bon\w+\s*=",
        "targets": ["query", "body", "uri"],
        "severity": "medium", "enabled": True,
    },
    {
        "id": 8, "name": "XSS — javascript: URI",
        "description": "Схема javascript: в href/src",
        "pattern": r"(?i)javascript\s*:",
        "targets": ["query", "body", "uri", "cookie"],
        "severity": "high", "enabled": True,
    },
    {
        "id": 9, "name": "XSS — SVG/HTML injection",
        "description": "Инъекция через SVG и опасные HTML-теги",
        "pattern": r"(?i)<\s*(svg|img|iframe|object|embed|link|meta)[\s>]",
        "targets": ["query", "body"],
        "severity": "medium", "enabled": True,
    },
    # ── Command Injection ─────────────────────────────────────────────────────
    {
        "id": 10, "name": "Command Injection — Shell operators",
        "description": "Shell-команды через ; | & операторы",
        "pattern": r"(;|\||&&|\|\|)\s*(ls|cat|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|perl)\b",
        "targets": ["query", "body", "uri"],
        "severity": "high", "enabled": True,
    },
    {
        "id": 11, "name": "Command Injection — Backtick/subshell",
        "description": "Подстановка команд через backtick и $(...)",
        "pattern": r"(`[^`]+`|\$\([^)]+\))",
        "targets": ["query", "body"],
        "severity": "high", "enabled": True,
    },
    {
        "id": 12, "name": "Command Injection — Common payloads",
        "description": "Типичные пути для чтения системных файлов",
        "pattern": r"(?i)\b(etc/passwd|etc/shadow|proc/self|/bin/bash|/bin/sh)\b",
        "targets": ["query", "body", "uri"],
        "severity": "high", "enabled": True,
    },
    # ── Path Traversal ────────────────────────────────────────────────────────
    {
        "id": 13, "name": "Path Traversal — Basic",
        "description": "Выход за пределы корневой директории",
        "pattern": r"(\.\.[\\/]){2,}",
        "targets": ["uri", "query"],
        "severity": "high", "enabled": True,
    },
    {
        "id": 14, "name": "Path Traversal — Encoded",
        "description": "URL-кодированные traversal-последовательности",
        "pattern": r"(%2e%2e[%2f%5c]|%252e%252e)",
        "targets": ["uri", "query"],
        "severity": "high", "enabled": True,
    },
    # ── SSRF ──────────────────────────────────────────────────────────────────
    {
        "id": 15, "name": "SSRF — Internal network",
        "description": "Обращение к внутренним адресам сети",
        "pattern": r"(?i)(localhost|127\.0\.0\.1|169\.254\.\d+\.\d+|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+)",
        "targets": ["query", "body"],
        "severity": "high", "enabled": True,
    },
    {
        "id": 16, "name": "SSRF — Dangerous URI schemes",
        "description": "Схемы file://, dict://, gopher:// для SSRF",
        "pattern": r"(?i)(file://|dict://|gopher://|ftp://|ldap://)",
        "targets": ["query", "body"],
        "severity": "high", "enabled": True,
    },
    # ── XXE ───────────────────────────────────────────────────────────────────
    {
        "id": 17, "name": "XXE — DOCTYPE entity",
        "description": "XML External Entity через DOCTYPE",
        "pattern": r"(?i)<!DOCTYPE[^>]*\[",
        "targets": ["body"],
        "severity": "high", "enabled": True,
    },
    {
        "id": 18, "name": "XXE — ENTITY declaration",
        "description": "Объявление внешних XML-сущностей",
        "pattern": r"(?i)<!ENTITY\s+\S+\s+SYSTEM",
        "targets": ["body"],
        "severity": "high", "enabled": True,
    },
    # ── HTTP Header Injection ─────────────────────────────────────────────────
    {
        "id": 19, "name": "Header Injection — CRLF",
        "description": "Инъекция CRLF-символов для подделки заголовков",
        "pattern": r"(%0d%0a|%0d|%0a|\r\n)(\s*(Set-Cookie|Location|Content-Type))",
        "targets": ["query", "uri"],
        "severity": "high", "enabled": True,
    },
]


class RuleEngine:
    def __init__(self) -> None:
        self._rules: list[dict] = []
        self._compiled: list[tuple[dict, re.Pattern]] = []

    async def load_rules(self, db_path: str) -> None:
        async with aiosqlite.connect(db_path) as db:
            async with db.execute("SELECT COUNT(*) FROM rules") as cur:
                count = (await cur.fetchone())[0]
            if count == 0:
                await self._seed(db)
            else:
                await self._seed_missing(db)
            async with db.execute(
                "SELECT id, name, description, pattern, targets, severity "
                "FROM rules WHERE enabled = 1"
            ) as cur:
                rows = await cur.fetchall()

        self._rules = []
        for row in rows:
            self._rules.append({
                "id": row[0], "name": row[1], "description": row[2],
                "pattern": row[3], "targets": row[4].split(","), "severity": row[5],
            })

        self._compiled = []
        for rule in self._rules:
            try:
                self._compiled.append((rule, re.compile(rule["pattern"])))
            except re.error:
                pass

    async def _seed(self, db: aiosqlite.Connection) -> None:
        for r in DEFAULT_RULES:
            await db.execute(
                "INSERT OR IGNORE INTO rules (id,name,description,pattern,targets,severity,enabled) VALUES (?,?,?,?,?,?,?)",
                (r["id"], r["name"], r["description"], r["pattern"], ",".join(r["targets"]), r["severity"], int(r["enabled"])),
            )
        await db.commit()

    async def _seed_missing(self, db: aiosqlite.Connection) -> None:
        for r in DEFAULT_RULES:
            await db.execute(
                "INSERT OR IGNORE INTO rules (id,name,description,pattern,targets,severity,enabled) VALUES (?,?,?,?,?,?,?)",
                (r["id"], r["name"], r["description"], r["pattern"], ",".join(r["targets"]), r["severity"], int(r["enabled"])),
            )
        await db.commit()

    def analyze(self, parsed: dict[str, Any]) -> list[dict]:
        matches: list[dict] = []
        targets: dict[str, str] = parsed.get("targets", {})
        for rule, pattern in self._compiled:
            for target_name in rule["targets"]:
                value = targets.get(target_name, "")
                if not value:
                    continue
                m = pattern.search(value)
                if m:
                    matches.append({
                        "rule_id": rule["id"], "name": rule["name"],
                        "severity": rule["severity"], "target": target_name,
                        "matched": m.group(0)[:120],
                    })
                    break
        return matches
