"""
rules_api.py — CRUD-операции для управления правилами WAF через REST API.
"""

from __future__ import annotations

from typing import Any
import aiosqlite


async def get_all_rules(db_path: str) -> list[dict]:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, name, description, pattern, targets, severity, enabled, created_at "
            "FROM rules ORDER BY id"
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def get_rule(db_path: str, rule_id: int) -> dict | None:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, name, description, pattern, targets, severity, enabled, created_at "
            "FROM rules WHERE id = ?", (rule_id,)
        ) as cur:
            row = await cur.fetchone()
    return dict(row) if row else None


async def create_rule(db_path: str, data: dict[str, Any]) -> dict:
    async with aiosqlite.connect(db_path) as db:
        cur = await db.execute(
            """INSERT INTO rules (name, description, pattern, targets, severity, enabled)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                data["name"],
                data.get("description", ""),
                data["pattern"],
                data.get("targets", "query,body,uri"),
                data.get("severity", "medium"),
                int(data.get("enabled", True)),
            ),
        )
        await db.commit()
        new_id = cur.lastrowid
    return await get_rule(db_path, new_id)


async def update_rule(db_path: str, rule_id: int, data: dict[str, Any]) -> dict | None:
    existing = await get_rule(db_path, rule_id)
    if not existing:
        return None

    # Обновляем только переданные поля
    name        = data.get("name",        existing["name"])
    description = data.get("description", existing["description"])
    pattern     = data.get("pattern",     existing["pattern"])
    targets     = data.get("targets",     existing["targets"])
    severity    = data.get("severity",    existing["severity"])
    enabled     = data.get("enabled",     bool(existing["enabled"]))

    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            """UPDATE rules
               SET name=?, description=?, pattern=?, targets=?, severity=?, enabled=?
               WHERE id=?""",
            (name, description, pattern, targets, severity, int(enabled), rule_id),
        )
        await db.commit()
    return await get_rule(db_path, rule_id)


async def delete_rule(db_path: str, rule_id: int) -> bool:
    existing = await get_rule(db_path, rule_id)
    if not existing:
        return False
    async with aiosqlite.connect(db_path) as db:
        await db.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
        await db.commit()
    return True


async def toggle_rule(db_path: str, rule_id: int) -> dict | None:
    existing = await get_rule(db_path, rule_id)
    if not existing:
        return None
    new_state = not bool(existing["enabled"])
    async with aiosqlite.connect(db_path) as db:
        await db.execute("UPDATE rules SET enabled=? WHERE id=?", (int(new_state), rule_id))
        await db.commit()
    return await get_rule(db_path, rule_id)
