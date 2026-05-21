"""
database.py — Этап 5: добавлена таблица incidents.
"""

from __future__ import annotations
import aiosqlite

DDL = """
CREATE TABLE IF NOT EXISTS rules (
    id          INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL,
    description TEXT,
    pattern     TEXT    NOT NULL,
    targets     TEXT    NOT NULL,
    severity    TEXT    NOT NULL DEFAULT 'medium',
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    client_ip   TEXT,
    method      TEXT,
    path        TEXT,
    query       TEXT,
    action      TEXT    NOT NULL,
    rule_id     INTEGER,
    rule_name   TEXT,
    severity    TEXT,
    target      TEXT,
    matched     TEXT,
    user_agent  TEXT
);

CREATE TABLE IF NOT EXISTS ip_lists (
    ip         TEXT PRIMARY KEY,
    action     TEXT NOT NULL CHECK(action IN ('allow','block')),
    comment    TEXT DEFAULT '',
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS incidents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    rule_id     TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    description TEXT,
    severity    TEXT    NOT NULL DEFAULT 'high',
    group_by    TEXT,
    group_value TEXT,
    event_count INTEGER DEFAULT 0,
    threshold   INTEGER DEFAULT 0,
    window_sec  INTEGER DEFAULT 60,
    status      TEXT    NOT NULL DEFAULT 'open'
                CHECK(status IN ('open','resolved','false_positive'))
);

CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ip_lists_action ON ip_lists(action);
CREATE INDEX IF NOT EXISTS idx_incidents_ts    ON incidents(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
"""


async def init_db(db_path: str) -> None:
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(DDL)
        await db.commit()


async def get_recent_events(db_path: str, limit: int = 5000) -> list[dict]:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """SELECT id, timestamp, client_ip, method, path,
                      action, rule_name, severity, matched, user_agent
               FROM events ORDER BY id DESC LIMIT ?""",
            (limit,),
        ) as cur:
            rows = await cur.fetchall()
    return [dict(row) for row in rows]


async def get_events_paginated(
    db_path: str, page: int = 1, per_page: int = 100,
    action_filter: str | None = None,
) -> tuple[list[dict], int]:
    """
    Возвращает (события на странице, общее количество событий).
    page начинается с 1. action_filter: 'block' | 'detect' | 'allow' | None.
    """
    offset = (page - 1) * per_page
    where  = "WHERE action = ?" if action_filter else ""
    p_count = (action_filter,) if action_filter else ()
    p_page  = (action_filter, per_page, offset) if action_filter else (per_page, offset)

    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"SELECT COUNT(*) FROM events {where}", p_count
        ) as cur:
            total = (await cur.fetchone())[0]
        async with db.execute(
            f"""SELECT id, timestamp, client_ip, method, path,
                      action, rule_name, severity, matched, user_agent
               FROM events {where} ORDER BY id DESC LIMIT ? OFFSET ?""",
            p_page,
        ) as cur:
            rows = await cur.fetchall()
    return [dict(row) for row in rows], total


async def get_all_events_count(db_path: str) -> int:
    """Возвращает общее количество событий в БД."""
    async with aiosqlite.connect(db_path) as db:
        async with db.execute("SELECT COUNT(*) FROM events") as cur:
            return (await cur.fetchone())[0]


async def get_events_stats(db_path: str) -> dict:
    """Возвращает реальные счётчики по всем событиям из БД."""
    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT action, COUNT(*) FROM events GROUP BY action"
        ) as cur:
            rows = await cur.fetchall()
    stats = {"block": 0, "detect": 0, "allow": 0, "total": 0}
    for action, count in rows:
        if action in stats:
            stats[action] = count
        stats["total"] += count
    return stats


async def get_unique_ips(db_path: str, limit: int = 100) -> list[dict]:
    """Возвращает уникальные IP с количеством запросов и последним действием."""
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """SELECT
                client_ip,
                COUNT(*) as total,
                SUM(CASE WHEN action='block' THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN action='detect' THEN 1 ELSE 0 END) as detected,
                SUM(CASE WHEN action='allow' THEN 1 ELSE 0 END) as allowed,
                MAX(timestamp) as last_seen
               FROM events
               WHERE client_ip IS NOT NULL
               GROUP BY client_ip
               ORDER BY total DESC
               LIMIT ?""",
            (limit,),
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def get_chart_data(db_path: str) -> dict:
    """Возвращает данные для графиков дашборда."""
    async with aiosqlite.connect(db_path) as db:

        # 1. Запросы по часам за последние 24 часа (block/detect/allow)
        async with db.execute("""
            SELECT
                strftime('%H:00', timestamp) as hour,
                action,
                COUNT(*) as cnt
            FROM events
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY hour, action
            ORDER BY hour
        """) as cur:
            hourly_rows = await cur.fetchall()

        # 2. Топ-10 правил по срабатываниям
        async with db.execute("""
            SELECT rule_name, COUNT(*) as cnt
            FROM events
            WHERE action IN ('block','detect')
              AND rule_name IS NOT NULL
            GROUP BY rule_name
            ORDER BY cnt DESC
            LIMIT 10
        """) as cur:
            rules_rows = await cur.fetchall()

        # 3. Топ-5 атакующих IP
        async with db.execute("""
            SELECT client_ip, COUNT(*) as cnt
            FROM events
            WHERE action IN ('block','detect')
              AND client_ip IS NOT NULL
            GROUP BY client_ip
            ORDER BY cnt DESC
            LIMIT 5
        """) as cur:
            ips_rows = await cur.fetchall()

        # 4. События по дням за последние 7 дней
        async with db.execute("""
            SELECT
                strftime('%d.%m', timestamp) as day,
                action,
                COUNT(*) as cnt
            FROM events
            WHERE timestamp >= datetime('now', '-7 days')
            GROUP BY day, action
            ORDER BY day
        """) as cur:
            daily_rows = await cur.fetchall()

    # Собираем почасовые данные
    hours = [f"{h:02d}:00" for h in range(24)]
    hourly = {h: {"block": 0, "detect": 0, "allow": 0} for h in hours}
    for hour, action, cnt in hourly_rows:
        if hour in hourly and action in ("block", "detect", "allow"):
            hourly[hour][action] = cnt

    # Собираем дневные данные
    days_map: dict = {}
    for day, action, cnt in daily_rows:
        if day not in days_map:
            days_map[day] = {"block": 0, "detect": 0, "allow": 0}
        if action in ("block", "detect", "allow"):
            days_map[day][action] = cnt

    return {
        "hourly": {
            "labels": hours,
            "block":  [hourly[h]["block"]  for h in hours],
            "detect": [hourly[h]["detect"] for h in hours],
            "allow":  [hourly[h]["allow"]  for h in hours],
        },
        "rules": {
            "labels": [r[0] for r in rules_rows],
            "values": [r[1] for r in rules_rows],
        },
        "top_ips": {
            "labels": [r[0] for r in ips_rows],
            "values": [r[1] for r in ips_rows],
        },
        "daily": {
            "labels": list(days_map.keys()),
            "block":  [days_map[d]["block"]  for d in days_map],
            "detect": [days_map[d]["detect"] for d in days_map],
            "allow":  [days_map[d]["allow"]  for d in days_map],
        },
    }
