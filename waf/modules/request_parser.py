"""
request_parser.py — извлекает все данные из входящего HTTP-запроса
и возвращает единый словарь для дальнейшего анализа.
"""

from __future__ import annotations

import urllib.parse
from typing import Any

from fastapi import Request


async def parse_request(request: Request) -> dict[str, Any]:
    """Разбирает FastAPI Request и возвращает нормализованный словарь."""

    # Тело запроса (ограничиваем 1 МБ во избежание OOM)
    body_bytes: bytes = await request.body()
    body_text: str = ""
    try:
        body_text = body_bytes[:1_048_576].decode("utf-8", errors="replace")
    except Exception:
        pass

    # Query-параметры как строка
    raw_query = str(request.url.query)

    # Заголовки (нижний регистр ключей)
    headers = dict(request.headers)

    # User-Agent и IP для логирования
    client_ip = (request.client.host if request.client else "unknown")
    user_agent = headers.get("user-agent", "")

    # Cookie как строка
    cookie_str = headers.get("cookie", "")

    return {
        "method":     request.method,
        "path":       request.url.path,
        "query":      raw_query,
        "body":       body_text,
        "headers":    headers,
        "client_ip":  client_ip,
        "user_agent": user_agent,
        "cookies":    cookie_str,
        # Все поля, которые будут сканироваться правилами, в одном месте
        "targets": {
            "uri":    urllib.parse.unquote(request.url.path),
            "query":  urllib.parse.unquote(raw_query),
            "body":   body_text,
            "cookie": cookie_str,
        },
    }
