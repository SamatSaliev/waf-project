"""
proxy.py — пересылает разрешённый запрос на backend и возвращает ответ.
"""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import Request
from fastapi.responses import Response

# Один клиент на всё приложение (connection pool)
_client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)


async def forward_request(
    request: Request,
    parsed: dict[str, Any],
    backend_url: str,
) -> Response:
    """
    Проксирует запрос на backend_url, сохраняя метод, заголовки,
    query string и тело.
    """
    # Собираем целевой URL
    target_url = backend_url.rstrip("/") + request.url.path
    if parsed["query"]:
        target_url += "?" + parsed["query"]

    # Убираем заголовки, которые httpx должен выставить сам
    headers = {
        k: v
        for k, v in parsed["headers"].items()
        if k.lower() not in ("host", "content-length", "transfer-encoding")
    }

    body = await request.body()

    try:
        backend_resp = await _client.request(
            method=parsed["method"],
            url=target_url,
            headers=headers,
            content=body,
        )
    except httpx.RequestError as exc:
        return Response(
            content=f"WAF: backend недоступен ({exc})",
            status_code=502,
            media_type="text/plain",
        )

    # Фильтруем hop-by-hop заголовки из ответа
    excluded = {"transfer-encoding", "connection", "keep-alive", "te", "trailers", "upgrade"}
    resp_headers = {
        k: v
        for k, v in backend_resp.headers.items()
        if k.lower() not in excluded
    }

    return Response(
        content=backend_resp.content,
        status_code=backend_resp.status_code,
        headers=resp_headers,
        media_type=backend_resp.headers.get("content-type"),
    )
