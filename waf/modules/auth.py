"""
auth.py — Bearer Token аутентификация для Admin API.

Поддерживает три способа передачи токена:
  1. Заголовок:      Authorization: Bearer <token>
  2. Query-параметр: ?token=<token>  (для браузера и экспорта)
  3. Без токена:     только для эндпоинтов экспорта (export_only=True)
"""

from __future__ import annotations

import os
import secrets
import logging

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger("waf.auth")

_token_from_env = os.getenv("WAF_API_TOKEN", "")
if _token_from_env:
    API_TOKEN = _token_from_env
else:
    API_TOKEN = secrets.token_hex(32)
    logger.warning("WAF_API_TOKEN не задан. Сгенерирован токен: %s", API_TOKEN)

_bearer = HTTPBearer(auto_error=False)


def _extract_token(
    credentials: HTTPAuthorizationCredentials | None,
    request: Request,
) -> str | None:
    """Извлекает токен из заголовка или query-параметра ?token=..."""
    # 1. Bearer-заголовок
    if credentials and credentials.scheme.lower() == "bearer":
        return credentials.credentials
    # 2. Query-параметр ?token=...
    token = request.query_params.get("token")
    if token:
        return token
    return None


async def require_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> str:
    """Требует валидный токен — через заголовок или ?token=."""
    token = _extract_token(credentials, request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Требуется Bearer-токен (заголовок или ?token=...)",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not secrets.compare_digest(token, API_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Неверный токен",
        )
    return token


async def require_token_flexible(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> str | None:
    """
    Мягкая проверка — для эндпоинтов экспорта.
    Если токен передан — проверяем его.
    Если токен не передан — пропускаем без ошибки.
    """
    token = _extract_token(credentials, request)
    if token and not secrets.compare_digest(token, API_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Неверный токен",
        )
    return token


async def no_auth() -> str:
    """Заглушка — эндпоинт доступен без токена."""
    return ""
