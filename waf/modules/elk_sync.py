"""
elk_sync.py — отправка инцидентов WAF в Elasticsearch (ELK Stack).

Каждый инцидент, созданный correlator'ом, отправляется в виде
SIEM-документа в индекс Elasticsearch вида waf-incidents-YYYY.MM.DD.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("waf.elk_sync")

ELK_ENABLED   = os.getenv("ELK_ENABLED", "false").lower() == "true"
ELK_URL       = os.getenv("ELK_URL", "").rstrip("/")          # например http://10.135.126.10:9200
ELK_USER      = os.getenv("ELK_USER", "")
ELK_PASSWORD  = os.getenv("ELK_PASSWORD", "")
ELK_INDEX_PREFIX = os.getenv("ELK_INDEX_PREFIX", "waf-incidents")
ELK_VERIFY_SSL    = os.getenv("ELK_VERIFY_SSL", "false").lower() == "true"


class ELKSync:
    def __init__(self) -> None:
        self._enabled = ELK_ENABLED and bool(ELK_URL)
        self._auth = (ELK_USER, ELK_PASSWORD) if (ELK_USER or ELK_PASSWORD) else None

        if not ELK_ENABLED:
            logger.info("ELK Sync отключён (ELK_ENABLED=false)")
        elif not ELK_URL:
            logger.warning("ELK Sync включён, но ELK_URL не задан — отправка отключена")
            self._enabled = False
        else:
            auth_info = "Basic Auth" if self._auth else "без аутентификации"
            logger.info("ELK Sync включён → %s (%s)", ELK_URL, auth_info)

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _index_name(self) -> str:
        """Индекс с датой, как принято в ELK: waf-incidents-2026.06.13"""
        date_str = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        return f"{ELK_INDEX_PREFIX}-{date_str}"

    async def send_incident(self, siem_event: dict) -> bool:
        """
        Отправляет один инцидент (в формате siem_event) в Elasticsearch.
        Возвращает True при успехе.
        """
        if not self._enabled:
            return False

        index = self._index_name()
        url   = f"{ELK_URL}/{index}/_doc"

        # Добавляем поля стандартные для ELK
        doc = {
            **siem_event,
            "@timestamp": siem_event.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "tags": ["waf", "incident", siem_event.get("severity", "unknown")],
        }

        try:
            async with httpx.AsyncClient(timeout=10.0, verify=ELK_VERIFY_SSL) as client:
                resp = await client.post(url, json=doc, auth=self._auth)
                if resp.status_code in (200, 201):
                    logger.info(
                        "ELK: инцидент отправлен → %s (id=%s)",
                        index, resp.json().get("_id", "?"),
                    )
                    return True
                else:
                    logger.error(
                        "ELK ошибка %d при отправке в %s: %s",
                        resp.status_code, index, resp.text[:300],
                    )
                    return False
        except Exception as e:
            logger.error("ELK: не удалось отправить инцидент: %s", e)
            return False

    async def test_connection(self) -> dict:
        """Проверяет соединение с Elasticsearch."""
        if not ELK_URL:
            return {"status": "error", "message": "ELK_URL не задан"}

        try:
            async with httpx.AsyncClient(timeout=10.0, verify=ELK_VERIFY_SSL) as client:
                resp = await client.get(f"{ELK_URL}/", auth=self._auth)
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "status":       "ok",
                        "elk_url":      ELK_URL,
                        "cluster_name": data.get("cluster_name", "?"),
                        "version":      data.get("version", {}).get("number", "?"),
                        "index_prefix": ELK_INDEX_PREFIX,
                        "enabled":      self._enabled,
                        "auth":         "basic" if self._auth else "none",
                    }
                elif resp.status_code == 401:
                    return {"status": "error", "message": "Неверный логин/пароль (401 Unauthorized)"}
                else:
                    return {"status": "error", "message": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
