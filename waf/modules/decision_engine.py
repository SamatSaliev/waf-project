"""
decision_engine.py — принимает итоговое решение на основе совпавших правил
и режима работы (per-rule + глобальный fallback).

Режимы:
  Каждое правило имеет собственный режим (rule.mode):
    blocking  — при срабатывании блокирует запрос (если severity high/medium)
    detection — при срабатывании только логирует ('detect'), запрос пропускается

  Глобальный режим WAF (self.mode) — аварийный fallback:
    если self.mode == 'detection', ВСЕ правила работают в режиме detection
    независимо от их индивидуальных настроек (полезно для экстренного
    перевода всего WAF в наблюдение, например при инциденте с false positives).
"""

from __future__ import annotations

from typing import Any


class DecisionEngine:
    # Какие уровни severity ведут к блокировке
    BLOCK_SEVERITIES = {"high", "medium"}

    def __init__(self, mode: str = "blocking") -> None:
        if mode not in ("detection", "blocking"):
            raise ValueError(f"Неизвестный режим: {mode!r}. Допустимо: detection | blocking")
        self.mode = mode

    def decide(
        self, matches: list[dict[str, Any]]
    ) -> tuple[str, dict[str, Any] | None]:
        """
        Возвращает кортеж (action, triggered_rule):
          action: 'allow' | 'block' | 'detect'
          triggered_rule: словарь первого сработавшего правила или None
        """
        if not matches:
            return "allow", None

        # Берём самое серьёзное совпадение
        priority = {"high": 0, "medium": 1, "low": 2}
        top = min(matches, key=lambda r: priority.get(r["severity"], 9))

        # Глобальный аварийный fallback — всё в detection
        if self.mode == "detection":
            return "detect", top

        # Режим конкретного правила (по умолчанию blocking, если не задан)
        rule_mode = top.get("mode", "blocking")
        if rule_mode == "detection":
            return "detect", top

        # blocking mode — блокируем при high / medium
        if top["severity"] in self.BLOCK_SEVERITIES:
            return "block", top

        return "detect", top
