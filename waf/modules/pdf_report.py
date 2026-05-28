"""
pdf_report.py — генератор PDF отчёта об эффективности WAF.
Использует reportlab + шрифт DejaVu для поддержки кириллицы.
"""

from __future__ import annotations

import io
import os
import urllib.request
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable, PageBreak, Paragraph, SimpleDocTemplate,
    Spacer, Table, TableStyle,
)

# ── Регистрация шрифта DejaVu с поддержкой кириллицы ─────────────────────────
_FONT_DIR  = "/tmp/waf_fonts"
_FONT_URLS = {
    "DejaVu":      "https://github.com/dejavu-fonts/dejavu-fonts/raw/master/ttf/DejaVuSans.ttf",
    "DejaVu-Bold": "https://github.com/dejavu-fonts/dejavu-fonts/raw/master/ttf/DejaVuSans-Bold.ttf",
}

def _ensure_fonts():
    os.makedirs(_FONT_DIR, exist_ok=True)
    for name, url in _FONT_URLS.items():
        path = os.path.join(_FONT_DIR, f"{name}.ttf")
        if not os.path.exists(path):
            try:
                urllib.request.urlretrieve(url, path)
            except Exception:
                # Fallback — используем встроенный Helvetica без кириллицы
                return False
        try:
            pdfmetrics.registerFont(TTFont(name, path))
        except Exception:
            return False
    return True

_CYRILLIC = _ensure_fonts()
_FONT      = "DejaVu"      if _CYRILLIC else "Helvetica"
_FONT_BOLD = "DejaVu-Bold" if _CYRILLIC else "Helvetica-Bold"

# ── Цвета ─────────────────────────────────────────────────────────────────────
NAVY    = colors.HexColor("#0a2342")
BLUE    = colors.HexColor("#1565c0")
GOLD    = colors.HexColor("#c8960c")
RED     = colors.HexColor("#f85149")
YELLOW  = colors.HexColor("#e3b341")
GREEN   = colors.HexColor("#3fb950")
GRAY    = colors.HexColor("#8b949e")
LIGHT   = colors.HexColor("#f0ede8")
WHITE   = colors.white
BLACK   = colors.black


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title", fontSize=22, textColor=WHITE, alignment=TA_CENTER,
            fontName=_FONT_BOLD, spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", fontSize=11, textColor=colors.HexColor("#c9d1d9"),
            alignment=TA_CENTER, fontName=_FONT, spaceAfter=2,
        ),
        "section": ParagraphStyle(
            "section", fontSize=13, textColor=NAVY, fontName=_FONT_BOLD,
            spaceBefore=14, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "body", fontSize=9, textColor=colors.HexColor("#1a1a2e"),
            fontName=_FONT, spaceAfter=3, leading=13,
        ),
        "muted": ParagraphStyle(
            "muted", fontSize=8, textColor=GRAY, fontName=_FONT,
            alignment=TA_CENTER,
        ),
        "stat_num": ParagraphStyle(
            "stat_num", fontSize=26, textColor=NAVY, fontName=_FONT_BOLD,
            alignment=TA_CENTER, spaceAfter=2,
        ),
        "stat_label": ParagraphStyle(
            "stat_label", fontSize=8, textColor=GRAY, fontName=_FONT,
            alignment=TA_CENTER, spaceAfter=0,
        ),
    }


def generate_pdf_report(
    stats: dict[str, Any],
    chart_data: dict[str, Any],
    incidents: list[dict],
    waf_mode: str,
    rate_limit: int,
) -> bytes:
    """
    Генерирует PDF отчёт и возвращает байты.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=15*mm, bottomMargin=15*mm,
        title="WAF — Отчёт об эффективности",
        author="КГТУ ПОКС WAF System",
    )

    s     = _styles()
    story = []
    W     = A4[0] - 40*mm  # ширина контента

    now = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")

    # ── Шапка ─────────────────────────────────────────────────────────────────
    header_data = [[
        Paragraph("🛡 WAF — Отчёт об эффективности", s["title"]),
    ]]
    header_table = Table(header_data, colWidths=[W])
    header_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), NAVY),
        ("TOPPADDING",    (0,0), (-1,-1), 18),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ("RIGHTPADDING",  (0,0), (-1,-1), 10),
        ("ROUNDEDCORNERS",(0,0), (-1,-1), [8,8,8,8]),
    ]))
    story.append(header_table)

    sub_data = [[
        Paragraph("Кафедра ПОКС · КГТУ им. И. Раззакова", s["subtitle"]),
    ],[
        Paragraph(f"Сформирован: {now}", s["subtitle"]),
    ]]
    sub_table = Table(sub_data, colWidths=[W])
    sub_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#1a3a6b")),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ]))
    story.append(sub_table)
    story.append(Spacer(1, 8*mm))

    # ── Конфигурация WAF ──────────────────────────────────────────────────────
    story.append(Paragraph("Конфигурация WAF", s["section"]))
    story.append(HRFlowable(width=W, color=GOLD, thickness=2, spaceAfter=4))

    cfg_data = [
        ["Параметр", "Значение"],
        ["Режим работы", waf_mode.upper()],
        ["Rate Limit",   f"{rate_limit} запросов/минута"],
        ["Дата отчёта",  now],
    ]
    cfg_table = Table(cfg_data, colWidths=[W*0.4, W*0.6])
    cfg_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  NAVY),
        ("TEXTCOLOR",     (0,0), (-1,0),  WHITE),
        ("FONTNAME",      (0,0), (-1,0),  _FONT_BOLD),
        ("FONTSIZE",      (0,0), (-1,-1), 9),
        ("BACKGROUND",    (0,1), (-1,-1), LIGHT),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT]),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#e0ddd6")),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
    ]))
    story.append(cfg_table)
    story.append(Spacer(1, 6*mm))

    # ── Сводная статистика ────────────────────────────────────────────────────
    story.append(Paragraph("Сводная статистика", s["section"]))
    story.append(HRFlowable(width=W, color=GOLD, thickness=2, spaceAfter=6))

    total   = stats.get("total",  0)
    blocked = stats.get("block",  0)
    detect  = stats.get("detect", 0)
    allowed = stats.get("allow",  0)

    det_rate = f"{blocked/total*100:.1f}%" if total > 0 else "0%"
    fp_rate  = f"{detect/total*100:.1f}%"  if total > 0 else "0%"

    stat_data = [[
        Paragraph(str(total),   s["stat_num"]),
        Paragraph(str(blocked), s["stat_num"]),
        Paragraph(str(detect),  s["stat_num"]),
        Paragraph(str(allowed), s["stat_num"]),
    ],[
        Paragraph("Всего событий",   s["stat_label"]),
        Paragraph("Заблокировано",   s["stat_label"]),
        Paragraph("Обнаружено",      s["stat_label"]),
        Paragraph("Пропущено",       s["stat_label"]),
    ]]
    stat_table = Table(stat_data, colWidths=[W/4]*4)
    stat_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (0,-1), colors.HexColor("#e8f0fe")),
        ("BACKGROUND",    (1,0), (1,-1), colors.HexColor("#fde8e8")),
        ("BACKGROUND",    (2,0), (2,-1), colors.HexColor("#fef9e8")),
        ("BACKGROUND",    (3,0), (3,-1), colors.HexColor("#e8f5e9")),
        ("TEXTCOLOR",     (0,0), (0,0),  BLUE),
        ("TEXTCOLOR",     (1,0), (1,0),  RED),
        ("TEXTCOLOR",     (2,0), (2,0),  YELLOW),
        ("TEXTCOLOR",     (3,0), (3,0),  GREEN),
        ("TOPPADDING",    (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LINEAFTER",     (0,0), (2,-1), 1, colors.HexColor("#e0ddd6")),
        ("BOX",           (0,0), (-1,-1), 1, colors.HexColor("#e0ddd6")),
    ]))
    story.append(stat_table)
    story.append(Spacer(1, 4*mm))

    # Ключевые метрики
    metrics_data = [
        ["Метрика",          "Значение", "Описание"],
        ["Detection Rate",   det_rate,   "Доля заблокированных от всех атак"],
        ["False Positive ~", fp_rate,    "Приблизительная доля ложных срабатываний"],
        ["Всего атак",       str(blocked+detect), "Заблокировано + Обнаружено"],
        ["Инцидентов",       str(len(incidents)),  "Выявлено correlator'ом"],
    ]
    m_table = Table(metrics_data, colWidths=[W*0.28, W*0.18, W*0.54])
    m_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  BLUE),
        ("TEXTCOLOR",     (0,0), (-1,0),  WHITE),
        ("FONTNAME",      (0,0), (-1,0),  _FONT_BOLD),
        ("FONTSIZE",      (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT]),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#e0ddd6")),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("FONTNAME",      (0,1), (1,-1),  _FONT_BOLD),
        ("TEXTCOLOR",     (1,1), (1,-1),  BLUE),
    ]))
    story.append(m_table)
    story.append(Spacer(1, 6*mm))

    # ── Топ правил ────────────────────────────────────────────────────────────
    if chart_data.get("rules", {}).get("labels"):
        story.append(Paragraph("Топ сработавших правил", s["section"]))
        story.append(HRFlowable(width=W, color=GOLD, thickness=2, spaceAfter=6))

        rules_labels = chart_data["rules"]["labels"]
        rules_values = chart_data["rules"]["values"]
        max_val = max(rules_values) if rules_values else 1

        rules_data = [["#", "Правило", "Срабатываний", "% от атак"]]
        for i, (rule, cnt) in enumerate(zip(rules_labels, rules_values), 1):
            pct = f"{cnt/(blocked+detect)*100:.1f}%" if (blocked+detect) > 0 else "0%"
            rules_data.append([str(i), rule[:55], str(cnt), pct])

        r_table = Table(rules_data, colWidths=[W*0.06, W*0.58, W*0.18, W*0.18])
        r_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  NAVY),
            ("TEXTCOLOR",     (0,0), (-1,0),  WHITE),
            ("FONTNAME",      (0,0), (-1,0),  _FONT_BOLD),
            ("FONTSIZE",      (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT]),
            ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#e0ddd6")),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 6),
            ("ALIGN",         (2,0), (-1,-1), "CENTER"),
            ("TEXTCOLOR",     (2,1), (2,-1),  RED),
            ("FONTNAME",      (2,1), (2,-1),  _FONT_BOLD),
        ]))
        story.append(r_table)
        story.append(Spacer(1, 6*mm))

    # ── Топ атакующих IP ──────────────────────────────────────────────────────
    if chart_data.get("top_ips", {}).get("labels"):
        story.append(Paragraph("Топ атакующих IP-адресов", s["section"]))
        story.append(HRFlowable(width=W, color=GOLD, thickness=2, spaceAfter=6))

        ip_labels = chart_data["top_ips"]["labels"]
        ip_values = chart_data["top_ips"]["values"]

        ip_data = [["#", "IP-адрес", "Атак", "% от всех атак"]]
        for i, (ip, cnt) in enumerate(zip(ip_labels, ip_values), 1):
            pct = f"{cnt/(blocked+detect)*100:.1f}%" if (blocked+detect) > 0 else "0%"
            ip_data.append([str(i), ip, str(cnt), pct])

        ip_table = Table(ip_data, colWidths=[W*0.06, W*0.42, W*0.18, W*0.34])
        ip_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  NAVY),
            ("TEXTCOLOR",     (0,0), (-1,0),  WHITE),
            ("FONTNAME",      (0,0), (-1,0),  _FONT_BOLD),
            ("FONTSIZE",      (0,0), (-1,-1), 9),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT]),
            ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#e0ddd6")),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 6),
            ("ALIGN",         (2,0), (-1,-1), "CENTER"),
            ("TEXTCOLOR",     (2,1), (2,-1),  RED),
            ("FONTNAME",      (2,1), (2,-1),  _FONT_BOLD),
        ]))
        story.append(ip_table)
        story.append(Spacer(1, 6*mm))

    # ── Инциденты ─────────────────────────────────────────────────────────────
    if incidents:
        story.append(PageBreak())
        story.append(Paragraph("Выявленные инциденты", s["section"]))
        story.append(HRFlowable(width=W, color=GOLD, thickness=2, spaceAfter=6))

        inc_data = [["#", "Тип инцидента", "Severity", "IP/Цель", "Событий", "Время", "Статус"]]
        for i, inc in enumerate(incidents[:30], 1):
            ts = inc.get("timestamp", "")[:16].replace("T", " ")
            inc_data.append([
                str(i),
                inc.get("name", "—")[:30],
                inc.get("severity", "—").upper(),
                inc.get("group_value", "—"),
                str(inc.get("event_count", 0)),
                ts,
                inc.get("status", "—").upper(),
            ])

        inc_table = Table(
            inc_data,
            colWidths=[W*0.04, W*0.25, W*0.1, W*0.18, W*0.09, W*0.2, W*0.14],
        )

        sev_colors = {"CRITICAL": RED, "HIGH": colors.HexColor("#ff6b35"),
                      "MEDIUM": YELLOW, "LOW": GREEN}

        inc_style = TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  NAVY),
            ("TEXTCOLOR",     (0,0), (-1,0),  WHITE),
            ("FONTNAME",      (0,0), (-1,0),  _FONT_BOLD),
            ("FONTSIZE",      (0,0), (-1,-1), 7.5),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT]),
            ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#e0ddd6")),
            ("TOPPADDING",    (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("LEFTPADDING",   (0,0), (-1,-1), 5),
            ("ALIGN",         (2,0), (-1,-1), "CENTER"),
            ("FONTNAME",      (0,1), (0,-1),  _FONT_BOLD),
        ])

        for row_idx, inc in enumerate(incidents[:30], 1):
            sev = inc.get("severity", "").upper()
            color = sev_colors.get(sev, GRAY)
            inc_style.add("TEXTCOLOR", (2, row_idx), (2, row_idx), color)
            inc_style.add("FONTNAME",  (2, row_idx), (2, row_idx), _FONT_BOLD)

        inc_table.setStyle(inc_style)
        story.append(inc_table)
        story.append(Spacer(1, 6*mm))

    # ── Подвал ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 8*mm))
    story.append(HRFlowable(width=W, color=GRAY, thickness=0.5))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(
        f"WAF System · Кафедра ПОКС · КГТУ им. И. Раззакова · {now}",
        s["muted"],
    ))

    doc.build(story)
    return buf.getvalue()
