"""
analyze.py — анализ эффективности WAF.

Читает события из WAF API, вычисляет метрики,
строит 4 графика matplotlib и сохраняет итоговый report.html.

Запуск:
  pip install requests matplotlib jinja2
  python analyze.py --url https://localhost:8443 --token YOUR_TOKEN
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

import matplotlib
matplotlib.use("Agg")  # без GUI
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import requests
from jinja2 import Template

# ── Стиль графиков ────────────────────────────────────────────────────────────
plt.rcParams.update({
    "figure.facecolor":  "#0d1117",
    "axes.facecolor":    "#161b22",
    "axes.edgecolor":    "#30363d",
    "axes.labelcolor":   "#c9d1d9",
    "xtick.color":       "#8b949e",
    "ytick.color":       "#8b949e",
    "text.color":        "#c9d1d9",
    "grid.color":        "#21262d",
    "grid.linestyle":    "--",
    "grid.alpha":        0.5,
    "font.family":       "monospace",
    "font.size":         10,
})

COLORS = {
    "block":  "#f85149",
    "detect": "#e3b341",
    "allow":  "#3fb950",
    "accent": "#58a6ff",
}


# ── Загрузка данных ───────────────────────────────────────────────────────────
def fetch_events(base_url: str, token: str) -> list[dict]:
    url = f"{base_url}/api/v1/events?limit=10000"
    try:
        r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, verify=False, timeout=15)
        r.raise_for_status()
        return r.json().get("events", [])
    except requests.RequestException as e:
        print(f"[ERROR] Не удалось загрузить события: {e}")
        sys.exit(1)


# ── Вычисление метрик ─────────────────────────────────────────────────────────
def compute_metrics(events: list[dict]) -> dict:
    total   = len(events)
    blocked = sum(1 for e in events if e["action"] == "block")
    detected= sum(1 for e in events if e["action"] == "detect")
    allowed = sum(1 for e in events if e["action"] == "allow")

    # Атаки = block + detect (всё что сработало)
    attacks = blocked + detected
    # Легитимные = allow
    legit   = allowed

    # Detection rate = заблокировано / все атаки
    detection_rate = (blocked / attacks * 100) if attacks > 0 else 0
    # False positive rate = detect среди легитимных (приблизительно)
    fp_rate = (detected / total * 100) if total > 0 else 0

    # По правилам
    rule_counter: Counter = Counter()
    for e in events:
        if e.get("rule_name"):
            rule_counter[e["rule_name"]] += 1

    # По IP
    ip_counter: Counter = Counter()
    for e in events:
        if e.get("client_ip") and e["action"] == "block":
            ip_counter[e["client_ip"]] += 1

    # По времени (группируем по минуте)
    timeline: dict[str, dict] = {}
    for e in events:
        ts = e.get("timestamp", "")[:16]  # YYYY-MM-DDTHH:MM
        if ts not in timeline:
            timeline[ts] = {"block": 0, "detect": 0, "allow": 0}
        timeline[ts][e["action"]] = timeline[ts].get(e["action"], 0) + 1
    timeline = dict(sorted(timeline.items()))

    return {
        "total":            total,
        "blocked":          blocked,
        "detected":         detected,
        "allowed":          allowed,
        "attacks":          attacks,
        "legit":            legit,
        "detection_rate":   round(detection_rate, 2),
        "fp_rate":          round(fp_rate, 2),
        "top_rules":        rule_counter.most_common(10),
        "top_ips":          ip_counter.most_common(10),
        "timeline":         timeline,
    }


# ── Графики ───────────────────────────────────────────────────────────────────
def fig_to_base64(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=120, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    buf.seek(0)
    return base64.b64encode(buf.read()).decode()


def plot_pie(m: dict) -> str:
    fig, ax = plt.subplots(figsize=(5, 4))
    values  = [m["blocked"], m["detected"], m["allowed"]]
    labels  = ["Заблокировано", "Обнаружено", "Пропущено"]
    colors  = [COLORS["block"], COLORS["detect"], COLORS["allow"]]
    wedges, texts, autotexts = ax.pie(
        values, labels=labels, colors=colors,
        autopct="%1.1f%%", startangle=140,
        wedgeprops={"linewidth": 1, "edgecolor": "#0d1117"},
    )
    for at in autotexts:
        at.set_color("#0d1117")
        at.set_fontweight("bold")
    ax.set_title("Распределение запросов", pad=14)
    result = fig_to_base64(fig)
    plt.close(fig)
    return result


def plot_top_rules(m: dict) -> str:
    if not m["top_rules"]:
        return ""
    rules, counts = zip(*m["top_rules"])
    rules = [r[:35] + "…" if len(r) > 35 else r for r in rules]
    fig, ax = plt.subplots(figsize=(8, max(3, len(rules) * 0.55)))
    bars = ax.barh(rules[::-1], counts[::-1], color=COLORS["block"], alpha=0.85)
    ax.bar_label(bars, padding=4, color=COLORS["accent"])
    ax.set_xlabel("Количество срабатываний")
    ax.set_title("Топ сработавших правил")
    ax.grid(axis="x")
    fig.tight_layout()
    result = fig_to_base64(fig)
    plt.close(fig)
    return result


def plot_timeline(m: dict) -> str:
    if not m["timeline"]:
        return ""
    labels = list(m["timeline"].keys())
    blocks  = [m["timeline"][t].get("block",  0) for t in labels]
    detects = [m["timeline"][t].get("detect", 0) for t in labels]
    allows  = [m["timeline"][t].get("allow",  0) for t in labels]

    x = range(len(labels))
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.fill_between(x, allows,  alpha=0.3, color=COLORS["allow"],  label="Allow")
    ax.fill_between(x, detects, alpha=0.4, color=COLORS["detect"], label="Detect")
    ax.fill_between(x, blocks,  alpha=0.5, color=COLORS["block"],  label="Block")
    ax.plot(x, allows,  color=COLORS["allow"],  linewidth=1.2)
    ax.plot(x, detects, color=COLORS["detect"], linewidth=1.2)
    ax.plot(x, blocks,  color=COLORS["block"],  linewidth=1.2)

    step = max(1, len(labels) // 8)
    ax.set_xticks(list(x)[::step])
    ax.set_xticklabels([labels[i][11:] for i in range(0, len(labels), step)], rotation=30)
    ax.set_ylabel("Запросов / минута")
    ax.set_title("Временная шкала запросов")
    ax.legend(loc="upper left")
    ax.grid(axis="y")
    fig.tight_layout()
    result = fig_to_base64(fig)
    plt.close(fig)
    return result


def plot_top_ips(m: dict) -> str:
    if not m["top_ips"]:
        return ""
    ips, counts = zip(*m["top_ips"])
    fig, ax = plt.subplots(figsize=(6, max(3, len(ips) * 0.5)))
    bars = ax.barh(list(ips)[::-1], list(counts)[::-1], color=COLORS["detect"], alpha=0.85)
    ax.bar_label(bars, padding=4, color=COLORS["accent"])
    ax.set_xlabel("Заблокировано запросов")
    ax.set_title("Топ заблокированных IP")
    ax.grid(axis="x")
    fig.tight_layout()
    result = fig_to_base64(fig)
    plt.close(fig)
    return result


# ── HTML-шаблон отчёта ────────────────────────────────────────────────────────
REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<title>WAF — Отчёт об эффективности</title>
<style>
  :root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--accent:#58a6ff;
        --danger:#f85149;--warn:#e3b341;--ok:#3fb950;--muted:#8b949e;--text:#c9d1d9;}
  *{box-sizing:border-box;margin:0;padding:0;}
  body{background:var(--bg);color:var(--text);font-family:"JetBrains Mono",monospace;font-size:13px;line-height:1.7;}
  header{padding:1.5rem 2rem;background:var(--surface);border-bottom:1px solid var(--border);}
  header h1{font-size:1.4rem;color:var(--accent);}
  header p{color:var(--muted);font-size:.82rem;margin-top:.25rem;}
  .container{max-width:1100px;margin:0 auto;padding:1.5rem 1rem 3rem;}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1px;
         background:var(--border);border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-bottom:2rem;}
  .stat{background:var(--surface);padding:1rem;text-align:center;}
  .stat-v{font-size:2rem;font-weight:700;}
  .stat-l{font-size:.7rem;color:var(--muted);text-transform:uppercase;margin-top:.15rem;}
  .c-block{color:var(--danger);} .c-detect{color:var(--warn);}
  .c-allow{color:var(--ok);}    .c-accent{color:var(--accent);}
  .c-ok   {color:var(--ok);}
  h2{font-size:.95rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;
     margin:2rem 0 1rem;padding-bottom:.4rem;border-bottom:1px solid var(--border);}
  .charts{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:2rem;}
  .chart-full{grid-column:1/-1;}
  .chart img{width:100%;border-radius:8px;border:1px solid var(--border);}
  table{width:100%;border-collapse:collapse;margin-bottom:2rem;}
  thead th{text-align:left;padding:.45rem .75rem;border-bottom:2px solid var(--border);
           color:var(--muted);font-size:.7rem;text-transform:uppercase;}
  tbody tr{border-bottom:1px solid var(--border);}
  tbody tr:hover{background:var(--surface);}
  tbody td{padding:.4rem .75rem;}
  .pill{display:inline-block;padding:.08rem .45rem;border-radius:3px;
        font-size:.7rem;font-weight:700;}
  .p-block {background:#3d1a1a;color:var(--danger);}
  .p-detect{background:#2d2200;color:var(--warn);}
  .p-allow {background:#122117;color:var(--ok);}
  .metric-row{display:flex;gap:2rem;margin-bottom:1rem;flex-wrap:wrap;}
  .metric{background:var(--surface);border:1px solid var(--border);
          border-radius:8px;padding:1rem 1.5rem;flex:1;min-width:200px;}
  .metric-v{font-size:1.6rem;font-weight:700;color:var(--accent);}
  .metric-l{font-size:.72rem;color:var(--muted);margin-top:.2rem;}
  footer{text-align:center;padding:2rem;color:var(--muted);font-size:.75rem;border-top:1px solid var(--border);}
</style>
</head>
<body>
<header>
  <h1>🛡 WAF — Отчёт об эффективности</h1>
  <p>Сформирован: {{ generated_at }} | Всего событий: {{ m.total }}</p>
</header>

<div class="container">

  <!-- Ключевые метрики -->
  <h2>Ключевые показатели</h2>
  <div class="metric-row">
    <div class="metric">
      <div class="metric-v c-block">{{ m.detection_rate }}%</div>
      <div class="metric-l">Detection Rate (заблокировано / все атаки)</div>
    </div>
    <div class="metric">
      <div class="metric-v c-warn">{{ m.fp_rate }}%</div>
      <div class="metric-l">Приблизительный False Positive Rate</div>
    </div>
    <div class="metric">
      <div class="metric-v c-accent">{{ m.attacks }}</div>
      <div class="metric-l">Атак обнаружено (block + detect)</div>
    </div>
    <div class="metric">
      <div class="metric-v c-allow">{{ m.allowed }}</div>
      <div class="metric-l">Легитимных запросов пропущено</div>
    </div>
  </div>

  <!-- Счётчики -->
  <div class="stats">
    <div class="stat"><div class="stat-v c-accent">{{ m.total }}</div><div class="stat-l">Всего</div></div>
    <div class="stat"><div class="stat-v c-block">{{ m.blocked }}</div><div class="stat-l">Заблокировано</div></div>
    <div class="stat"><div class="stat-v c-detect">{{ m.detected }}</div><div class="stat-l">Обнаружено</div></div>
    <div class="stat"><div class="stat-v c-allow">{{ m.allowed }}</div><div class="stat-l">Пропущено</div></div>
  </div>

  <!-- Графики -->
  <h2>Графики</h2>
  <div class="charts">
    {% if chart_pie %}
    <div class="chart"><img src="data:image/png;base64,{{ chart_pie }}" alt="Распределение запросов"/></div>
    {% endif %}
    {% if chart_rules %}
    <div class="chart"><img src="data:image/png;base64,{{ chart_rules }}" alt="Топ правил"/></div>
    {% endif %}
    {% if chart_timeline %}
    <div class="chart chart-full"><img src="data:image/png;base64,{{ chart_timeline }}" alt="Временная шкала"/></div>
    {% endif %}
    {% if chart_ips %}
    <div class="chart"><img src="data:image/png;base64,{{ chart_ips }}" alt="Топ IP"/></div>
    {% endif %}
  </div>

  <!-- Топ правил таблица -->
  {% if m.top_rules %}
  <h2>Топ сработавших правил</h2>
  <table>
    <thead><tr><th>#</th><th>Правило</th><th>Срабатываний</th><th>% от атак</th></tr></thead>
    <tbody>
      {% for rule, count in m.top_rules %}
      <tr>
        <td class="c-muted">{{ loop.index }}</td>
        <td>{{ rule }}</td>
        <td class="c-block">{{ count }}</td>
        <td class="c-muted">{{ "%.1f"|format(count / m.attacks * 100 if m.attacks else 0) }}%</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% endif %}

  <!-- Топ заблокированных IP -->
  {% if m.top_ips %}
  <h2>Топ заблокированных IP</h2>
  <table>
    <thead><tr><th>#</th><th>IP-адрес</th><th>Заблокировано запросов</th></tr></thead>
    <tbody>
      {% for ip, count in m.top_ips %}
      <tr>
        <td class="c-muted">{{ loop.index }}</td>
        <td class="mono">{{ ip }}</td>
        <td class="c-block">{{ count }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% endif %}

</div>
<footer>WAF Diploma Project — Этап 4 | Автоматически сформирован скриптом analyze.py</footer>
</body>
</html>
"""


# ── Точка входа ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="WAF Effectiveness Report Generator")
    parser.add_argument("--url",   default="https://localhost:8443", help="WAF base URL")
    parser.add_argument("--token", default=os.getenv("WAF_API_TOKEN", "my-secret-token-change-me"))
    parser.add_argument("--out",   default="waf_report.html", help="Output HTML file")
    args = parser.parse_args()

    print(f"[*] Загружаем события с {args.url} ...")
    events = fetch_events(args.url, args.token)
    print(f"[*] Получено событий: {len(events)}")

    if not events:
        print("[!] Событий нет. Сначала запустите нагрузочный тест.")
        sys.exit(0)

    print("[*] Вычисляем метрики ...")
    m = compute_metrics(events)

    print("[*] Строим графики ...")
    chart_pie      = plot_pie(m)
    chart_rules    = plot_top_rules(m)
    chart_timeline = plot_timeline(m)
    chart_ips      = plot_top_ips(m)

    print("[*] Формируем HTML-отчёт ...")
    html = Template(REPORT_TEMPLATE).render(
        m              = m,
        generated_at   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        chart_pie      = chart_pie,
        chart_rules    = chart_rules,
        chart_timeline = chart_timeline,
        chart_ips      = chart_ips,
    )

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n{'='*55}")
    print(f"  Отчёт сохранён: {args.out}")
    print(f"  Всего событий:  {m['total']}")
    print(f"  Заблокировано:  {m['blocked']}")
    print(f"  Detection Rate: {m['detection_rate']}%")
    print(f"  False Positive: ~{m['fp_rate']}%")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    main()
