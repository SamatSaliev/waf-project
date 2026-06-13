"""
WAF — Web Application Firewall
Этап 5: Корреляция событий + выявление инцидентов
"""

import csv
import io
import json
import os
import re as _re
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx

from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, Request, status, Cookie
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from modules.auth import (
    API_TOKEN, no_auth, require_token, require_token_flexible,
    check_session, create_session, destroy_session, verify_password,
)
from modules.database import get_all_events_count, get_chart_data, get_events_paginated, get_events_stats, get_unique_ips, init_db
from modules.decision_engine import DecisionEngine
from modules.ip_filter import IpFilter
from modules.logger import EventLogger
from modules.proxy import forward_request
from modules.rate_limiter import RateLimiter
from modules.request_parser import parse_request
from modules.rule_engine import RuleEngine
from modules.rules_api import (
    create_rule, delete_rule, get_all_rules, get_rule, toggle_rule, update_rule,
)
from modules.correlator import (
    Correlator, get_incident_by_id, get_incident_related_events,
    get_recent_incidents, update_incident_status,
)
from modules.ti_sync import TISync
from modules.telegram_notify import TelegramNotifier
from modules.elk_sync import ELKSync

# ── Конфигурация ──────────────────────────────────────────────────────────────
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:5000")
WAF_MODE    = os.getenv("WAF_MODE", "blocking")   # меняется через UI
DB_PATH     = os.getenv("DB_PATH", "/data/waf.db")
LOG_PATH    = os.getenv("LOG_PATH", "/data/events.jsonl")
RATE_LIMIT  = int(os.getenv("RATE_LIMIT", "60"))

# IP whitelist для /waf-admin (через запятую, пустая строка = все разрешены)
_whitelist_raw   = os.getenv("ADMIN_IP_WHITELIST", "")
ADMIN_WHITELIST  = [ip.strip() for ip in _whitelist_raw.split(",") if ip.strip()]


def check_admin_ip(request: Request) -> bool:
    """Проверяет что IP клиента разрешён для доступа к /waf-admin."""
    if not ADMIN_WHITELIST:
        return True  # whitelist не задан — разрешаем всем
    client_ip = request.client.host if request.client else ""
    return client_ip in ADMIN_WHITELIST


def require_admin_ip(request: Request) -> None:
    """FastAPI dependency — блокирует доступ если IP не в whitelist."""
    if not check_admin_ip(request):
        client_ip = request.client.host if request.client else "unknown"
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Доступ запрещён. IP {client_ip} не в списке разрешённых.",
        )

# ── Модули ────────────────────────────────────────────────────────────────────
rule_engine     = RuleEngine()
decision_engine = DecisionEngine(mode=WAF_MODE)
event_logger    = EventLogger(log_path=LOG_PATH, db_path=DB_PATH)
rate_limiter    = RateLimiter(max_requests=RATE_LIMIT, window_seconds=60)
ip_filter       = IpFilter(db_path=DB_PATH)
correlator      = Correlator(db_path=DB_PATH)
ti_sync         = TISync(ip_filter=ip_filter, db_path=DB_PATH)
tg              = TelegramNotifier()
elk             = ELKSync()

templates = Jinja2Templates(directory="templates")
os.makedirs("static", exist_ok=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db(DB_PATH)
    await rule_engine.load_rules(DB_PATH)
    await ip_filter.load()
    await ti_sync.start()
    await tg.send_startup(WAF_MODE, RATE_LIMIT)
    print(f"\n{'='*60}")
    print(f"  WAF | Режим: {WAF_MODE} | Rate limit: {RATE_LIMIT}/min")
    print(f"  API Token: {API_TOKEN}")
    print(f"{'='*60}\n")
    yield
    ti_sync.stop()


app = FastAPI(title="Python WAF — Этап 5", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.middleware("http")
async def admin_ip_whitelist_middleware(request: Request, call_next):
    """Блокирует доступ к /waf-admin и /waf-login если IP не в whitelist."""
    path = request.url.path
    if ADMIN_WHITELIST and (path.startswith("/waf-admin") or path.startswith("/waf-login")):
        client_ip = request.client.host if request.client else ""
        if client_ip not in ADMIN_WHITELIST:
            return JSONResponse(
                status_code=403,
                content={
                    "error":   "Forbidden",
                    "message": f"Доступ к панели администратора запрещён. IP {client_ip} не разрешён.",
                },
            )
    return await call_next(request)


# ═══════════════════════════════════════════════════════════════════════════════
# AUTH — Login / Logout
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/waf-login", response_class=HTMLResponse, tags=["auth"])
async def login_page(request: Request, waf_session: str | None = Cookie(default=None)):
    if check_session(waf_session):
        return RedirectResponse("/waf-admin", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/waf-login", tags=["auth"])
async def login_submit(
    request: Request,
    password: str = Form(...),
    waf_session: str | None = Cookie(default=None),
):
    if verify_password(password):
        token = create_session()
        response = RedirectResponse("/waf-admin", status_code=303)
        response.set_cookie(
            key="waf_session", value=token,
            httponly=True, samesite="lax",
            max_age=3600,
        )
        return response
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "Неверный пароль"},
        status_code=401,
    )


@app.get("/waf-logout", tags=["auth"])
async def logout(waf_session: str | None = Cookie(default=None)):
    destroy_session(waf_session or "")
    response = RedirectResponse("/waf-login", status_code=303)
    response.delete_cookie("waf_session")
    return response


# ── Вспомогательная dependency для проверки сессии ───────────────────────────
async def require_session(
    request: Request,
    waf_session: str | None = Cookie(default=None),
):
    if not check_session(waf_session):
        raise HTTPException(
            status_code=303,
            headers={"Location": "/waf-login"},
        )
    return waf_session


# ═══════════════════════════════════════════════════════════════════════════════
# AUTH — Login / Logout
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/waf-login", response_class=HTMLResponse, tags=["auth"])
async def login_page(request: Request, waf_session: str | None = Cookie(default=None)):
    if check_session(waf_session):
        return RedirectResponse("/waf-admin", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/waf-login", response_class=HTMLResponse, tags=["auth"])
async def login_submit(request: Request, password: str = Form(...)):
    if verify_password(password):
        token = create_session()
        response = RedirectResponse("/waf-admin", status_code=303)
        response.set_cookie(
            key="waf_session", value=token,
            httponly=True, samesite="lax",
            max_age=3600,
        )
        return response
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "Неверный пароль"},
        status_code=401,
    )


@app.get("/waf-logout", tags=["auth"])
async def logout(waf_session: str | None = Cookie(default=None)):
    if waf_session:
        destroy_session(waf_session)
    response = RedirectResponse("/waf-login", status_code=303)
    response.delete_cookie("waf_session")
    return response


# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN UI
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/waf-admin", response_class=HTMLResponse, tags=["admin-ui"])
async def admin_dashboard(
    request: Request,
    waf_session: str = Depends(require_session),
):
    page      = int(request.query_params.get("page", 1))
    per_page  = 100
    action    = request.query_params.get("action", "all")
    sort_by   = request.query_params.get("sort", "id")
    sort_dir  = request.query_params.get("dir", "desc")
    inc_sort  = request.query_params.get("inc_sort", "id")
    inc_dir   = request.query_params.get("inc_dir", "desc")
    events, total_events = await get_events_paginated(
        DB_PATH, page=page, per_page=per_page,
        action_filter=None if action == "all" else action,
        sort_by=sort_by, sort_dir=sort_dir,
    )
    stats     = await get_events_stats(DB_PATH)
    ip_list   = await ip_filter.get_all()
    rules     = await get_all_rules(DB_PATH)
    incidents = await get_recent_incidents(
        DB_PATH, limit=200, sort_by=inc_sort, sort_dir=inc_dir,
    )
    return templates.TemplateResponse("dashboard.html", {
        "request":       request,
        "events":        events,
        "total_events":  total_events,
        "current_page":  page,
        "per_page":      per_page,
        "action_filter": action,
        "sort_by":       sort_by,
        "sort_dir":      sort_dir,
        "inc_sort":      inc_sort,
        "inc_dir":       inc_dir,
        "stats":         stats,
        "ip_list":       ip_list,
        "rules":         rules,
        "incidents":     incidents,
        "mode":          WAF_MODE,
        "rate_limit":    RATE_LIMIT,
        "api_token":     API_TOKEN,
    })


@app.post("/waf-admin/mode", tags=["admin-ui"])
async def admin_set_mode(mode: str = Form(...), _: str = Depends(require_session)):
    """Переключает режим WAF между blocking и detection прямо из UI."""
    global WAF_MODE
    if mode not in ("blocking", "detection"):
        return JSONResponse(status_code=400, content={"error": "Недопустимый режим"})
    WAF_MODE = mode
    decision_engine.mode = mode
    return RedirectResponse("/waf-admin", status_code=303)


@app.post("/waf-admin/ip/add", tags=["admin-ui"])
async def admin_ip_add(
    ip: str = Form(...), action: str = Form(...),
    comment: str = Form(""), _: str = Depends(require_session),
):
    if action not in ("allow", "block"):
        return JSONResponse(status_code=400, content={"error": "action must be allow or block"})
    await ip_filter.add_ip(ip, action, comment)  # type: ignore[arg-type]
    return RedirectResponse("/waf-admin", status_code=303)


@app.post("/waf-admin/ip/remove", tags=["admin-ui"])
async def admin_ip_remove(ip: str = Form(...), _: str = Depends(require_session)):
    await ip_filter.remove_ip(ip)
    return RedirectResponse("/waf-admin", status_code=303)


@app.post("/waf-admin/incidents/{incident_id}/resolve", tags=["admin-ui"])
async def admin_resolve_incident(incident_id: int, _: str = Depends(require_session)):
    await update_incident_status(DB_PATH, incident_id, "resolved")
    return RedirectResponse("/waf-admin", status_code=303)


@app.post("/waf-admin/incidents/{incident_id}/fp", tags=["admin-ui"])
async def admin_fp_incident(incident_id: int, _: str = Depends(require_session)):
    await update_incident_status(DB_PATH, incident_id, "false_positive")
    return RedirectResponse("/waf-admin", status_code=303)


@app.get("/api/v1/ti/status", tags=["api-ti"])
async def api_ti_status(_: str = Depends(require_token)):
    """Статус TI синхронизации."""
    from modules.ti_sync import TI_BASE_URL, TI_SYNC_INTERVAL, TI_SCORE_THRESHOLD, TI_ENABLED
    return {
        "enabled":        TI_ENABLED,
        "ti_url":         TI_BASE_URL,
        "interval_sec":   TI_SYNC_INTERVAL,
        "score_threshold": TI_SCORE_THRESHOLD,
        "synced_ips":     len(ti_sync._synced),
        "synced_list":    list(ti_sync._synced),
    }


@app.post("/api/v1/ti/sync", tags=["api-ti"])
async def api_ti_sync_now(_: str = Depends(require_token)):
    """Принудительная синхронизация с TI прямо сейчас."""
    result = await ti_sync.sync_now()
    return result


@app.get("/api/v1/elk/status", tags=["api-elk"])
async def api_elk_status(_: str = Depends(require_token)):
    """Статус подключения к ELK / Elasticsearch."""
    from modules.elk_sync import ELK_URL, ELK_INDEX_PREFIX, ELK_ENABLED
    result = await elk.test_connection()
    result["configured_url"] = ELK_URL
    result["index_prefix"]   = ELK_INDEX_PREFIX
    result["enabled_flag"]   = ELK_ENABLED
    return result


@app.post("/api/v1/elk/resend/{incident_id}", tags=["api-elk"])
async def api_elk_resend_incident(incident_id: int, _: str = Depends(require_token)):
    """Повторная отправка одного инцидента в ELK (например для теста)."""
    if not elk.enabled:
        raise HTTPException(status_code=400, detail="ELK Sync не включён (ELK_ENABLED=false или ELK_URL не задан)")

    incident = await get_incident_by_id(DB_PATH, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Инцидент {incident_id} не найден")

    siem_event = {
        "siem_format":    "WAF-Incident-v1",
        "device_vendor":  "KGTU-POKS",
        "device_product": "Custom-WAF",
        "device_version": "1.0",
        "incident_id":    incident["id"],
        "signature_id":   incident["rule_id"],
        "name":           incident["name"],
        "description":    incident["description"],
        "severity":       incident["severity"],
        "timestamp":      incident["timestamp"],
        "source": {
            incident["group_by"]: incident["group_value"],
        },
        "event_count":    incident["event_count"],
        "threshold":      incident["threshold"],
        "window_seconds": incident["window_sec"],
        "status":         incident["status"],
    }
    ok = await elk.send_incident(siem_event)
    if not ok:
        raise HTTPException(status_code=502, detail="Не удалось отправить инцидент в ELK — проверьте логи waf")
    return {"status": "ok", "incident_id": incident_id, "index": elk._index_name()}


@app.post("/api/v1/elk/resend-all", tags=["api-elk"])
async def api_elk_resend_all(_: str = Depends(require_token)):
    """Отправляет все инциденты из БД в ELK (полезно при первой настройке)."""
    if not elk.enabled:
        raise HTTPException(status_code=400, detail="ELK Sync не включён (ELK_ENABLED=false или ELK_URL не задан)")

    incidents = await get_recent_incidents(DB_PATH, limit=10000)
    sent, failed = 0, 0
    for incident in incidents:
        siem_event = {
            "siem_format":    "WAF-Incident-v1",
            "device_vendor":  "KGTU-POKS",
            "device_product": "Custom-WAF",
            "device_version": "1.0",
            "incident_id":    incident["id"],
            "signature_id":   incident["rule_id"],
            "name":           incident["name"],
            "description":    incident["description"],
            "severity":       incident["severity"],
            "timestamp":      incident["timestamp"],
            "source": {
                incident["group_by"]: incident["group_value"],
            },
            "event_count":    incident["event_count"],
            "threshold":      incident["threshold"],
            "window_seconds": incident["window_sec"],
            "status":         incident["status"],
        }
        if await elk.send_incident(siem_event):
            sent += 1
        else:
            failed += 1
    return {"status": "ok", "total": len(incidents), "sent": sent, "failed": failed, "index": elk._index_name()}


# ═══════════════════════════════════════════════════════════════════════════════
# REST API — Events
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/events", tags=["api-events"])
async def api_get_events(limit: int = 1000, _: str = Depends(require_token)):
    events, _ = await get_events_paginated(DB_PATH, page=1, per_page=limit)
    return {"count": len(events), "events": events}


@app.get("/api/v1/events/export/json", tags=["api-events"])
async def api_export_json(request: Request, _: str = Depends(no_auth)):
    action = request.query_params.get("action", "all")
    events, _ = await get_events_paginated(
        DB_PATH, page=1, per_page=999999,
        action_filter=None if action == "all" else action,
    )
    content = json.dumps(
        {"exported_at": _now(), "count": len(events), "filter": action, "events": events},
        ensure_ascii=False, indent=2,
    )
    suffix = "" if action == "all" else f"_{action}"
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="waf_events{suffix}_{_today()}.json"'},
    )


@app.get("/api/v1/events/export/csv", tags=["api-events"])
async def api_export_csv(request: Request, _: str = Depends(no_auth)):
    action = request.query_params.get("action", "all")
    events, _ = await get_events_paginated(
        DB_PATH, page=1, per_page=999999,
        action_filter=None if action == "all" else action,
    )
    buf    = io.StringIO()
    if events:
        writer = csv.DictWriter(buf, fieldnames=events[0].keys())
        writer.writeheader()
        writer.writerows(events)
    suffix = "" if action == "all" else f"_{action}"
    return StreamingResponse(
        io.BytesIO(buf.getvalue().encode("utf-8-sig")),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="waf_events{suffix}_{_today()}.csv"'},
    )


@app.get("/api/v1/incidents/export/json", tags=["api-incidents"])
async def api_export_incidents_json(_: str = Depends(no_auth)):
    incidents = await get_recent_incidents(DB_PATH, limit=10000)
    content = json.dumps(
        {"exported_at": _now(), "count": len(incidents), "incidents": incidents},
        ensure_ascii=False, indent=2,
    )
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="waf_incidents_{_today()}.json"'},
    )


@app.get("/api/v1/incidents/export/csv", tags=["api-incidents"])
async def api_export_incidents_csv(_: str = Depends(no_auth)):
    incidents = await get_recent_incidents(DB_PATH, limit=10000)
    buf = io.StringIO()
    if incidents:
        writer = csv.DictWriter(buf, fieldnames=incidents[0].keys())
        writer.writeheader()
        writer.writerows(incidents)
    return StreamingResponse(
        io.BytesIO(buf.getvalue().encode("utf-8-sig")),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="waf_incidents_{_today()}.csv"'},
    )


_PRIVATE_IP_RE = _re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)")


@app.get("/api/v1/incidents/{incident_id}/details", tags=["api-incidents"])
async def api_incident_details(incident_id: int, _: str = Depends(no_auth)):
    """
    Подробная информация об инциденте: связанные события, геолокация/WHOIS IP
    (через ip-api.com), сводка по типам атак и SIEM-готовое представление (CEF-like JSON).
    """
    incident = await get_incident_by_id(DB_PATH, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Инцидент не найден")

    related_events = await get_incident_related_events(
        DB_PATH,
        group_by    = incident["group_by"],
        group_value = incident["group_value"],
        window_sec  = incident["window_sec"],
        end_ts      = incident["timestamp"],
        limit       = 50,
    )

    # ── Сводка по типам атак ────────────────────────────────────────────────
    attack_types: dict[str, int] = {}
    for ev in related_events:
        rule = ev.get("rule_name") or "Неизвестно"
        attack_types[rule] = attack_types.get(rule, 0) + 1
    attack_summary = [
        {"rule_name": k, "count": v}
        for k, v in sorted(attack_types.items(), key=lambda x: -x[1])
    ]

    # ── Геолокация / WHOIS для IP ────────────────────────────────────────────
    geo_info: dict | None = None
    ip_candidate = incident["group_value"] if incident["group_by"] == "client_ip" else None

    if ip_candidate and not _PRIVATE_IP_RE.match(ip_candidate):
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"http://ip-api.com/json/{ip_candidate}",
                    params={"fields": "status,message,country,countryCode,region,regionName,"
                                       "city,zip,lat,lon,timezone,isp,org,as,asname,reverse,proxy,hosting"},
                )
                data = resp.json()
                if data.get("status") == "success":
                    geo_info = data
        except Exception:
            geo_info = None
    elif ip_candidate and _PRIVATE_IP_RE.match(ip_candidate):
        geo_info = {"status": "private", "message": "Приватный IP-адрес — геолокация недоступна"}

    # ── SIEM-готовый формат (упрощённый CEF / JSON) ─────────────────────────
    siem_event = {
        "siem_format":     "WAF-Incident-v1",
        "device_vendor":   "KGTU-POKS",
        "device_product":  "Custom-WAF",
        "device_version":  "1.0",
        "signature_id":    incident["rule_id"],
        "name":            incident["name"],
        "severity":        incident["severity"],
        "timestamp":       incident["timestamp"],
        "source": {
            incident["group_by"]: incident["group_value"],
            "geo": geo_info if geo_info and geo_info.get("status") == "success" else None,
        },
        "event_count":     incident["event_count"],
        "threshold":       incident["threshold"],
        "window_seconds":  incident["window_sec"],
        "status":          incident["status"],
        "attack_types":    attack_summary,
        "related_events_count": len(related_events),
    }

    return {
        "incident":       incident,
        "related_events": related_events,
        "attack_summary": attack_summary,
        "geo_info":       geo_info,
        "siem_event":     siem_event,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# REST API — Incidents
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/incidents", tags=["api-incidents"])
async def api_get_incidents(limit: int = 200, _: str = Depends(require_token)):
    incidents = await get_recent_incidents(DB_PATH, limit=limit)
    open_count = sum(1 for i in incidents if i["status"] == "open")
    return {"count": len(incidents), "open": open_count, "incidents": incidents}


@app.post("/api/v1/incidents/{incident_id}/resolve", tags=["api-incidents"])
async def api_resolve_incident(incident_id: int, _: str = Depends(require_token)):
    ok = await update_incident_status(DB_PATH, incident_id, "resolved")
    if not ok:
        raise HTTPException(status_code=404, detail="Инцидент не найден")
    return {"status": "resolved"}


@app.post("/api/v1/incidents/{incident_id}/false-positive", tags=["api-incidents"])
async def api_fp_incident(incident_id: int, _: str = Depends(require_token)):
    ok = await update_incident_status(DB_PATH, incident_id, "false_positive")
    if not ok:
        raise HTTPException(status_code=404, detail="Инцидент не найден")
    return {"status": "false_positive"}


# ═══════════════════════════════════════════════════════════════════════════════
# REST API — Rules CRUD
# ═══════════════════════════════════════════════════════════════════════════════

class RuleCreate(BaseModel):
    name: str; description: str = ""; pattern: str
    targets: str = "query,body,uri"; severity: str = "medium"; enabled: bool = True

class RuleUpdate(BaseModel):
    name: str | None = None; description: str | None = None
    pattern: str | None = None; targets: str | None = None
    severity: str | None = None; enabled: bool | None = None


@app.get("/api/v1/rules", tags=["api-rules"])
async def api_list_rules(_: str = Depends(require_token)):
    rules = await get_all_rules(DB_PATH)
    return {"count": len(rules), "rules": rules}

@app.get("/api/v1/rules/{rule_id}", tags=["api-rules"])
async def api_get_rule(rule_id: int, _: str = Depends(require_token)):
    rule = await get_rule(DB_PATH, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Правило {rule_id} не найдено")
    return rule

@app.post("/api/v1/rules", status_code=status.HTTP_201_CREATED, tags=["api-rules"])
async def api_create_rule(body: RuleCreate, _: str = Depends(require_token)):
    rule = await create_rule(DB_PATH, body.model_dump())
    await rule_engine.load_rules(DB_PATH)
    return rule

@app.patch("/api/v1/rules/{rule_id}", tags=["api-rules"])
async def api_update_rule(rule_id: int, body: RuleUpdate, _: str = Depends(require_token)):
    updated = await update_rule(DB_PATH, rule_id, body.model_dump(exclude_none=True))
    if not updated:
        raise HTTPException(status_code=404, detail=f"Правило {rule_id} не найдено")
    await rule_engine.load_rules(DB_PATH)
    return updated

@app.post("/api/v1/rules/{rule_id}/toggle", tags=["api-rules"])
async def api_toggle_rule(rule_id: int, _: str = Depends(require_token)):
    rule = await toggle_rule(DB_PATH, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Правило {rule_id} не найдено")
    await rule_engine.load_rules(DB_PATH)
    return rule

@app.delete("/api/v1/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["api-rules"])
async def api_delete_rule(rule_id: int, _: str = Depends(require_token)):
    ok = await delete_rule(DB_PATH, rule_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Правило {rule_id} не найдено")
    await rule_engine.load_rules(DB_PATH)


# ═══════════════════════════════════════════════════════════════════════════════
# REST API — IP Lists
# ═══════════════════════════════════════════════════════════════════════════════

class IpEntry(BaseModel):
    ip: str; action: str; comment: str = ""

@app.get("/api/v1/ip-list", tags=["api-ip"])
async def api_ip_list(_: str = Depends(require_token)):
    return {"ip_list": await ip_filter.get_all()}

@app.post("/api/v1/ip-list", status_code=status.HTTP_201_CREATED, tags=["api-ip"])
async def api_ip_add(body: IpEntry, _: str = Depends(require_token)):
    if body.action not in ("allow", "block"):
        raise HTTPException(status_code=400, detail="action must be 'allow' or 'block'")
    await ip_filter.add_ip(body.ip, body.action, body.comment)  # type: ignore[arg-type]
    return {"status": "ok", "ip": body.ip, "action": body.action}

@app.delete("/api/v1/ip-list/{ip}", status_code=status.HTTP_204_NO_CONTENT, tags=["api-ip"])
async def api_ip_remove(ip: str, _: str = Depends(require_token)):
    await ip_filter.remove_ip(ip)


@app.get("/api/v1/report/pdf", tags=["api-report"])
async def api_pdf_report(request: Request, _: str = Depends(no_auth)):
    """
    Генерирует и скачивает PDF отчёт об эффективности WAF.
    Параметры:
      section=full|events|incidents — какие разделы включить (по умолчанию full)
      action=all|block|detect|allow — фильтр событий для раздела events
    """
    from modules.pdf_report import generate_pdf_report
    section = request.query_params.get("section", "full")
    action  = request.query_params.get("action", "all")

    stats      = await get_events_stats(DB_PATH)
    chart_data = await get_chart_data(DB_PATH)
    incidents  = await get_recent_incidents(DB_PATH, limit=200)

    # Раздел "события" — фильтруем по action и берём только нужную статистику
    events_filtered = None
    if section == "events":
        events_filtered, total_filtered = await get_events_paginated(
            DB_PATH, page=1, per_page=500,
            action_filter=None if action == "all" else action,
        )
        incidents = []  # не включаем инциденты в отчёт по событиям
    elif section == "incidents":
        events_filtered = None
        chart_data = {"rules": {"labels": [], "values": []}, "top_ips": {"labels": [], "values": []},
                       "hourly": chart_data.get("hourly", {}), "daily": chart_data.get("daily", {})}
    # section == "full" — всё как есть

    pdf_bytes = generate_pdf_report(
        stats        = stats,
        chart_data   = chart_data,
        incidents    = incidents,
        waf_mode     = WAF_MODE,
        rate_limit   = RATE_LIMIT,
        events       = events_filtered,
        section      = section,
        action_filter= action,
    )

    suffix = {"events": "events", "incidents": "incidents", "full": "full"}.get(section, "full")
    filename = f"waf_report_{suffix}_{_today()}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/v1/charts", tags=["api-charts"])
async def api_charts(period: str = "24h", _: str = Depends(no_auth)):
    """Данные для графиков дашборда. period: 24h | 7d | 30d"""
    if period not in ("24h", "7d", "30d"):
        period = "24h"
    data = await get_chart_data(DB_PATH, period=period)
    return data


@app.get("/api/v1/geo", tags=["api-geo"])
async def api_geo(_: str = Depends(no_auth)):
    """Возвращает уникальные IP для отображения на карте."""
    ips = await get_unique_ips(DB_PATH, limit=200)
    return {"ips": ips}


# ═══════════════════════════════════════════════════════════════════════════════
# Reverse Proxy (catch-all)
# ═══════════════════════════════════════════════════════════════════════════════

@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
    tags=["proxy"],
)
async def waf_proxy(request: Request, path: str):
    parsed    = await parse_request(request)
    client_ip = parsed["client_ip"]

    # 1. IP filter
    ip_action, ip_reason = await ip_filter.check(client_ip)
    if ip_action == "block":
        event = {**parsed, "action": "block", "rule_name": f"IP Blocklist: {ip_reason}",
                 "rule_id": None, "severity": "high", "target": "ip", "matched": client_ip}
        await event_logger.log(parsed, "block", {
            "rule_id": None, "name": f"IP Blocklist: {ip_reason}",
            "severity": "high", "target": "ip", "matched": client_ip,
        })
        await correlator.process_event({**parsed, "action": "block", "rule_name": "IP Blocklist"})
        return JSONResponse(status_code=403,
                            content={"error": "Forbidden", "message": ip_reason})

    # 2. Rate limiting
    allowed, _ = rate_limiter.is_allowed(client_ip)
    if not allowed:
        await event_logger.log(parsed, "block", {
            "rule_id": None, "name": "Rate Limit Exceeded",
            "severity": "medium", "target": "ip", "matched": client_ip,
        })
        await correlator.process_event({**parsed, "action": "block", "rule_name": "Rate Limit Exceeded"})
        asyncio.create_task(tg.send_rate_limit(client_ip, RATE_LIMIT))
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": "60", "X-RateLimit-Limit": str(RATE_LIMIT)},
            content={"error": "Too Many Requests",
                     "message": f"Лимит: {RATE_LIMIT} запросов/мин"},
        )

    # 3. Rule engine
    matches = rule_engine.analyze(parsed)
    action, triggered_rule = decision_engine.decide(matches)

    # 4. Log
    await event_logger.log(request=parsed, action=action, rule=triggered_rule)

    # 5. Корреляция — передаём событие в correlator
    corr_event = {
        **parsed,
        "action":    action,
        "rule_name": triggered_rule["name"] if triggered_rule else "",
        "severity":  triggered_rule["severity"] if triggered_rule else "",
    }
    await correlator.process_event(corr_event)

    # 6. Block или pass
    if action == "block":
        return JSONResponse(status_code=403, content={
            "error":   "Forbidden",
            "message": "Request blocked by WAF",
            "rule":    triggered_rule["name"] if triggered_rule else None,
        })

    return await forward_request(request, parsed, BACKEND_URL)


def _now()   -> str: return datetime.now(timezone.utc).isoformat()
def _today() -> str: return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
