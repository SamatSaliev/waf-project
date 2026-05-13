# Python WAF — Этап 1: Прототип

Reverse-Proxy Web Application Firewall на FastAPI + SQLite.

## Файловая структура

```
waf-project/
├── docker-compose.yml
├── README.md
├── backend/                  # Тестовый backend (Flask)
│   ├── Dockerfile
│   └── app.py
└── waf/                      # Основной сервис WAF
    ├── Dockerfile
    ├── requirements.txt
    ├── main.py               # Точка входа FastAPI
    ├── modules/
    │   ├── __init__.py
    │   ├── request_parser.py  # Разбор входящего HTTP-запроса
    │   ├── rule_engine.py     # Хранение и применение правил (regex)
    │   ├── decision_engine.py # Принятие решения: block / detect / allow
    │   ├── logger.py          # Запись событий в JSONL + SQLite
    │   ├── database.py        # DDL и вспомогательные запросы
    │   └── proxy.py           # Проксирование на backend (httpx)
    └── templates/
        └── dashboard.html     # Веб-интерфейс администратора
```

## Быстрый старт

### 1. Требования

- Docker >= 24
- Docker Compose >= 2.20

### 2. Запуск

```bash
# Клонируем / переходим в директорию проекта
cd waf-project

# Поднимаем оба сервиса
docker compose up --build
```

После сборки:
| Сервис          | URL                              |
|-----------------|----------------------------------|
| WAF (прокси)    | http://localhost:8080            |
| Admin Dashboard | http://localhost:8080/waf-admin  |
| Backend (скрыт) | доступен только внутри Docker    |

### 3. Переменные окружения (docker-compose.yml)

| Переменная    | По умолчанию               | Описание                           |
|---------------|----------------------------|------------------------------------|
| `BACKEND_URL` | `http://backend:5000`      | Адрес защищаемого приложения       |
| `WAF_MODE`    | `blocking`                 | `blocking` или `detection`         |
| `DB_PATH`     | `/data/waf.db`             | Путь к SQLite базе данных          |
| `LOG_PATH`    | `/data/events.jsonl`       | Путь к JSON-логу событий           |

### 4. Смена режима без пересборки

```bash
# Переключить в режим только обнаружения
docker compose stop waf
WAF_MODE=detection docker compose up waf -d
```

---

## Тестирование правил

Используйте `curl` для проверки правил WAF.

### Легитимный запрос (должен пройти)
```bash
curl "http://localhost:8080/search?q=python+tutorial"
```

### SQL Injection — UNION SELECT (должен быть заблокирован)
```bash
curl "http://localhost:8080/search?q=1+UNION+SELECT+username,password+FROM+users"
```

### SQL Injection — Тавтология (должен быть заблокирован)
```bash
curl "http://localhost:8080/search?q=admin'+OR+1=1--"
```

### SQL Injection — Комментарий
```bash
curl "http://localhost:8080/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin--", "password": "anything"}'
```

### XSS — Script tag (должен быть заблокирован)
```bash
curl "http://localhost:8080/comment" \
  -H "Content-Type: application/json" \
  -d '{"text": "<script>alert(document.cookie)</script>"}'
```

### XSS — Event handler (должен быть заблокирован)
```bash
curl "http://localhost:8080/comment" \
  -H "Content-Type: application/json" \
  -d '{"text": "<img src=x onerror=alert(1)>"}'
```

### XSS — javascript: URI (должен быть заблокирован)
```bash
curl "http://localhost:8080/search?q=javascript:alert(1)"
```

### Path Traversal (должен быть заблокирован)
```bash
curl "http://localhost:8080/../../etc/passwd"
```

---

## Просмотр логов

### Веб-интерфейс
Откройте http://localhost:8080/waf-admin — таблица последних 100 событий
с возможностью фильтрации по действию (block / detect / allow).

### JSON API
```bash
curl http://localhost:8080/waf-admin/api/events | python3 -m json.tool
```

### JSONL-файл (внутри контейнера)
```bash
docker exec waf tail -f /data/events.jsonl | python3 -m json.tool
```

### SQLite напрямую
```bash
docker exec -it waf sqlite3 /data/waf.db \
  "SELECT timestamp, action, rule_name, path FROM events ORDER BY id DESC LIMIT 20;"
```

---

## Встроенные правила

| ID | Название                  | Паттерн (упрощённо)         | Severity | Цели               |
|----|---------------------------|------------------------------|----------|--------------------|
| 1  | SQLi — UNION-based        | `UNION ... SELECT`           | high     | query, body, uri   |
| 2  | SQLi — Boolean/Tautology  | `OR/AND N=N`                 | high     | query, body, uri   |
| 3  | SQLi — Comment sequences  | `--, #, /* */`               | medium   | query, body        |
| 4  | XSS — Script tag          | `<script`                    | high     | query, body, uri   |
| 5  | XSS — Event handler       | `on*=`                       | medium   | query, body, uri   |
| 6  | XSS — javascript: URI     | `javascript:`                | high     | query, body, uri, cookie |
| 7  | Path Traversal            | `../../`                     | high     | uri, query         |

---

## Архитектура (поток данных)

```
Клиент → [WAF :8080]
              │
              ├─ request_parser  → нормализует запрос
              ├─ rule_engine     → применяет regex-правила
              ├─ decision_engine → block / detect / allow
              ├─ logger          → SQLite + JSONL
              │
              ├─ [403 Forbidden] ← если action = block
              │
              └─ [Backend :5000] ← если action = allow / detect
```

## Следующие этапы

- Этап 2: Rate limiting, IP allowlist/blocklist, правила на основе OWASP CRS
- Этап 3: REST API для управления правилами, аутентификация дашборда
- Этап 4: Нагрузочное тестирование, метрики Prometheus
