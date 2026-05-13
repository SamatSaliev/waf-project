# Этап 4 — Нагрузочное тестирование и анализ WAF

## Файловая структура

```
testing/
├── locust/
│   └── locustfile.py          # Сценарий нагрузочного теста (Locust)
├── k6/
│   └── script.js              # Сценарий нагрузочного теста (k6)
├── results/                   # Создаётся автоматически — отчёты
├── analyze.py                 # Генератор отчёта (таблица + графики)
├── requirements.txt           # Зависимости для analyze.py
├── docker-compose.test.yml    # Запуск Locust в Docker
└── README.md
```

---

## Предварительные требования

WAF должен быть запущен:
```cmd
cd waf-project
docker compose up -d
```

---

## Вариант 1 — Locust

### Через Docker (рекомендуется, ничего не устанавливать)

```cmd
cd testing
mkdir results
docker compose -f docker-compose.test.yml up
```

Результаты сохранятся в `testing/results/`:
- `locust_report.html` — встроенный Locust-отчёт
- `locust_report_stats.csv` — статистика по эндпоинтам
- `locust_report_failures.csv` — ошибки

### Через pip (локально)

```cmd
pip install locust
mkdir results
locust -f locust/locustfile.py ^
       --host https://localhost:8443 ^
       --users 100 --spawn-rate 10 --run-time 60s ^
       --headless ^
       --csv results/locust_report ^
       --html results/locust_report.html
```

---

## Вариант 2 — k6

### Установка k6 (Windows)

```cmd
winget install k6 --source winget
```

Или скачайте с https://k6.io/docs/get-started/installation/

### Запуск

```cmd
cd testing
mkdir results
k6 run --insecure-skip-tls-verify ^
       --out json=results/k6_raw.json ^
       k6/script.js
```

k6 выводит итоговые метрики прямо в консоль:
- `waf_attack_detection_rate` — доля заблокированных атак (цель: > 80%)
- `waf_legit_pass_rate`       — доля пропущенных легитимных (цель: > 90%)
- `http_req_duration p(95)`   — 95-й перцентиль времени ответа (цель: < 2с)

---

## Генерация итогового отчёта

После любого нагрузочного теста запустите анализатор:

```cmd
cd testing
pip install -r requirements.txt

python analyze.py ^
  --url https://localhost:8443 ^
  --token my-secret-token-change-me ^
  --out results/waf_report.html
```

Откройте `results/waf_report.html` в браузере — там:
- 4 ключевые метрики (Detection Rate, FP Rate, атак, легитимных)
- Круговая диаграмма распределения запросов
- Гистограмма топ сработавших правил
- Временная шкала трафика
- Топ заблокированных IP

---

## Что означают метрики

| Метрика | Формула | Хорошее значение |
|---------|---------|-----------------|
| Detection Rate | заблокировано / (block + detect) | > 80% |
| False Positive Rate | detect / total | < 5% |
| Throughput | запросов / сек | зависит от железа |
| p95 Response Time | 95-й перцентиль | < 2000 мс |

---

## Типичные результаты

При 100 пользователях / 60 секунд ожидается:
- ~3000–5000 запросов всего
- ~900–1500 атак (30% трафика)
- Detection Rate: 85–95%
- p95 Response Time: 50–300 мс (локально)
