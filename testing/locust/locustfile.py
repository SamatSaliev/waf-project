"""
locustfile.py — нагрузочный тест WAF.

Сценарий моделирует реальный трафик:
  70% — легитимные запросы
  30% — атаки (SQLi, XSS, Command Injection, Path Traversal, SSRF)

Запуск (headless, 100 пользователей, 60 секунд):
  locust -f locustfile.py --host https://localhost:8443 \
         --users 100 --spawn-rate 10 --run-time 60s --headless \
         --csv=results/locust_report
"""

import random
from locust import HttpUser, between, task

# ── Атакующие payload'ы ───────────────────────────────────────────────────────
SQLI_PAYLOADS = [
    "1 UNION SELECT username, password FROM users",
    "' OR 1=1 --",
    "admin'--",
    "1; DROP TABLE users--",
    "1 AND SLEEP(3)--",
]

XSS_PAYLOADS = [
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
]

CMDI_PAYLOADS = [
    "; cat /etc/passwd",
    "| whoami",
    "`id`",
    "$(uname -a)",
]

PATH_TRAVERSAL_PAYLOADS = [
    "/../../../etc/passwd",
    "/..%2F..%2F..%2Fetc%2Fshadow",
    "/%2e%2e/%2e%2e/etc/passwd",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1/admin",
    "http://localhost:5000/internal",
    "file:///etc/passwd",
    "http://169.254.169.254/latest/meta-data/",
]

LEGIT_QUERIES = [
    "python tutorial", "web security", "fastapi docs",
    "docker guide", "linux commands", "REST API design",
    "database tips", "machine learning",
]


class LegitimateUser(HttpUser):
    """70% трафика — обычные пользователи."""
    weight    = 70
    wait_time = between(0.5, 2.0)

    @task(4)
    def search(self):
        q = random.choice(LEGIT_QUERIES)
        self.client.get(f"/search?q={q}", verify=False, name="/search [legit]")

    @task(3)
    def home(self):
        self.client.get("/", verify=False, name="/ [legit]")

    @task(2)
    def health(self):
        self.client.get("/health", verify=False, name="/health [legit]")

    @task(1)
    def login(self):
        self.client.post(
            "/login",
            json={"username": "alice", "password": "secret123"},
            verify=False,
            name="/login [legit]",
        )


class AttackerUser(HttpUser):
    """30% трафика — атакующий."""
    weight    = 30
    wait_time = between(0.2, 1.0)

    @task(3)
    def sqli_search(self):
        self.client.get(
            f"/search?q={random.choice(SQLI_PAYLOADS)}",
            verify=False, name="/search [SQLi]",
        )

    @task(2)
    def xss_comment(self):
        self.client.post(
            "/comment",
            json={"text": random.choice(XSS_PAYLOADS)},
            verify=False, name="/comment [XSS]",
        )

    @task(2)
    def sqli_login(self):
        self.client.post(
            "/login",
            json={"username": random.choice(SQLI_PAYLOADS), "password": "x"},
            verify=False, name="/login [SQLi]",
        )

    @task(1)
    def cmdi(self):
        self.client.get(
            f"/search?q={random.choice(CMDI_PAYLOADS)}",
            verify=False, name="/search [CMDi]",
        )

    @task(1)
    def path_traversal(self):
        self.client.get(
            random.choice(PATH_TRAVERSAL_PAYLOADS),
            verify=False, name="/.. [PathTraversal]",
        )

    @task(1)
    def ssrf(self):
        self.client.get(
            f"/search?url={random.choice(SSRF_PAYLOADS)}",
            verify=False, name="/search [SSRF]",
        )
