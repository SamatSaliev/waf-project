/**
 * k6 нагрузочный тест WAF
 *
 * Запуск:
 *   k6 run --insecure-skip-tls-verify script.js
 *
 * С HTML-отчётом:
 *   k6 run --insecure-skip-tls-verify --out json=results/k6_raw.json script.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// ── Метрики ──────────────────────────────────────────────────────────────────
const blockedRequests = new Counter('waf_blocked_requests');
const attackRate      = new Rate('waf_attack_detection_rate');
const legitRate       = new Rate('waf_legit_pass_rate');
const responseTime    = new Trend('waf_response_time_ms');

// ── Конфигурация теста ────────────────────────────────────────────────────────
export const options = {
  scenarios: {
    legitimate_users: {
      executor:   'ramping-vus',
      startVUs:   0,
      stages: [
        { duration: '10s', target: 70 },  // разогрев
        { duration: '40s', target: 70 },  // основная нагрузка
        { duration: '10s', target: 0  },  // остывание
      ],
      exec: 'legitimateUser',
    },
    attackers: {
      executor:   'ramping-vus',
      startVUs:   0,
      stages: [
        { duration: '10s', target: 30 },
        { duration: '40s', target: 30 },
        { duration: '10s', target: 0  },
      ],
      exec: 'attackerUser',
    },
  },
  thresholds: {
    http_req_duration:          ['p(95)<2000'],  // 95% запросов быстрее 2с
    waf_attack_detection_rate:  ['rate>0.8'],    // WAF блокирует >80% атак
    waf_legit_pass_rate:        ['rate>0.9'],    // >90% легитимных проходит
  },
  insecureSkipTLSVerify: true,
};

const BASE_URL = 'https://localhost:8443';

// ── Payload'ы ─────────────────────────────────────────────────────────────────
const SQLI = [
  "1 UNION SELECT username,password FROM users",
  "' OR 1=1 --",
  "1 AND SLEEP(3)--",
  "'; DROP TABLE users--",
];
const XSS = [
  "<script>alert(document.cookie)</script>",
  "<img src=x onerror=alert(1)>",
  "javascript:alert(1)",
];
const CMDI = ["; cat /etc/passwd", "| whoami", "`id`"];
const LEGIT_QUERIES = [
  "python tutorial", "web security", "linux commands",
  "docker guide", "REST API", "database tips",
];

function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

// ── Сценарий: легитимный пользователь ────────────────────────────────────────
export function legitimateUser() {
  const action = Math.random();
  let res;

  if (action < 0.4) {
    res = http.get(`${BASE_URL}/search?q=${pick(LEGIT_QUERIES)}`);
  } else if (action < 0.7) {
    res = http.get(`${BASE_URL}/`);
  } else if (action < 0.85) {
    res = http.get(`${BASE_URL}/health`);
  } else {
    res = http.post(`${BASE_URL}/login`,
      JSON.stringify({ username: 'alice', password: 'secret' }),
      { headers: { 'Content-Type': 'application/json' } });
  }

  responseTime.add(res.timings.duration);
  const passed = check(res, { 'legit: not blocked': (r) => r.status !== 403 });
  legitRate.add(passed);
  sleep(0.5 + Math.random() * 1.5);
}

// ── Сценарий: атакующий ───────────────────────────────────────────────────────
export function attackerUser() {
  const action = Math.random();
  let res;

  if (action < 0.35) {
    res = http.get(`${BASE_URL}/search?q=${pick(SQLI)}`);
  } else if (action < 0.6) {
    res = http.post(`${BASE_URL}/comment`,
      JSON.stringify({ text: pick(XSS) }),
      { headers: { 'Content-Type': 'application/json' } });
  } else if (action < 0.75) {
    res = http.post(`${BASE_URL}/login`,
      JSON.stringify({ username: pick(SQLI), password: 'x' }),
      { headers: { 'Content-Type': 'application/json' } });
  } else if (action < 0.88) {
    res = http.get(`${BASE_URL}/search?q=${pick(CMDI)}`);
  } else {
    res = http.get(`${BASE_URL}/../../../etc/passwd`);
  }

  responseTime.add(res.timings.duration);
  const blocked = check(res, { 'attack: blocked by WAF': (r) => r.status === 403 });
  if (blocked) blockedRequests.add(1);
  attackRate.add(blocked);
  sleep(0.2 + Math.random() * 0.8);
}
