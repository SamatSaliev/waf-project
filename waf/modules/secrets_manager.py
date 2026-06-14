"""
secrets_manager.py — загрузка и расшифровка секретов WAF из зашифрованного файла.

Принцип работы:
  1. Все пароли/токены хранятся в файле secrets.enc.json в зашифрованном виде
     (значения зашифрованы алгоритмом Fernet — AES-128-CBC + HMAC).
  2. Master-ключ для расшифровки хранится ОТДЕЛЬНО — в переменной окружения
     WAF_MASTER_KEY или в файле /run/secrets/master.key (Docker secret).
  3. При старте WAF расшифровывает все значения в память (os.environ),
     дальше код работает с os.getenv() как обычно — никаких изменений
     в остальных модулях не требуется.

Если secrets.enc.json отсутствует или WAF_MASTER_KEY не задан —
модуль просто ничего не делает, и WAF использует обычные переменные
окружения из docker-compose.yml (обратная совместимость).
"""

from __future__ import annotations

import json
import logging
import os

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("waf.secrets")

SECRETS_FILE     = os.getenv("SECRETS_FILE", "/app/secrets.enc.json")
MASTER_KEY_FILE  = os.getenv("MASTER_KEY_FILE", "/run/secrets/master.key")


def _load_master_key() -> bytes | None:
    """
    Источники master-ключа (по приоритету):
      1. Переменная окружения WAF_MASTER_KEY
      2. Файл /run/secrets/master.key (Docker secret)
    """
    env_key = os.getenv("WAF_MASTER_KEY", "").strip()
    if env_key:
        return env_key.encode()

    if os.path.exists(MASTER_KEY_FILE):
        try:
            with open(MASTER_KEY_FILE, "rb") as f:
                return f.read().strip()
        except Exception as e:
            logger.error("Не удалось прочитать %s: %s", MASTER_KEY_FILE, e)

    return None


def load_encrypted_secrets() -> int:
    """
    Расшифровывает secrets.enc.json и записывает значения в os.environ
    (только если переменная ещё не задана — secrets.enc.json не перезаписывает
    значения, явно переданные через docker-compose environment).

    Возвращает количество успешно расшифрованных и применённых переменных.
    """
    if not os.path.exists(SECRETS_FILE):
        logger.info("Файл секретов %s не найден — используются обычные env-переменные", SECRETS_FILE)
        return 0

    master_key = _load_master_key()
    if not master_key:
        logger.warning(
            "secrets.enc.json найден, но WAF_MASTER_KEY не задан — "
            "зашифрованные секреты НЕ будут загружены"
        )
        return 0

    try:
        fernet = Fernet(master_key)
    except Exception as e:
        logger.error("Неверный формат WAF_MASTER_KEY: %s", e)
        return 0

    try:
        with open(SECRETS_FILE, "r", encoding="utf-8") as f:
            encrypted = json.load(f)
    except Exception as e:
        logger.error("Не удалось прочитать %s: %s", SECRETS_FILE, e)
        return 0

    applied = 0
    for key, enc_value in encrypted.items():
        try:
            decrypted = fernet.decrypt(enc_value.encode()).decode()
        except InvalidToken:
            logger.error("Не удалось расшифровать %s — неверный master-ключ?", key)
            continue
        except Exception as e:
            logger.error("Ошибка расшифровки %s: %s", key, e)
            continue

        # Не перезаписываем значения, явно заданные в docker-compose
        if key in os.environ and os.environ[key]:
            continue

        os.environ[key] = decrypted
        applied += 1

    logger.info("Загружено зашифрованных секретов: %d из %d", applied, len(encrypted))
    return applied
