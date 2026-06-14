#!/usr/bin/env python3
"""
encrypt_secrets.py — утилита для шифрования паролей/токенов WAF.

Использование:

  # 1. Сгенерировать новый master-ключ (один раз)
  python3 encrypt_secrets.py genkey

  # 2. Зашифровать значение
  python3 encrypt_secrets.py encrypt WAF_API_TOKEN "my-secret-token"

  # 3. Зашифровать несколько значений сразу из docker-compose.yml
  python3 encrypt_secrets.py encrypt-all

  # 4. Проверить расшифровку
  python3 encrypt_secrets.py decrypt WAF_API_TOKEN

Master-ключ нужно сохранить В ОТДЕЛЬНОМ МЕСТЕ (не в git!), например:
  - переменная окружения WAF_MASTER_KEY на хосте
  - Docker secret /run/secrets/master.key
  - менеджер паролей / сейф
"""

from __future__ import annotations

import json
import os
import sys

from cryptography.fernet import Fernet

SECRETS_FILE    = "secrets.enc.json"
MASTER_KEY_FILE = ".master.key"   # НЕ коммитить в git!


def genkey() -> None:
    """Генерирует новый master-ключ Fernet."""
    key = Fernet.generate_key()
    with open(MASTER_KEY_FILE, "wb") as f:
        f.write(key)
    os.chmod(MASTER_KEY_FILE, 0o600)
    print(f"✓ Master-ключ сохранён в {MASTER_KEY_FILE} (права 600)")
    print(f"\nКЛЮЧ (сохраните в безопасном месте, например менеджер паролей):")
    print(f"  {key.decode()}")
    print(f"\nДобавьте {MASTER_KEY_FILE} в .gitignore!")


def _load_key() -> bytes:
    env_key = os.getenv("WAF_MASTER_KEY", "").strip()
    if env_key:
        return env_key.encode()
    if os.path.exists(MASTER_KEY_FILE):
        with open(MASTER_KEY_FILE, "rb") as f:
            return f.read().strip()
    print("✗ Master-ключ не найден. Запустите: python3 encrypt_secrets.py genkey")
    sys.exit(1)


def _load_secrets() -> dict:
    if os.path.exists(SECRETS_FILE):
        with open(SECRETS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def _save_secrets(data: dict) -> None:
    with open(SECRETS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"✓ Сохранено в {SECRETS_FILE}")


def encrypt(key_name: str, value: str) -> None:
    fernet = Fernet(_load_key())
    secrets = _load_secrets()
    secrets[key_name] = fernet.encrypt(value.encode()).decode()
    _save_secrets(secrets)
    print(f"✓ {key_name} зашифрован и добавлен в {SECRETS_FILE}")


def decrypt(key_name: str) -> None:
    fernet = Fernet(_load_key())
    secrets = _load_secrets()
    if key_name not in secrets:
        print(f"✗ {key_name} не найден в {SECRETS_FILE}")
        return
    value = fernet.decrypt(secrets[key_name].encode()).decode()
    print(f"{key_name} = {value}")


def encrypt_all() -> None:
    """Интерактивно зашифровывает стандартный набор секретов WAF."""
    fernet = Fernet(_load_key())
    secrets = _load_secrets()

    prompts = [
        ("WAF_API_TOKEN",     "API токен для REST API"),
        ("DASHBOARD_PASSWORD","Пароль дашборда /waf-admin"),
        ("TG_BOT_TOKEN",      "Telegram Bot Token"),
        ("ELK_PASSWORD",      "Пароль Elasticsearch"),
    ]

    print("Введите значения для шифрования (Enter — пропустить):\n")
    for key_name, label in prompts:
        current = " (уже задан)" if key_name in secrets else ""
        value = input(f"  {label} [{key_name}]{current}: ").strip()
        if value:
            secrets[key_name] = fernet.encrypt(value.encode()).decode()
            print(f"    ✓ зашифрован")

    _save_secrets(secrets)


def list_keys() -> None:
    secrets = _load_secrets()
    if not secrets:
        print("Секретов нет.")
        return
    print(f"Зашифрованные ключи в {SECRETS_FILE}:")
    for k in secrets:
        print(f"  - {k}")


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        return

    cmd = sys.argv[1]

    if cmd == "genkey":
        genkey()
    elif cmd == "encrypt" and len(sys.argv) == 4:
        encrypt(sys.argv[2], sys.argv[3])
    elif cmd == "decrypt" and len(sys.argv) == 3:
        decrypt(sys.argv[2])
    elif cmd == "encrypt-all":
        encrypt_all()
    elif cmd == "list":
        list_keys()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
