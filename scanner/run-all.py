#!/usr/bin/python3
import subprocess
import sys
import os
from urllib.parse import urlparse

SCRIPTS = [
    "host-discovery.py",
    "top-port-scan.py",
    "os-detection.py",
    "service-scan.py",
    "ssl-certs.py",
    "ssl-ciphers.py",
    "report.py",
]


def clean_target(raw):
    raw = raw.strip()
    if '://' in raw:
        raw = urlparse(raw).netloc or urlparse(raw).path
    return raw.strip('/')


def main():
    if len(sys.argv) > 1:
        target = clean_target(sys.argv[1])
    else:
        target = clean_target(input("Введите цель (IP/домен/подсеть): "))

    if not target:
        print("[!] Цель не может быть пустой")
        sys.exit(1)

    print(f"[i] Цель после очистки: {target}")

    env = os.environ.copy()
    env["SCAN_TARGET"] = target

    base_dir = os.path.dirname(os.path.abspath(__file__))

    for script in SCRIPTS:
        path = os.path.join(base_dir, script)
        print(f"\n=== Запуск {script} ===")
        result = subprocess.run(
            [sys.executable, path],
            env=env,
        )
        if result.returncode != 0:
            print(f"[!] {script} завершился с ошибкой (код {result.returncode}), продолжаю дальше")

    print("\n=== Готово ===")


if __name__ == "__main__":
    main()
