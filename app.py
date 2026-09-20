#!/usr/bin/python3
import ipaddress
import os
import re
import subprocess
import sys
import threading
from urllib.parse import urlparse

from flask import Flask, request, jsonify
from flask_cors import CORS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCANNER_DIR = os.path.join(BASE_DIR, 'scanner')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')

sys.path.insert(0, BASE_DIR)
sys.path.insert(0, SCANNER_DIR)

from db import (init_db, create_scan, mark_scan_done, mark_scan_error, get_scan,
                get_history, update_scan_step, fail_interrupted_scans)
from report_builder import build_report_dict

app = Flask(__name__)
app.json.ensure_ascii = False
CORS(app)

scan_lock = threading.Lock()

STEPS = [
    ('host-discovery.py', 'Поиск хоста и проверка доступности'),
    ('top-port-scan.py', 'Сканирование открытых портов'),
    ('os-detection.py', 'Определение операционной системы'),
    ('service-scan.py', 'Определение служб на портах'),
    ('ssl-certs.py', 'Проверка SSL-сертификатов'),
    ('ssl-ciphers.py', 'Проверка защиты соединения (TLS)'),
]
STEP_TIMEOUT = 300

DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')


def clean_target(raw):
    raw = (raw or '').strip().lower()
    if '://' in raw:
        return urlparse(raw).hostname or ''
    return raw.split('/')[0].split(':')[0]


def is_valid_target(target):
    try:
        ipaddress.IPv4Address(target)
        return True
    except ValueError:
        return bool(DOMAIN_RE.match(target))


def clean_stage_dirs():
    for stage in ('Stage_1', 'Stage_2'):
        folder = os.path.join(REPORTS_DIR, stage)
        os.makedirs(folder, exist_ok=True)
        for name in os.listdir(folder):
            if name.endswith('.xml'):
                os.remove(os.path.join(folder, name))


def run_scan(scan_id, target):
    label = ''
    try:
        clean_stage_dirs()
        env = os.environ.copy()
        env['SCAN_TARGET'] = target

        for script, label in STEPS:
            update_scan_step(scan_id, label)
            result = subprocess.run(
                [sys.executable, os.path.join(SCANNER_DIR, script)],
                cwd=SCANNER_DIR,
                env=env,
                capture_output=True,
                text=True,
                timeout=STEP_TIMEOUT,
            )
            if result.returncode != 0:
                mark_scan_error(scan_id, f'Ошибка на этапе «{label}»: {result.stderr[-500:]}')
                return

        update_scan_step(scan_id, 'Формирование отчёта')
        mark_scan_done(scan_id, build_report_dict(target))
    except subprocess.TimeoutExpired:
        mark_scan_error(scan_id, f'Этап «{label}» выполнялся слишком долго')
    except Exception as e:
        mark_scan_error(scan_id, str(e))
    finally:
        scan_lock.release()


@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.get_json(silent=True) or {}
    target = clean_target(data.get('target'))

    if not is_valid_target(target):
        return jsonify({'error': 'Некорректный адрес. Введите домен (example.com) или IPv4-адрес.'}), 400

    if not scan_lock.acquire(blocking=False):
        return jsonify({'error': 'Сейчас уже идёт другое сканирование. Дождитесь его завершения.'}), 409

    try:
        scan_id = create_scan(target)
        threading.Thread(target=run_scan, args=(scan_id, target), daemon=True).start()
    except Exception:
        scan_lock.release()
        raise

    return jsonify({'scan_id': scan_id, 'status': 'running'}), 202


@app.route('/api/scan/<int:scan_id>/status', methods=['GET'])
def scan_status(scan_id):
    scan = get_scan(scan_id)
    if scan is None:
        return jsonify({'error': 'Скан не найден'}), 404
    return jsonify({
        'scan_id': scan['id'],
        'target': scan['target'],
        'status': scan['status'],
        'current_step': scan.get('current_step'),
        'error_message': scan.get('error_message'),
    })


@app.route('/api/scan/<int:scan_id>/report', methods=['GET'])
def scan_report(scan_id):
    scan = get_scan(scan_id)
    if scan is None:
        return jsonify({'error': 'Скан не найден'}), 404
    if scan['status'] != 'done':
        return jsonify({'error': 'Отчёт ещё не готов', 'status': scan['status']}), 409
    return jsonify(scan['report'])


@app.route('/api/history', methods=['GET'])
def history():
    return jsonify(get_history())


if __name__ == '__main__':
    init_db()
    fail_interrupted_scans()
    app.run(host='127.0.0.1', port=5000, debug=False)