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
current_scan = {'id': None, 'process': None, 'cancelled': False}
current_scan_guard = threading.Lock()

ALL_STEPS = {
    'discovery': ('host-discovery.py', 'Поиск хоста и проверка доступности'),
    'ports': ('top-port-scan.py', 'Сканирование открытых портов'),
    'os': ('os-detection.py', 'Определение операционной системы'),
    'services': ('service-scan.py', 'Определение служб на портах'),
    'ssl_certs': ('ssl-certs.py', 'Проверка SSL-сертификатов'),
    'ssl_ciphers': ('ssl-ciphers.py', 'Проверка защиты соединения (TLS)'),
    'headers': ('headers-check.py', 'Проверка заголовков безопасности'),
    'vuln': ('vuln-scan.py', 'Поиск известных уязвимостей'),
    'nikto': ('nikto-scan.py', 'Базовое сканирование веб-уязвимостей'),
}

REQUIRED_STEPS = ['discovery', 'ports', 'os', 'services', 'ssl_certs']

STEP_TIMEOUTS = {
    'vuln': 240,
    'nikto': 200,
}
DEFAULT_TIMEOUT = 120

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
            if name.endswith(('.xml', '.json', '.txt')):
                os.remove(os.path.join(folder, name))


def run_scan(scan_id, target, checks):
    label = ''
    try:
        clean_stage_dirs()
        env = os.environ.copy()
        env['SCAN_TARGET'] = target

        steps_to_run = list(dict.fromkeys(REQUIRED_STEPS + checks))

        for key in steps_to_run:
            with current_scan_guard:
                if current_scan['cancelled']:
                    mark_scan_error(scan_id, 'Сканирование остановлено пользователем')
                    return

            if key not in ALL_STEPS:
                continue
            script, label = ALL_STEPS[key]
            update_scan_step(scan_id, label)
            timeout = STEP_TIMEOUTS.get(key, DEFAULT_TIMEOUT)

            process = subprocess.Popen(
                [sys.executable, os.path.join(SCANNER_DIR, script)],
                cwd=SCANNER_DIR,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            with current_scan_guard:
                current_scan['process'] = process

            try:
                _, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                mark_scan_error(scan_id, f'Этап «{label}» выполнялся слишком долго')
                return

            with current_scan_guard:
                was_cancelled = current_scan['cancelled']

            if was_cancelled:
                mark_scan_error(scan_id, 'Сканирование остановлено пользователем')
                return

            if process.returncode != 0:
                mark_scan_error(scan_id, f'Ошибка на этапе «{label}»: {stderr[-500:]}')
                return

        update_scan_step(scan_id, 'Формирование отчёта')
        mark_scan_done(scan_id, build_report_dict(target))
    except Exception as e:
        mark_scan_error(scan_id, str(e))
    finally:
        with current_scan_guard:
            current_scan['id'] = None
            current_scan['process'] = None
            current_scan['cancelled'] = False
        scan_lock.release()


@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.get_json(silent=True) or {}
    target = clean_target(data.get('target'))
    checks = data.get('checks') or []
    checks = [c for c in checks if c in ALL_STEPS]

    if not is_valid_target(target):
        return jsonify({'error': 'Некорректный адрес. Введите домен (example.com) или IPv4-адрес.'}), 400

    if not scan_lock.acquire(blocking=False):
        return jsonify({'error': 'Сейчас уже идёт другое сканирование. Дождитесь его завершения.'}), 409

    try:
        scan_id = create_scan(target)
        with current_scan_guard:
            current_scan['id'] = scan_id
            current_scan['process'] = None
            current_scan['cancelled'] = False
        threading.Thread(target=run_scan, args=(scan_id, target, checks), daemon=True).start()
    except Exception:
        scan_lock.release()
        raise

    return jsonify({'scan_id': scan_id, 'status': 'running'}), 202


@app.route('/api/scan/<int:scan_id>/cancel', methods=['POST'])
def cancel_scan(scan_id):
    with current_scan_guard:
        if current_scan['id'] != scan_id:
            return jsonify({'error': 'Этот скан уже не выполняется'}), 409
        current_scan['cancelled'] = True
        process = current_scan['process']

    if process is not None and process.poll() is None:
        process.kill()

    return jsonify({'status': 'cancelling'})


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