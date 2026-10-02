#!/usr/bin/python3
import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
from urllib.parse import urlparse

import requests as http_client

from flask import Flask, request, jsonify, g
from flask_cors import CORS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCANNER_DIR = os.path.join(BASE_DIR, 'scanner')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')

sys.path.insert(0, BASE_DIR)
sys.path.insert(0, SCANNER_DIR)

from db import (init_db, create_scan, mark_scan_done, mark_scan_error, get_scan,
                get_history, update_scan_step, fail_interrupted_scans,
                create_user, authenticate_user, get_user_by_id,
                create_token, validate_token, delete_token, delete_expired_tokens,
                get_all_users, get_all_scans, get_admin_stats,
                set_user_admin, delete_user_by_id, delete_scan_by_id)
from report_builder import build_report_dict

app = Flask(__name__)
app.json.ensure_ascii = False
CORS(app)

# ---------------------------------------------------------------------------
#  Конфигурация Gemini AI
# ---------------------------------------------------------------------------

def load_env():
    """Загружает переменные из .env файла."""
    env_path = os.path.join(BASE_DIR, '.env')
    if os.path.exists(env_path):
        with open(env_path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, _, value = line.partition('=')
                    os.environ.setdefault(key.strip(), value.strip())

load_env()

GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')
GEMINI_MODELS = ['gemini-3.5-flash', 'gemini-3.8-flash', 'gemini-2.5-flash-lite']
GEMINI_API_BASE = 'https://generativelanguage.googleapis.com/v1beta/models'

GEMINI_SYSTEM_PROMPT = """Ты — «SiteScanner AI» — продвинутый ИБ-аналитик (специалист по информационной безопасности) встроенный в систему сканирования веб-ресурсов SiteScanner.

ТВОЯ ЭКСПЕРТИЗА:
• Сетевая безопасность (открытые порты, протоколы, службы)
• Криптография и SSL/TLS (сертификаты, шифры, оценка конфигурации)
• Веб-безопасность (заголовки, OWASP Top 10, XSS, CSRF, инъекции)
• Уязвимости CVE и их эксплуатация
• Hardening серверов (Linux, Windows, Nginx, Apache)
• Compliance (PCI DSS, GDPR, ISO 27001)
• Мониторинг и реагирование на инциденты
• Безопасность DNS, почтовых серверов, баз данных

ФОРМАТ ОТВЕТОВ:
1. Начинай с краткого резюме (1-2 предложения).
2. Используй структурированный формат:
   - **Проблема** → **Уровень опасности** (🔴 Критический / 🟠 Высокий / 🟡 Средний / 🟢 Низкий) → **Решение**
3. Давай конкретные примеры конфигов (Nginx, Apache, .htaccess) когда уместно.
4. Ссылайся на стандарты: CWE, CVE, OWASP когда это применимо.
5. В конце ответа — краткое **резюме действий** в виде нумерованного списка.

ПРАВИЛА:
- Отвечай на РУССКОМ языке.
- Если дан отчёт сканирования — анализируй именно его данные, не выдумывай.
- Если отчёта нет — отвечай на общие вопросы по информационной безопасности как эксперт.
- Используй markdown: **жирный**, заголовки (##, ###), списки, `код`.
- Будь профессиональным, но дружелюбным — объясняй так, чтобы понял даже новичок.
- Если видишь критическую проблему — выделяй её особо, начинай с неё.
- Оценивай общий уровень защищённости по шкале от A (отлично) до F (критически плохо)."""

GEMINI_SYSTEM_PROMPT_NO_REPORT = """Ты — «SiteScanner AI» — продвинутый ИБ-аналитик, встроенный в систему сканирования.
Сейчас у пользователя нет активного отчёта. Помогай с общими вопросами по кибербезопасности:
- Объясняй термины (порты, протоколы, уязвимости, шифрование)
- Давай советы по защите серверов и сайтов
- Рассказывай про лучшие практики ИБ
- Отвечай на вопросы про OWASP, CVE, CWE
Отвечай на РУССКОМ. Используй markdown. Будь экспертом, но объясняй понятно."""

scan_lock = threading.Lock()
current_scan = {'id': None, 'processes': [], 'cancelled': False}
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

SEQUENTIAL_STEPS = ['discovery', 'ports']
REQUIRED_PARALLEL_STEPS = ['os', 'services', 'ssl_certs']

STEP_TIMEOUTS = {
    'vuln': 300,
    'nikto': 300,
}
DEFAULT_TIMEOUT = 90

PORT_DEPTHS = {
    'fast': '--top-ports 100',
    'normal': '--top-ports 1000',
    'full': '-p-',
}
DEFAULT_PORT_DEPTH = 'normal'

DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')

USERNAME_RE = re.compile(r'^[a-zA-Zа-яА-ЯёЁ0-9_]{3,30}$')
MIN_PASSWORD_LENGTH = 6


# ---------------------------------------------------------------------------
#  Авторизация — декоратор и хелперы
# ---------------------------------------------------------------------------

def get_current_user():
    """Извлекает пользователя из заголовка Authorization: Bearer <token>."""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    token = auth[7:]
    user_id = validate_token(token)
    if user_id is None:
        return None
    return get_user_by_id(user_id)


def login_required(f):
    """Декоратор: пропускает только авторизованных пользователей."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if user is None:
            return jsonify({'error': 'Необходимо войти в систему'}), 401
        g.user = user
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Декоратор: пропускает только администраторов."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if user is None:
            return jsonify({'error': 'Необходимо войти в систему'}), 401
        if not user.get('is_admin'):
            return jsonify({'error': 'Доступ запрещён: требуются права администратора'}), 403
        g.user = user
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
#  Эндпоинты авторизации
# ---------------------------------------------------------------------------

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not USERNAME_RE.match(username):
        return jsonify({'error': 'Имя пользователя: 3–30 символов (буквы, цифры, _)'}), 400
    if len(password) < MIN_PASSWORD_LENGTH:
        return jsonify({'error': f'Пароль должен быть не менее {MIN_PASSWORD_LENGTH} символов'}), 400

    user_id, is_admin = create_user(username, password)
    if user_id is None:
        return jsonify({'error': 'Пользователь с таким именем уже существует'}), 409

    token = create_token(user_id)
    return jsonify({
        'token': token,
        'user': {'id': user_id, 'username': username, 'is_admin': is_admin},
    }), 201


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    user = authenticate_user(username, password)
    if user is None:
        return jsonify({'error': 'Неверное имя пользователя или пароль'}), 401

    token = create_token(user['id'])
    return jsonify({
        'token': token,
        'user': {'id': user['id'], 'username': user['username'], 'is_admin': bool(user.get('is_admin'))},
    })


@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    token = request.headers.get('Authorization', '')[7:]
    delete_token(token)
    return jsonify({'ok': True})


@app.route('/api/auth/me', methods=['GET'])
@login_required
def me():
    return jsonify({'user': {
        'id': g.user['id'],
        'username': g.user['username'],
        'is_admin': g.user.get('is_admin', False),
    }})


# ---------------------------------------------------------------------------
#  Сканирование — хелперы
# ---------------------------------------------------------------------------

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


def register_process(process):
    with current_scan_guard:
        current_scan['processes'].append(process)


def is_cancelled():
    with current_scan_guard:
        return current_scan['cancelled']


def run_step(key, env, timeout):
    script, label = ALL_STEPS[key]
    process = subprocess.Popen(
        [sys.executable, os.path.join(SCANNER_DIR, script)],
        cwd=SCANNER_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    register_process(process)

    try:
        _, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        return key, label, False, f'Этап «{label}» выполнялся слишком долго'

    if is_cancelled():
        return key, label, False, 'Сканирование остановлено пользователем'

    if process.returncode != 0:
        return key, label, False, f'Ошибка на этапе «{label}»: {stderr[-500:]}'

    return key, label, True, None


def run_scan(scan_id, target, checks, port_depth):
    try:
        clean_stage_dirs()
        env = os.environ.copy()
        env['SCAN_TARGET'] = target
        env['PORT_FLAG'] = PORT_DEPTHS.get(port_depth, PORT_DEPTHS[DEFAULT_PORT_DEPTH])

        for key in SEQUENTIAL_STEPS:
            if is_cancelled():
                mark_scan_error(scan_id, 'Сканирование остановлено пользователем')
                return
            script, label = ALL_STEPS[key]
            update_scan_step(scan_id, label)
            timeout = STEP_TIMEOUTS.get(key, DEFAULT_TIMEOUT)
            _, _, ok, err = run_step(key, env, timeout)
            if not ok:
                mark_scan_error(scan_id, err)
                return

        parallel_keys = list(dict.fromkeys(REQUIRED_PARALLEL_STEPS + [c for c in checks if c in ALL_STEPS]))
        labels = [ALL_STEPS[k][1] for k in parallel_keys]
        update_scan_step(scan_id, 'Одновременно: ' + ', '.join(labels))

        errors = []
        with ThreadPoolExecutor(max_workers=len(parallel_keys)) as executor:
            futures = {
                executor.submit(run_step, key, env, STEP_TIMEOUTS.get(key, DEFAULT_TIMEOUT)): key
                for key in parallel_keys
            }
            for future in as_completed(futures):
                _, label, ok, err = future.result()
                if not ok:
                    errors.append(err)

        if is_cancelled():
            mark_scan_error(scan_id, 'Сканирование остановлено пользователем')
            return

        if errors:
            mark_scan_error(scan_id, errors[0])
            return

        update_scan_step(scan_id, 'Формирование отчёта')
        mark_scan_done(scan_id, build_report_dict(target))
    except Exception as e:
        mark_scan_error(scan_id, str(e))
    finally:
        with current_scan_guard:
            current_scan['id'] = None
            current_scan['processes'] = []
            current_scan['cancelled'] = False
        scan_lock.release()


# ---------------------------------------------------------------------------
#  Эндпоинты сканирования (защищены авторизацией)
# ---------------------------------------------------------------------------

@app.route('/api/scan', methods=['POST'])
@login_required
def start_scan():
    data = request.get_json(silent=True) or {}
    target = clean_target(data.get('target'))
    checks = data.get('checks') or []
    checks = [c for c in checks if c in ALL_STEPS]
    port_depth = data.get('port_depth', DEFAULT_PORT_DEPTH)
    if port_depth not in PORT_DEPTHS:
        port_depth = DEFAULT_PORT_DEPTH

    if not is_valid_target(target):
        return jsonify({'error': 'Некорректный адрес. Введите домен (example.com) или IPv4-адрес.'}), 400

    if not scan_lock.acquire(blocking=False):
        return jsonify({'error': 'Сейчас уже идёт другое сканирование. Дождитесь его завершения.'}), 409

    try:
        scan_id = create_scan(target, user_id=g.user['id'])
        with current_scan_guard:
            current_scan['id'] = scan_id
            current_scan['processes'] = []
            current_scan['cancelled'] = False
        threading.Thread(target=run_scan, args=(scan_id, target, checks, port_depth), daemon=True).start()
    except Exception:
        scan_lock.release()
        raise

    return jsonify({'scan_id': scan_id, 'status': 'running'}), 202


@app.route('/api/scan/<int:scan_id>/cancel', methods=['POST'])
@login_required
def cancel_scan(scan_id):
    with current_scan_guard:
        if current_scan['id'] != scan_id:
            return jsonify({'error': 'Этот скан уже не выполняется'}), 409
        current_scan['cancelled'] = True
        processes = list(current_scan['processes'])

    for process in processes:
        if process.poll() is None:
            process.kill()

    return jsonify({'status': 'cancelling'})


@app.route('/api/scan/<int:scan_id>/status', methods=['GET'])
@login_required
def scan_status(scan_id):
    scan = get_scan(scan_id, user_id=g.user['id'])
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
@login_required
def scan_report(scan_id):
    scan = get_scan(scan_id, user_id=g.user['id'])
    if scan is None:
        return jsonify({'error': 'Скан не найден'}), 404
    if scan['status'] != 'done':
        return jsonify({'error': 'Отчёт ещё не готов', 'status': scan['status']}), 409
    return jsonify(scan['report'])


@app.route('/api/history', methods=['GET'])
@login_required
def history():
    return jsonify(get_history(user_id=g.user['id']))


# ---------------------------------------------------------------------------
#  ИИ-консультант (Gemini)
# ---------------------------------------------------------------------------

def summarize_report(report):
    """Формирует краткую текстовую сводку отчёта для промпта Gemini."""
    lines = [f"Цель сканирования: {report.get('target', '?')}"]
    for host in report.get('hosts', []):
        lines.append(f"\nХост: {host.get('hostname') or host.get('ip')} ({host.get('ip')})")

        ports = host.get('open_ports', [])
        if ports:
            lines.append("Открытые порты: " + ', '.join(
                f"{p['port']}/{p.get('protocol','tcp')} ({p.get('service','?')})" for p in ports
            ))

        os_guesses = host.get('os_guesses', [])
        if os_guesses:
            lines.append("ОС: " + ', '.join(f"{o['name']} ({o['accuracy']}%)" for o in os_guesses))

        services = host.get('services', [])
        if services:
            lines.append("Службы: " + ', '.join(f"{s['port']}: {s['name']}" for s in services))

        certs = host.get('ssl_certs', [])
        if certs:
            for c in certs:
                lines.append(f"SSL-сертификат (порты {c.get('ports')}): выдан на {c.get('subject')}, "
                             f"издатель {c.get('issuer')}, до {c.get('valid_after')}"
                             + (" [НЕСООТВЕТСТВИЕ ДОМЕНА!]" if c.get('domain_mismatch') else ""))

        ciphers = host.get('ssl_ciphers', [])
        if ciphers:
            for c in ciphers:
                lines.append(f"TLS порт {c['port']}: протоколы {c.get('protocols')}, оценка {c.get('grade')}")

        hc = host.get('headers_check')
        if hc and not hc.get('error'):
            missing = hc.get('missing', [])
            if missing:
                lines.append("Отсутствуют заголовки безопасности: " + ', '.join(missing))
            else:
                lines.append("Все основные заголовки безопасности присутствуют.")

        vulns = host.get('vuln_findings', [])
        if vulns:
            for v in vulns:
                lines.append(f"Уязвимость (порт {v['port']}, {v['script']}): {v['output'][:300]}")

        nikto = host.get('nikto_findings', [])
        if nikto:
            lines.append("Nikto находки:\n" + '\n'.join(f"  - {n}" for n in nikto))

    return '\n'.join(lines)


@app.route('/api/ask', methods=['POST'])
@login_required
def ask_ai():
    if not GEMINI_API_KEY or GEMINI_API_KEY == 'ВСТАВЬ_СЮДА_СВОЙ_КЛЮЧ':
        return jsonify({'error': 'API-ключ Gemini не настроен. Укажите GEMINI_API_KEY в файле .env'}), 500

    data = request.get_json(silent=True) or {}
    question = (data.get('question') or '').strip()
    chat_history = data.get('history') or []
    scan_id = data.get('scan_id')

    if not question:
        return jsonify({'error': 'Введите вопрос'}), 400

    system_text = GEMINI_SYSTEM_PROMPT_NO_REPORT

    # Если есть скан, добавляем его в контекст
    if scan_id:
        scan = get_scan(scan_id, user_id=g.user['id'])
        if scan and scan['status'] == 'done' and 'report' in scan:
            report_summary = summarize_report(scan['report'])
            system_text = (
                GEMINI_SYSTEM_PROMPT
                + "\n\n--- ОТЧЁТ СКАНИРОВАНИЯ ---\n"
                + report_summary
                + "\n--- КОНЕЦ ОТЧЁТА ---"
            )

    # Формируем историю диалога
    contents = []
    for msg in chat_history[-10:]:  # Последние 10 сообщений
        role = 'user' if msg.get('role') == 'user' else 'model'
        contents.append({'role': role, 'parts': [{'text': msg['text']}]})
    
    contents.append({'role': 'user', 'parts': [{'text': question}]})

    body = {
        'system_instruction': {'parts': [{'text': system_text}]},
        'contents': contents,
        'generationConfig': {
            'temperature': 0.7,
            'maxOutputTokens': 2048,
        },
    }

    # Пробуем модели по очереди (fallback при 503)
    last_error = None
    for model in GEMINI_MODELS:
        url = f'{GEMINI_API_BASE}/{model}:generateContent'
        try:
            resp = http_client.post(
                url,
                params={'key': GEMINI_API_KEY},
                json=body,
                timeout=60,
            )
            if resp.status_code == 503:
                last_error = f'Модель {model} временно перегружена'
                continue  # пробуем следующую модель
            resp.raise_for_status()
            result = resp.json()
            answer = result['candidates'][0]['content']['parts'][0]['text']
            return jsonify({'answer': answer})
        except http_client.exceptions.Timeout:
            last_error = 'Gemini не ответил вовремя'
            continue
        except http_client.exceptions.RequestException:
            last_error = 'Ошибка связи с Gemini'
            continue
        except (KeyError, IndexError):
            last_error = 'Gemini вернул некорректный ответ'
            continue

    return jsonify({'error': f'{last_error}. Попробуйте ещё раз через минуту.'}), 502


# ---------------------------------------------------------------------------
#  Эндпоинты администрирования (только для администраторов)
# ---------------------------------------------------------------------------

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def admin_stats():
    return jsonify(get_admin_stats())


@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_users():
    return jsonify(get_all_users())


@app.route('/api/admin/scans', methods=['GET'])
@admin_required
def admin_scans():
    return jsonify(get_all_scans())


@app.route('/api/admin/users/<int:user_id>/toggle-admin', methods=['POST'])
@admin_required
def admin_toggle_admin(user_id):
    if user_id == g.user['id']:
        return jsonify({'error': 'Нельзя снять права администратора с самого себя'}), 400
    user = get_user_by_id(user_id)
    if user is None:
        return jsonify({'error': 'Пользователь не найден'}), 404
    new_status = not user['is_admin']
    set_user_admin(user_id, new_status)
    return jsonify({'ok': True, 'is_admin': new_status})


@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    if user_id == g.user['id']:
        return jsonify({'error': 'Нельзя удалить самого себя'}), 400
    user = get_user_by_id(user_id)
    if user is None:
        return jsonify({'error': 'Пользователь не найден'}), 404
    delete_user_by_id(user_id)
    return jsonify({'ok': True})


@app.route('/api/admin/scans/<int:scan_id>', methods=['DELETE'])
@admin_required
def admin_delete_scan(scan_id):
    delete_scan_by_id(scan_id)
    return jsonify({'ok': True})


if __name__ == '__main__':
    init_db()
    fail_interrupted_scans()
    delete_expired_tokens()
    app.run(host='127.0.0.1', port=5000, debug=False)