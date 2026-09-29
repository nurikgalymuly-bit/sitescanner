import sqlite3
import os
import json
import secrets
from datetime import datetime, timedelta

from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database.db')

TOKEN_LIFETIME_DAYS = 7


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


# ---------------------------------------------------------------------------
#  Инициализация базы данных
# ---------------------------------------------------------------------------

def init_db():
    conn = get_connection()

    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS user_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            token TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            current_step TEXT,
            created_at TEXT NOT NULL,
            finished_at TEXT,
            report_json TEXT,
            error_message TEXT
        )
    ''')

    # Миграция: добавить колонки, если их нет (для совместимости со старой БД)
    scan_cols = [row['name'] for row in conn.execute('PRAGMA table_info(scans)')]
    if 'current_step' not in scan_cols:
        conn.execute('ALTER TABLE scans ADD COLUMN current_step TEXT')
    if 'user_id' not in scan_cols:
        conn.execute('ALTER TABLE scans ADD COLUMN user_id INTEGER REFERENCES users(id)')

    user_cols = [row['name'] for row in conn.execute('PRAGMA table_info(users)')]
    if 'is_admin' not in user_cols:
        conn.execute('ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0')

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
#  Пользователи
# ---------------------------------------------------------------------------

def create_user(username, password):
    """Создаёт пользователя. Первый пользователь автоматически становится админом.
    Возвращает (user_id, is_admin) или (None, False) если имя занято."""
    conn = get_connection()
    try:
        # Первый пользователь в системе — автоматически админ
        count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        is_admin = 1 if count == 0 else 0
        cur = conn.execute(
            'INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)',
            (username.strip(), generate_password_hash(password), is_admin, datetime.now().isoformat())
        )
        conn.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        user_id = None
        is_admin = 0
    finally:
        conn.close()
    return user_id, bool(is_admin)


def authenticate_user(username, password):
    """Проверяет логин и пароль. Возвращает dict пользователя или None."""
    conn = get_connection()
    row = conn.execute(
        'SELECT * FROM users WHERE username = ? COLLATE NOCASE', (username.strip(),)
    ).fetchone()
    conn.close()
    if row is None:
        return None
    user = dict(row)
    if not check_password_hash(user['password_hash'], password):
        return None
    return user


def get_user_by_id(user_id):
    conn = get_connection()
    row = conn.execute(
        'SELECT id, username, is_admin, created_at FROM users WHERE id = ?', (user_id,)
    ).fetchone()
    conn.close()
    if row is None:
        return None
    user = dict(row)
    user['is_admin'] = bool(user['is_admin'])
    return user


# ---------------------------------------------------------------------------
#  Токены сессии
# ---------------------------------------------------------------------------

def create_token(user_id):
    """Генерирует криптографически стойкий токен и сохраняет в БД."""
    token = secrets.token_urlsafe(48)
    now = datetime.now()
    expires = now + timedelta(days=TOKEN_LIFETIME_DAYS)
    conn = get_connection()
    conn.execute(
        'INSERT INTO user_tokens (user_id, token, created_at, expires_at) VALUES (?, ?, ?, ?)',
        (user_id, token, now.isoformat(), expires.isoformat())
    )
    conn.commit()
    conn.close()
    return token


def validate_token(token):
    """Проверяет токен. Возвращает user_id или None если невалиден/истёк."""
    conn = get_connection()
    row = conn.execute(
        'SELECT user_id, expires_at FROM user_tokens WHERE token = ?', (token,)
    ).fetchone()
    conn.close()
    if row is None:
        return None
    if datetime.fromisoformat(row['expires_at']) < datetime.now():
        delete_token(token)
        return None
    return row['user_id']


def delete_token(token):
    """Удаляет токен (выход из системы)."""
    conn = get_connection()
    conn.execute('DELETE FROM user_tokens WHERE token = ?', (token,))
    conn.commit()
    conn.close()


def delete_expired_tokens():
    """Очищает все просроченные токены."""
    conn = get_connection()
    conn.execute('DELETE FROM user_tokens WHERE expires_at < ?', (datetime.now().isoformat(),))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
#  Сканирования
# ---------------------------------------------------------------------------

def fail_interrupted_scans():
    conn = get_connection()
    conn.execute(
        "UPDATE scans SET status = 'error', finished_at = ?, error_message = ? WHERE status = 'running'",
        (datetime.now().isoformat(), 'Сканирование прервано перезапуском сервера')
    )
    conn.commit()
    conn.close()


def create_scan(target, user_id=None):
    conn = get_connection()
    cur = conn.execute(
        'INSERT INTO scans (target, status, created_at, user_id) VALUES (?, ?, ?, ?)',
        (target, 'running', datetime.now().isoformat(), user_id)
    )
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return scan_id


def update_scan_step(scan_id, step):
    conn = get_connection()
    conn.execute('UPDATE scans SET current_step = ? WHERE id = ?', (step, scan_id))
    conn.commit()
    conn.close()


def mark_scan_done(scan_id, report_dict):
    conn = get_connection()
    conn.execute(
        'UPDATE scans SET status = ?, current_step = ?, finished_at = ?, report_json = ? WHERE id = ?',
        ('done', 'Готово', datetime.now().isoformat(), json.dumps(report_dict, ensure_ascii=False), scan_id)
    )
    conn.commit()
    conn.close()


def mark_scan_error(scan_id, error_message):
    conn = get_connection()
    conn.execute(
        'UPDATE scans SET status = ?, finished_at = ?, error_message = ? WHERE id = ?',
        ('error', datetime.now().isoformat(), error_message, scan_id)
    )
    conn.commit()
    conn.close()


def get_scan(scan_id, user_id=None):
    conn = get_connection()
    if user_id is not None:
        row = conn.execute('SELECT * FROM scans WHERE id = ? AND user_id = ?', (scan_id, user_id)).fetchone()
    else:
        row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    result = dict(row)
    if result['report_json']:
        result['report'] = json.loads(result['report_json'])
    return result


def get_history(user_id=None):
    conn = get_connection()
    if user_id is not None:
        rows = conn.execute(
            'SELECT id, target, status, created_at, finished_at FROM scans WHERE user_id = ? ORDER BY created_at DESC',
            (user_id,)
        ).fetchall()
    else:
        rows = conn.execute(
            'SELECT id, target, status, created_at, finished_at FROM scans ORDER BY created_at DESC'
        ).fetchall()
    conn.close()
    return [dict(row) for row in rows]



# ---------------------------------------------------------------------------
#  Администрирование
# ---------------------------------------------------------------------------

def get_all_users():
    """Возвращает список всех пользователей (без хешей паролей)."""
    conn = get_connection()
    rows = conn.execute(
        'SELECT id, username, is_admin, created_at FROM users ORDER BY id'
    ).fetchall()
    conn.close()
    users = []
    for row in rows:
        u = dict(row)
        u['is_admin'] = bool(u['is_admin'])
        # Считаем кол-во сканирований пользователя
        users.append(u)
    # Добавляем статистику по сканам
    conn = get_connection()
    for u in users:
        u['scan_count'] = conn.execute(
            'SELECT COUNT(*) FROM scans WHERE user_id = ?', (u['id'],)
        ).fetchone()[0]
    conn.close()
    return users


def get_all_scans():
    """Возвращает все сканирования всех пользователей (для админки)."""
    conn = get_connection()
    rows = conn.execute('''
        SELECT s.id, s.target, s.status, s.created_at, s.finished_at, s.error_message,
               s.user_id, u.username
        FROM scans s
        LEFT JOIN users u ON s.user_id = u.id
        ORDER BY s.created_at DESC
    ''').fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_admin_stats():
    """Возвращает общую статистику системы."""
    conn = get_connection()
    total_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    total_scans = conn.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
    done_scans = conn.execute("SELECT COUNT(*) FROM scans WHERE status = 'done'").fetchone()[0]
    error_scans = conn.execute("SELECT COUNT(*) FROM scans WHERE status = 'error'").fetchone()[0]
    running_scans = conn.execute("SELECT COUNT(*) FROM scans WHERE status = 'running'").fetchone()[0]
    conn.close()
    return {
        'total_users': total_users,
        'total_scans': total_scans,
        'done_scans': done_scans,
        'error_scans': error_scans,
        'running_scans': running_scans,
    }


def set_user_admin(user_id, is_admin):
    """Назначает или снимает права администратора."""
    conn = get_connection()
    conn.execute('UPDATE users SET is_admin = ? WHERE id = ?', (1 if is_admin else 0, user_id))
    conn.commit()
    conn.close()


def delete_user_by_id(user_id):
    """Удаляет пользователя и все его токены и сканирования."""
    conn = get_connection()
    conn.execute('DELETE FROM user_tokens WHERE user_id = ?', (user_id,))
    conn.execute('DELETE FROM scans WHERE user_id = ?', (user_id,))
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()


def delete_scan_by_id(scan_id):
    """Удаляет конкретное сканирование."""
    conn = get_connection()
    conn.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    conn.commit()
    conn.close()