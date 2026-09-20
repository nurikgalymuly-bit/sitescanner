import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.expanduser('~/Документы/sitescanner/database.db')


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            current_step TEXT,
            created_at TEXT NOT NULL,
            finished_at TEXT,
            report_json TEXT,
            error_message TEXT
        )
    ''')
    columns = [row['name'] for row in conn.execute('PRAGMA table_info(scans)')]
    if 'current_step' not in columns:
        conn.execute('ALTER TABLE scans ADD COLUMN current_step TEXT')
    conn.commit()
    conn.close()


def fail_interrupted_scans():
    conn = get_connection()
    conn.execute(
        "UPDATE scans SET status = 'error', finished_at = ?, error_message = ? WHERE status = 'running'",
        (datetime.now().isoformat(), 'Сканирование прервано перезапуском сервера')
    )
    conn.commit()
    conn.close()


def create_scan(target):
    conn = get_connection()
    cur = conn.execute(
        'INSERT INTO scans (target, status, created_at) VALUES (?, ?, ?)',
        (target, 'running', datetime.now().isoformat())
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


def get_scan(scan_id):
    conn = get_connection()
    row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    result = dict(row)
    if result['report_json']:
        result['report'] = json.loads(result['report_json'])
    return result


def get_history():
    conn = get_connection()
    rows = conn.execute(
        'SELECT id, target, status, created_at, finished_at FROM scans ORDER BY created_at DESC'
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]