# SiteScanner — Справка по проекту

## Описание
Дипломный проект: веб-приложение для сканирования безопасности сайтов.
Flask (Python) бэкенд + React/Vite фронтенд + SQLite + nmap/nikto сканеры.

## Структура файлов
```
sitescanner/
├── app.py              # Flask API (436+ строк). Авторизация + сканирование + ИИ-чат + админка
├── db.py               # SQLite: users, user_tokens, scans. Авторизация, CRUD
├── .env                # GEMINI_API_KEY — ключ для Gemini AI
├── database.db         # SQLite база данных
├── scanner/
│   ├── report_builder.py   # Парсит XML/JSON результаты → dict
│   ├── host-discovery.py   # nmap ICMP/SYN обнаружение
│   ├── top-port-scan.py    # nmap порт-скан (env PORT_FLAG)
│   ├── os-detection.py     # nmap -O определение ОС
│   ├── service-scan.py     # nmap -sV службы
│   ├── ssl-certs.py        # SSL сертификаты
│   ├── ssl-ciphers.py      # TLS шифры
│   ├── headers-check.py    # HTTP заголовки безопасности
│   ├── vuln-scan.py        # nmap --script vuln (таймаут 300с)
│   └── nikto-scan.py       # nikto (таймаут 300с)
├── reports/
│   ├── Stage_1/            # Временные XML/JSON от nmap
│   └── Stage_2/            # Временные TXT от nikto
└── frontend/
    └── src/
        ├── App.jsx         # React: всё в одном файле (~870 строк)
        └── App.css         # Стили (тёмная тема, все компоненты)
```

## Архитектура бэкенда (app.py)
- **Flask** на `127.0.0.1:5000`, CORS включён
- **Авторизация**: Bearer-токен в заголовке `Authorization`. `@login_required` / `@admin_required`
- **Gemini AI**: использует fallback-список (`gemini-3.5-flash`, `3.8`, `2.5-lite`) на случай перегрузки API (503). Эндпоинт `POST /api/ask`. Ключ скрыт из сообщений об ошибках.
- **Сканирование**: последовательные шаги (discovery→ports), потом параллельные (os, ssl, nikto, whatweb).
- **Target Sanitization**: Фронтенд автоматически обрезает `https://` и пути из URL, чтобы Nmap не падал.

## Структура файлов (дополнения)
- `scanner/whatweb-scan.py` — утилита WhatWeb для определения стека технологий. Запускается с флагом `--color=never`.

## API эндпоинты
| Метод | URL | Защита | Описание |
|-------|-----|--------|----------|
| POST | `/api/auth/register` | — | Регистрация. Первый user = admin |
| POST | `/api/auth/login` | — | Логин, возвращает token |
| POST | `/api/auth/logout` | login | Удалить токен |
| GET | `/api/auth/me` | login | Текущий user |
| POST | `/api/scan` | login | Запустить скан |
| GET | `/api/scan/<id>/status` | login | Статус скана |
| GET | `/api/scan/<id>/report` | login | JSON-отчёт |
| POST | `/api/scan/<id>/cancel` | login | Отменить скан |
| GET | `/api/history` | login | История сканов юзера (автообновляется после скана) |
| POST | `/api/ask` | login | ИИ-чат. Body: `{question, history, scan_id?}` |
| GET | `/api/admin/stats` | admin | Статистика |
| GET | `/api/admin/users` | admin | Все пользователи |
| GET | `/api/admin/scans` | admin | Все сканирования |
| POST | `/api/admin/users/<id>/toggle-admin` | admin | Назначить/снять admin |
| DELETE | `/api/admin/users/<id>` | admin | Удалить пользователя |
| DELETE | `/api/admin/scans/<id>` | admin | Удалить скан |

## База данных (db.py)
```sql
users: id, username, password_hash, is_admin, created_at
user_tokens: id, user_id, token, created_at, expires_at
scans: id, user_id, target, status, current_step, error_message, report_json, created_at
```

## Фронтенд компоненты (App.jsx)
- **i18n & Темы**: Поддержка 3 языков (RU, KZ, EN) через `LangContext` и светлой/тёмной темы через CSS-переменные (сохраняется в `localStorage`).
- **PDF Экспорт**: Кнопка "Сохранить в PDF" (использует `@media print` для чистой печати отчёта).
- `AuthPage` — форма логин/регистрация с выбором языка и темы.
- `HistoryPanel` — автообновляемая история сканирований.
- `HostCard` — включает **Дашборд уязвимостей** (🔴 Критичные, 🟠 Средние, 🔵 Инфо) и распарсенные теги WhatWeb.
- `AiChat` — плавающий чат с кнопками "развернуть/свернуть" (⛶ / ⊡) для удобного чтения лонгридов.
- `AdminPanel` — вкладки: 📊 Статистика, 👥 Пользователи, 🔍 Все сканы.

## Технические детали
- Сканирование: `whatweb` добавлен в параллельные проверки (таймаут 60с).
- Gemini API: увеличено время ожидания до 60с для thinking-моделей.
- CSS: добавлено `overflow-wrap: anywhere` для корректного переноса длинных строк SSL-сертификатов.

## Запуск
```bash
# Бэкенд
cd ~/Документы/sitescanner
python3 app.py            # порт 5000

# Фронтенд
cd ~/Документы/sitescanner/frontend
npm run dev               # порт 5173
```

## Известные детали / особенности
- Сканер требует root (nmap/nikto нужны привилегии)
- `.env` содержит GEMINI_API_KEY — в .gitignore
- Команда `rm database.db` нужна чтобы сбросить всё с нуля
