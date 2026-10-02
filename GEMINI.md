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
- **Декораторы**: `login_required`, `admin_required` → используют `g.user`
- **Gemini AI**: модель `gemini-3.5-flash`, URL из `.env`, промпт — ИБ-эксперт. Эндпоинт `POST /api/ask`
- **Сканирование**: последовательные шаги (discovery→ports), потом параллельные в ThreadPoolExecutor

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
| GET | `/api/history` | login | История сканов юзера |
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
- `create_user(username, password)` → `(user_id, is_admin)` — первый user автоматически admin
- `get_scan(scan_id, user_id=None)` — user_id=None используется для админа
- Миграция: при старте добавляются колонки если их нет

## Фронтенд компоненты (App.jsx)
- `AuthPage` — форма логин/регистрация
- `Header` — шапка с именем, бейджем admin, кнопками
- `HistoryPanel` — раскрываемая история (кнопка "📋 История")
- `HostCard` — карточка с результатами хоста (порты, ОС, SSL, заголовки, уязвимости, nikto)
- `Report` — список HostCard
- `AiChat` — плавающий чат 🤖 (всегда виден). Если `scanId` есть → режим "Анализ отчёта", иначе → режим "Эксперт"
- `AdminPanel` — вкладки: 📊 Статистика, 👥 Пользователи, 🔍 Все сканы
- `App` — главный компонент, state: `user`, `scanId`, `report`, `showAdmin`, `showReport`

## Технические детали
- `localStorage.getItem('token')` — хранение токена в браузере
- Сканирование: `STEP_TIMEOUTS = {vuln: 300, nikto: 300}`, `DEFAULT_TIMEOUT = 90`
- PORT_DEPTHS: fast=top-100, normal=top-1000, full=-p-
- Werkzeug `generate_password_hash` / `check_password_hash` для паролей
- Gemini: `POST /api/ask` принимает `{question, history: [{role, text}], scan_id?}`
- `summarize_report(report)` — конвертирует JSON-отчёт в текст для промпта Gemini

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
- Старые сканы в БД не имеют user_id (NULL) — они видны только в /api/admin/scans
- `.env` содержит GEMINI_API_KEY — в .gitignore
- Первый зарегистрированный пользователь = администратор автоматически
- Команда `rm database.db` нужна чтобы сбросить всё с нуля
