import { useState, useEffect, useCallback } from 'react'
import './App.css'

const API = 'http://127.0.0.1:5000'
const RISKY_PORTS = new Set([21, 23, 110, 143, 2000, 5060])

const CHECK_OPTIONS = [
  { key: 'ssl_ciphers', label: 'Проверка SSL/TLS' },
  { key: 'headers', label: 'Проверка заголовков безопасности' },
  { key: 'vuln', label: 'Поиск известных уязвимостей (nmap)' },
  { key: 'nikto', label: 'Базовое сканирование веб-уязвимостей (nikto)' },
]

const PORT_DEPTH_OPTIONS = [
  { key: 'fast', label: 'Быстро (100 портов)' },
  { key: 'normal', label: 'Стандартно (1000 портов)' },
  { key: 'full', label: 'Полностью (65535 портов)' },
]

const DEFAULT_CHECKS = ['ssl_ciphers']

const stripCN = (s) => (s || '').replace('commonName=', '')
const fmtDate = (s) => (/^\d{4}-\d{2}-\d{2}/.test(s) ? s.slice(0, 10) : s)

/* ======================================================================== */
/*  API-утилита: добавляет токен ко всем запросам                           */
/* ======================================================================== */

function authHeaders() {
  const token = localStorage.getItem('token')
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function api(path, opts = {}) {
  const res = await fetch(`${API}${path}`, {
    ...opts,
    headers: { 'Content-Type': 'application/json', ...authHeaders(), ...(opts.headers || {}) },
  })
  const data = await res.json()
  if (!res.ok) throw new Error(data.error || 'Ошибка сервера')
  return data
}

/* ======================================================================== */
/*  Компонент: Форма входа и регистрации                                    */
/* ======================================================================== */

function AuthPage({ onAuth }) {
  const [isLogin, setIsLogin] = useState(true)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [password2, setPassword2] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setError('')

    if (!isLogin && password !== password2) {
      setError('Пароли не совпадают')
      return
    }

    setLoading(true)
    try {
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register'
      const data = await api(endpoint, {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      })
      localStorage.setItem('token', data.token)
      onAuth(data.user)
    } catch (err) {
      setError(
        err instanceof TypeError
          ? 'Не удалось связаться с сервером. Запущен ли Flask (python3 app.py)?'
          : err.message
      )
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="auth-page">
      <div className="auth-card">
        <h1>🛡️ SiteScanner</h1>
        <p className="subtitle">Сканер безопасности веб-ресурсов</p>

        <div className="auth-tabs">
          <button className={isLogin ? 'active' : ''} onClick={() => { setIsLogin(true); setError('') }}>
            Вход
          </button>
          <button className={!isLogin ? 'active' : ''} onClick={() => { setIsLogin(false); setError('') }}>
            Регистрация
          </button>
        </div>

        <form onSubmit={submit}>
          <input
            type="text"
            placeholder="Имя пользователя"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
          />
          <input
            type="password"
            placeholder="Пароль"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={isLogin ? 'current-password' : 'new-password'}
            required
          />
          {!isLogin && (
            <input
              type="password"
              placeholder="Повторите пароль"
              value={password2}
              onChange={(e) => setPassword2(e.target.value)}
              autoComplete="new-password"
              required
            />
          )}
          {error && <div className="auth-error">{error}</div>}
          <button type="submit" disabled={loading}>
            {loading ? 'Подождите…' : isLogin ? 'Войти' : 'Зарегистрироваться'}
          </button>
        </form>
      </div>
    </main>
  )
}

/* ======================================================================== */
/*  Компонент: Шапка с именем пользователя и выходом                        */
/* ======================================================================== */

function Header({ user, onLogout, onAdminToggle, showAdmin }) {
  return (
    <header className="app-header">
      <div className="header-brand">🛡️ SiteScanner</div>
      <div className="header-user">
        {user.is_admin && (
          <button
            className={`header-admin-btn ${showAdmin ? 'active' : ''}`}
            onClick={onAdminToggle}
          >
            ⚙️ Админ
          </button>
        )}
        <span className="header-username">
          {user.is_admin && <span className="admin-badge">admin</span>}
          {user.username}
        </span>
        <button className="header-logout" onClick={onLogout}>Выйти</button>
      </div>
    </header>
  )
}

/* ======================================================================== */
/*  Компонент: Боковая панель истории сканирований                          */
/* ======================================================================== */

function HistoryPanel({ onSelect }) {
  const [items, setItems] = useState([])
  const [open, setOpen] = useState(false)

  const load = useCallback(async () => {
    try {
      const data = await api('/api/history')
      setItems(data)
    } catch { /* ignore */ }
  }, [])

  useEffect(() => { load() }, [load])

  const statusIcon = (s) => s === 'done' ? '✅' : s === 'running' ? '⏳' : '❌'

  return (
    <div className="history-panel">
      <button className="history-toggle" onClick={() => { setOpen(!open); if (!open) load() }}>
        📋 История {open ? '▲' : '▼'}
      </button>
      {open && (
        <div className="history-list">
          {items.length === 0 && <p className="muted">Сканирований пока нет.</p>}
          {items.map((it) => (
            <button
              key={it.id}
              className="history-item"
              onClick={() => { if (it.status === 'done') onSelect(it.id) }}
              disabled={it.status !== 'done'}
            >
              <span>{statusIcon(it.status)} {it.target}</span>
              <span className="muted">{fmtDate(it.created_at)}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

/* ======================================================================== */
/*  Компоненты отчёта (без изменений)                                       */
/* ======================================================================== */

function HostCard({ host }) {
  const hasRisky = host.open_ports.some((p) => RISKY_PORTS.has(p.port))
  const hc = host.headers_check

  return (
    <section className="card">
      <h2>
        {host.hostname || host.ip} <span className="muted">{host.ip}</span>
      </h2>

      <h3>Открытые порты</h3>
      <div className="chips">
        {host.open_ports.map((p) => (
          <span key={p.port} className={`chip ${RISKY_PORTS.has(p.port) ? 'warn' : ''}`}>
            {p.port} · {p.service}
          </span>
        ))}
      </div>
      {hasRisky && (
        <p className="hint">
          Жёлтым отмечены порты, которые стоит закрыть от интернета, если они не нужны для работы сайта.
        </p>
      )}

      <h3>Операционная система (предположения)</h3>
      {host.os_guesses.length === 0 ? (
        <p className="muted">Определить не удалось.</p>
      ) : (
        <ul>
          {host.os_guesses.map((o, i) => (
            <li key={i}>
              {o.name} <span className="muted">— точность {o.accuracy}%</span>
            </li>
          ))}
        </ul>
      )}

      <h3>SSL-сертификаты</h3>
      {host.ssl_certs.length === 0 ? (
        <p className="muted">Сертификаты не найдены.</p>
      ) : (
        host.ssl_certs.map((c, i) => (
          <div key={i} className={`note ${c.domain_mismatch ? 'warn' : ''}`}>
            <b>Порты {c.ports.join(', ')}</b>
            <div>Выдан на: {stripCN(c.subject)}</div>
            <div>Кем выдан: {stripCN(c.issuer)}</div>
            <div>Действует до: {fmtDate(c.valid_after)}</div>
            {c.domain_mismatch && (
              <div className="alert">
                ⚠ Сертификат выписан не на этот сайт. Браузеры могут показывать предупреждение о небезопасном соединении.
              </div>
            )}
          </div>
        ))
      )}

      <h3>Защита соединения (TLS)</h3>
      {host.ssl_ciphers.length === 0 ? (
        <p className="muted">Данных нет.</p>
      ) : (
        <div className="chips">
          {host.ssl_ciphers.map((c) => (
            <span key={c.port} className={`chip grade-${c.grade || 'none'}`}>
              порт {c.port} · оценка {c.grade || '?'}
            </span>
          ))}
        </div>
      )}

      {hc && (
        <>
          <h3>Заголовки безопасности</h3>
          {hc.error ? (
            <p className="muted">Не удалось проверить: {hc.error}</p>
          ) : (
            <>
              {hc.missing.length === 0 ? (
                <p className="muted">Все основные заголовки безопасности присутствуют.</p>
              ) : (
                <div className="note warn">
                  <b>Отсутствуют заголовки:</b>
                  <div>{hc.missing.join(', ')}</div>
                </div>
              )}
            </>
          )}
        </>
      )}

      {host.vuln_findings.length > 0 && (
        <>
          <h3>Возможные уязвимости (nmap)</h3>
          {host.vuln_findings.map((v, i) => (
            <div key={i} className="note warn">
              <b>Порт {v.port} · {v.script}</b>
              <div style={{ whiteSpace: 'pre-wrap' }}>{v.output}</div>
            </div>
          ))}
        </>
      )}

      {host.nikto_findings.length > 0 && (
        <>
          <h3>Возможные проблемы (найдено сканером nikto)</h3>
          <ul>
            {host.nikto_findings.map((line, i) => (
              <li key={i}>{line}</li>
            ))}
          </ul>
        </>
      )}
    </section>
  )
}

function Report({ report }) {
  if (!report.hosts.length) {
    return (
      <div className="card">
        Живых хостов не найдено: сервер не ответил на проверки. Возможно, он закрыт файрволом.
      </div>
    )
  }
  return report.hosts.map((h) => <HostCard key={h.ip} host={h} />)
}

/* ======================================================================== */
/*  Компонент: Админ-панель                                                 */
/* ======================================================================== */

function AdminPanel({ currentUserId }) {
  const [tab, setTab] = useState('stats')
  const [stats, setStats] = useState(null)
  const [users, setUsers] = useState([])
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(false)

  const loadTab = useCallback(async (t) => {
    setLoading(true)
    try {
      if (t === 'stats') {
        setStats(await api('/api/admin/stats'))
      } else if (t === 'users') {
        setUsers(await api('/api/admin/users'))
      } else if (t === 'scans') {
        setScans(await api('/api/admin/scans'))
      }
    } catch { /* ignore */ }
    setLoading(false)
  }, [])

  useEffect(() => { loadTab(tab) }, [tab, loadTab])

  const toggleAdmin = async (userId) => {
    try {
      await api(`/api/admin/users/${userId}/toggle-admin`, { method: 'POST' })
      loadTab('users')
    } catch (err) { alert(err.message) }
  }

  const deleteUser = async (userId, username) => {
    if (!confirm(`Удалить пользователя «${username}» и все его сканирования?`)) return
    try {
      await api(`/api/admin/users/${userId}`, { method: 'DELETE' })
      loadTab('users')
    } catch (err) { alert(err.message) }
  }

  const deleteScan = async (scanId) => {
    if (!confirm(`Удалить скан #${scanId}?`)) return
    try {
      await api(`/api/admin/scans/${scanId}`, { method: 'DELETE' })
      loadTab('scans')
    } catch (err) { alert(err.message) }
  }

  return (
    <main className="page">
      <h1>⚙️ Панель администратора</h1>
      <p className="subtitle">Управление пользователями, сканированиями и статистика системы.</p>

      <div className="admin-tabs">
        {[
          ['stats', '📊 Статистика'],
          ['users', '👥 Пользователи'],
          ['scans', '🔍 Все сканирования'],
        ].map(([key, label]) => (
          <button
            key={key}
            className={tab === key ? 'active' : ''}
            onClick={() => setTab(key)}
          >
            {label}
          </button>
        ))}
      </div>

      {loading && <div className="status"><span className="spinner" /> Загрузка…</div>}

      {/* Статистика */}
      {tab === 'stats' && stats && !loading && (
        <div className="admin-stats-grid">
          <div className="stat-card">
            <div className="stat-value">{stats.total_users}</div>
            <div className="stat-label">Пользователей</div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{stats.total_scans}</div>
            <div className="stat-label">Всего сканирований</div>
          </div>
          <div className="stat-card ok">
            <div className="stat-value">{stats.done_scans}</div>
            <div className="stat-label">Завершены</div>
          </div>
          <div className="stat-card err">
            <div className="stat-value">{stats.error_scans}</div>
            <div className="stat-label">С ошибками</div>
          </div>
          <div className="stat-card running">
            <div className="stat-value">{stats.running_scans}</div>
            <div className="stat-label">В процессе</div>
          </div>
        </div>
      )}

      {/* Пользователи */}
      {tab === 'users' && !loading && (
        <div className="admin-table-wrap">
          <table className="admin-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Имя</th>
                <th>Роль</th>
                <th>Сканов</th>
                <th>Зарегистрирован</th>
                <th>Действия</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td>{u.id}</td>
                  <td>{u.username}</td>
                  <td>
                    <span className={`role-badge ${u.is_admin ? 'admin' : 'user'}`}>
                      {u.is_admin ? 'Админ' : 'Пользователь'}
                    </span>
                  </td>
                  <td>{u.scan_count}</td>
                  <td>{fmtDate(u.created_at)}</td>
                  <td className="action-cell">
                    {u.id !== currentUserId && (
                      <>
                        <button className="btn-sm" onClick={() => toggleAdmin(u.id)}>
                          {u.is_admin ? '↓ Снять админа' : '↑ Сделать админом'}
                        </button>
                        <button className="btn-sm danger" onClick={() => deleteUser(u.id, u.username)}>
                          🗑
                        </button>
                      </>
                    )}
                    {u.id === currentUserId && <span className="muted">Это вы</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Все сканирования */}
      {tab === 'scans' && !loading && (
        <div className="admin-table-wrap">
          <table className="admin-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Цель</th>
                <th>Пользователь</th>
                <th>Статус</th>
                <th>Дата</th>
                <th>Действия</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id}>
                  <td>{s.id}</td>
                  <td>{s.target}</td>
                  <td>{s.username || <span className="muted">—</span>}</td>
                  <td>
                    <span className={`status-badge ${s.status}`}>
                      {s.status === 'done' ? '✅ Готово' : s.status === 'running' ? '⏳ В процессе' : '❌ Ошибка'}
                    </span>
                  </td>
                  <td>{fmtDate(s.created_at)}</td>
                  <td>
                    <button className="btn-sm danger" onClick={() => deleteScan(s.id)}>
                      🗑
                    </button>
                  </td>
                </tr>
              ))}
              {scans.length === 0 && (
                <tr><td colSpan={6} className="muted" style={{ textAlign: 'center' }}>Сканирований нет</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </main>
  )
}

/* ======================================================================== */
/*  Главный компонент приложения                                            */
/* ======================================================================== */

function App() {
  const [user, setUser] = useState(null)
  const [authChecked, setAuthChecked] = useState(false)
  const [showAdmin, setShowAdmin] = useState(false)

  /* --- состояние сканера --- */
  const [target, setTarget] = useState('')
  const [checks, setChecks] = useState(DEFAULT_CHECKS)
  const [portDepth, setPortDepth] = useState('fast')
  const [scanId, setScanId] = useState(null)
  const [status, setStatus] = useState('idle')
  const [error, setError] = useState('')
  const [report, setReport] = useState(null)
  const [showReport, setShowReport] = useState(false)
  const [currentStep, setCurrentStep] = useState('')

  /* --- проверка токена при загрузке --- */
  useEffect(() => {
    const token = localStorage.getItem('token')
    if (!token) { setAuthChecked(true); return }
    fetch(`${API}/api/auth/me`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.ok ? r.json() : Promise.reject())
      .then((d) => setUser(d.user))
      .catch(() => localStorage.removeItem('token'))
      .finally(() => setAuthChecked(true))
  }, [])

  const handleAuth = (u) => setUser(u)

  const handleLogout = async () => {
    try { await api('/api/auth/logout', { method: 'POST' }) } catch { /* ok */ }
    localStorage.removeItem('token')
    setUser(null)
    setReport(null)
    setShowReport(false)
    setShowAdmin(false)
    setStatus('idle')
  }

  /* --- сканирование --- */
  const toggleCheck = (key) => {
    setChecks((prev) => (prev.includes(key) ? prev.filter((c) => c !== key) : [...prev, key]))
  }

  const startScan = async (e) => {
    e.preventDefault()
    setError('')
    setReport(null)
    setShowReport(false)
    setCurrentStep('')
    try {
      const data = await api('/api/scan', {
        method: 'POST',
        body: JSON.stringify({ target, checks, port_depth: portDepth }),
      })
      setScanId(data.scan_id)
      setStatus('running')
    } catch (err) {
      setStatus('error')
      setError(
        err instanceof TypeError
          ? 'Не удалось связаться с сервером. Запущен ли Flask (python3 app.py)?'
          : err.message
      )
    }
  }

  const stopScan = async () => {
    if (!scanId) return
    try {
      await api(`/api/scan/${scanId}/cancel`, { method: 'POST' })
    } catch { /* ignore */ }
  }

  /* --- загрузка отчёта из истории --- */
  const loadHistoryReport = async (id) => {
    try {
      const data = await api(`/api/scan/${id}/report`)
      setReport(data)
      setShowReport(true)
      setStatus('done')
    } catch { /* ignore */ }
  }

  /* --- опрос статуса --- */
  useEffect(() => {
    if (status !== 'running' || !scanId) return

    const timer = setInterval(async () => {
      try {
        const data = await api(`/api/scan/${scanId}/status`)
        setCurrentStep(data.current_step)
        if (data.status === 'done') {
          const r = await api(`/api/scan/${scanId}/report`)
          setReport(r)
          setStatus('done')
        } else if (data.status === 'error') {
          setError(data.error_message || 'Сканирование завершилось с ошибкой')
          setStatus('error')
        }
      } catch { /* retry */ }
    }, 3000)

    return () => clearInterval(timer)
  }, [status, scanId])

  /* --- рендер --- */
  if (!authChecked) return null
  if (!user) return <AuthPage onAuth={handleAuth} />

  return (
    <>
      <Header
        user={user}
        onLogout={handleLogout}
        onAdminToggle={() => setShowAdmin((v) => !v)}
        showAdmin={showAdmin}
      />

      {showAdmin && user.is_admin ? (
        <AdminPanel currentUserId={user.id} />
      ) : (
        <main className="page">
          <h1>Сканер безопасности сайта</h1>
          <p className="subtitle">Введите адрес сайта или IP и получите понятный отчёт.</p>

          <HistoryPanel onSelect={loadHistoryReport} />

          <form className="scan-form" onSubmit={startScan}>
            <input
              type="text"
              placeholder="example.com или 192.168.1.1"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
            {status === 'running' ? (
              <button type="button" className="danger" onClick={stopScan}>
                Остановить
              </button>
            ) : (
              <button type="submit" disabled={!target.trim()}>
                Старт
              </button>
            )}
            <button
              type="button"
              className="secondary"
              disabled={!report}
              onClick={() => setShowReport((v) => !v)}
            >
              Отчёт
            </button>
          </form>

          <div className="checks">
            {PORT_DEPTH_OPTIONS.map((opt) => (
              <label key={opt.key} className="check">
                <input
                  type="radio"
                  name="portDepth"
                  checked={portDepth === opt.key}
                  onChange={() => setPortDepth(opt.key)}
                />
                {opt.label}
              </label>
            ))}
          </div>

          <div className="checks">
            {CHECK_OPTIONS.map((opt) => (
              <label key={opt.key} className="check">
                <input
                  type="checkbox"
                  checked={checks.includes(opt.key)}
                  onChange={() => toggleCheck(opt.key)}
                />
                {opt.label}
              </label>
            ))}
          </div>

          {status === 'running' && (
            <div className="status">
              <span className="spinner" />
              {currentStep || 'Подготовка к сканированию…'}
            </div>
          )}
          {status === 'done' && !showReport && (
            <div className="status ok">Готово! Нажмите «Отчёт», чтобы посмотреть результат.</div>
          )}
          {status === 'error' && <div className="status err">{error}</div>}

          {showReport && report && <Report report={report} />}
        </main>
      )}
    </>
  )
}

export default App