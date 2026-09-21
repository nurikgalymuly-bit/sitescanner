import { useState, useEffect } from 'react'
import './App.css'

const API = 'http://127.0.0.1:5000'
const RISKY_PORTS = new Set([21, 23, 110, 143, 2000, 5060])

const CHECK_OPTIONS = [
  { key: 'ssl_ciphers', label: 'Проверка SSL/TLS' },
  { key: 'headers', label: 'Проверка заголовков безопасности' },
  { key: 'vuln', label: 'Поиск известных уязвимостей (nmap)' },
  { key: 'nikto', label: 'Базовое сканирование веб-уязвимостей (nikto)' },
]

const DEFAULT_CHECKS = ['ssl_ciphers']

const stripCN = (s) => (s || '').replace('commonName=', '')
const fmtDate = (s) => (/^\d{4}-\d{2}-\d{2}/.test(s) ? s.slice(0, 10) : s)

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
          <h3>Находки nikto</h3>
          <ul>
            {host.nikto_findings.map((line, i) => (
              <li key={i}>{line.replace(/^\+\s*/, '')}</li>
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

function App() {
  const [target, setTarget] = useState('')
  const [checks, setChecks] = useState(DEFAULT_CHECKS)
  const [scanId, setScanId] = useState(null)
  const [status, setStatus] = useState('idle')
  const [error, setError] = useState('')
  const [report, setReport] = useState(null)
  const [showReport, setShowReport] = useState(false)
  const [currentStep, setCurrentStep] = useState('')

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
      const res = await fetch(`${API}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, checks }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Не удалось запустить сканирование')
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
    await fetch(`${API}/api/scan/${scanId}/cancel`, { method: 'POST' })
  } catch {
    // если сервер недоступен, просто ждём следующего опроса статуса
  }
}

  useEffect(() => {
    if (status !== 'running' || !scanId) return

    const timer = setInterval(async () => {
      try {
        const res = await fetch(`${API}/api/scan/${scanId}/status`)
        const data = await res.json()
        setCurrentStep(data.current_step)
        if (data.status === 'done') {
          const r = await fetch(`${API}/api/scan/${scanId}/report`)
          setReport(await r.json())
          setStatus('done')
        } else if (data.status === 'error') {
          setError(data.error_message || 'Сканирование завершилось с ошибкой')
          setStatus('error')
        }
      } catch {
        // сервер временно недоступен, попробуем ещё раз на следующем тике
      }
    }, 3000)

    return () => clearInterval(timer)
  }, [status, scanId])

  return (
    <main className="page">
      <h1>Сканер безопасности сайта</h1>
      <p className="subtitle">Введите адрес сайта или IP и получите понятный отчёт.</p>

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
  )
}

export default App