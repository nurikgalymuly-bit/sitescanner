import { useState, useEffect, useCallback, createContext, useContext } from 'react'
import './App.css'

const API = 'http://127.0.0.1:5000'
const RISKY_PORTS = new Set([21, 23, 110, 143, 2000, 5060])

/* ======================================================================== */
/*  Переводы (Русский / Қазақша / English)                                   */
/* ======================================================================== */

const TRANSLATIONS = {
  ru: {
    brand: '🛡️ SiteScanner',
    subtitle: 'Сканер безопасности веб-ресурсов',
    login: 'Вход',
    register: 'Регистрация',
    username: 'Имя пользователя',
    password: 'Пароль',
    password2: 'Повторите пароль',
    passwordMismatch: 'Пароли не совпадают',
    loginBtn: 'Войти',
    registerBtn: 'Зарегистрироваться',
    wait: 'Подождите…',
    serverError: 'Не удалось связаться с сервером. Запущен ли Flask (python3 app.py)?',
    logout: 'Выйти',
    admin: '⚙️ Админ',
    scannerTitle: 'Сканер безопасности сайта',
    scannerSubtitle: 'Введите адрес сайта или IP и получите понятный отчёт.',
    history: '📋 История',
    noScans: 'Сканирований пока нет.',
    start: 'Старт',
    stop: 'Остановить',
    report: 'Отчёт',
    preparing: 'Подготовка к сканированию…',
    done: 'Готово! Нажмите «Отчёт», чтобы посмотреть результат.',
    scanError: 'Сканирование завершилось с ошибкой',
    placeholder: 'example.com или 192.168.1.1',
    checkSsl: 'Проверка SSL/TLS',
    checkHeaders: 'Проверка заголовков безопасности',
    checkVuln: 'Поиск известных уязвимостей (nmap)',
    checkNikto: 'Базовое сканирование веб-уязвимостей (nikto)',
    fast: 'Быстро (100 портов)',
    normal: 'Стандартно (1000 портов)',
    full: 'Полностью (65535 портов)',
    openPorts: 'Открытые порты',
    riskyHint: 'Жёлтым отмечены порты, которые стоит закрыть от интернета, если они не нужны для работы сайта.',
    osGuesses: 'Операционная система (предположения)',
    osUnknown: 'Определить не удалось.',
    accuracy: 'точность',
    sslCerts: 'SSL-сертификаты',
    noCerts: 'Сертификаты не найдены.',
    issuedTo: 'Выдан на',
    issuedBy: 'Кем выдан',
    validUntil: 'Действует до',
    domainMismatch: '⚠ Сертификат выписан не на этот сайт. Браузеры могут показывать предупреждение о небезопасном соединении.',
    tlsTitle: 'Защита соединения (TLS)',
    tlsNoData: 'Данных нет.',
    tlsPort: 'порт',
    tlsGrade: 'оценка',
    headersTitle: 'Заголовки безопасности',
    headersError: 'Не удалось проверить',
    headersOk: 'Все основные заголовки безопасности присутствуют.',
    headersMissing: 'Отсутствуют заголовки:',
    vulnTitle: 'Возможные уязвимости (nmap)',
    niktoTitle: 'Возможные проблемы (найдено сканером nikto)',
    noHosts: 'Живых хостов не найдено: сервер не ответил на проверки. Возможно, он закрыт файрволом.',
    adminTitle: '⚙️ Панель администратора',
    adminSubtitle: 'Управление пользователями, сканированиями и статистика системы.',
    tabStats: '📊 Статистика',
    tabUsers: '👥 Пользователи',
    tabScans: '🔍 Все сканирования',
    loading: 'Загрузка…',
    statUsers: 'Пользователей',
    statTotal: 'Всего сканирований',
    statDone: 'Завершены',
    statError: 'С ошибками',
    statRunning: 'В процессе',
    thId: 'ID',
    thName: 'Имя',
    thRole: 'Роль',
    thScans: 'Сканов',
    thRegistered: 'Зарегистрирован',
    thActions: 'Действия',
    roleAdmin: 'Админ',
    roleUser: 'Пользователь',
    demoteAdmin: '↓ Снять админа',
    promoteAdmin: '↑ Сделать админом',
    itsYou: 'Это вы',
    thTarget: 'Цель',
    thUser: 'Пользователь',
    thStatus: 'Статус',
    thDate: 'Дата',
    statusDone: '✅ Готово',
    statusRunning: '⏳ В процессе',
    statusError: '❌ Ошибка',
    noScansAdmin: 'Сканирований нет',
    confirmDeleteUser: 'Удалить пользователя',
    confirmDeleteScan: 'Удалить скан',
    aiReportMode: '🤖 SiteScanner AI (Анализ отчёта)',
    aiExpertMode: '🤖 SiteScanner AI (Эксперт)',
    aiWelcomeReport: 'Привет! Я изучил результаты сканирования. Что вас интересует?',
    aiWelcomeExpert: 'Привет! Я эксперт по кибербезопасности. Чем могу помочь?',
    aiThinking: 'Думаю',
    aiPlaceholder: 'Задайте вопрос...',
    aiYou: '👤 Вы',
    aiBot: '🤖 ИИ',
    scanQ1: '💡 Оцени общий уровень безопасности',
    scanQ2: '⚠️ Какие главные угрозы?',
    scanQ3: '🛡️ Как исправить заголовки?',
    scanQ4: '🔒 Что с сертификатами?',
    scanQ5: '📋 Составь план защиты',
    genQ1: 'Что такое OWASP Top 10?',
    genQ2: 'Как защитить Nginx от DDoS?',
    genQ3: 'Чем опасен открытый порт 3306?',
    genQ4: 'Как настроить HSTS?',
    ports: 'Порты',
    printReport: '🖨️ Сохранить в PDF',
    reportTitle: 'Отчёт о сканировании',
  },
  kz: {
    brand: '🛡️ SiteScanner',
    subtitle: 'Веб-ресурстар қауіпсіздігінің сканері',
    login: 'Кіру',
    register: 'Тіркелу',
    username: 'Пайдаланушы аты',
    password: 'Құпия сөз',
    password2: 'Құпия сөзді қайталаңыз',
    passwordMismatch: 'Құпия сөздер сәйкес келмейді',
    loginBtn: 'Кіру',
    registerBtn: 'Тіркелу',
    wait: 'Күтіңіз…',
    serverError: 'Серверге қосылу мүмкін болмады. Flask (python3 app.py) іске қосылды ма?',
    logout: 'Шығу',
    admin: '⚙️ Әкімші',
    scannerTitle: 'Сайт қауіпсіздігінің сканері',
    scannerSubtitle: 'Сайт мекенжайын немесе IP енгізіп, түсінікті есеп алыңыз.',
    history: '📋 Тарих',
    noScans: 'Сканерлеу әлі жоқ.',
    start: 'Бастау',
    stop: 'Тоқтату',
    report: 'Есеп',
    preparing: 'Сканерлеуге дайындық…',
    done: 'Дайын! Нәтижені көру үшін «Есеп» батырмасын басыңыз.',
    scanError: 'Сканерлеу қатемен аяқталды',
    placeholder: 'example.com немесе 192.168.1.1',
    checkSsl: 'SSL/TLS тексеру',
    checkHeaders: 'Қауіпсіздік тақырыптарын тексеру',
    checkVuln: 'Белгілі осалдықтарды іздеу (nmap)',
    checkNikto: 'Веб-осалдықтарды сканерлеу (nikto)',
    fast: 'Жылдам (100 порт)',
    normal: 'Стандартты (1000 порт)',
    full: 'Толық (65535 порт)',
    openPorts: 'Ашық порттар',
    riskyHint: 'Сары түспен белгіленген порттарды интернеттен жабу керек, егер олар сайт жұмысына қажет болмаса.',
    osGuesses: 'Операциялық жүйе (болжамдар)',
    osUnknown: 'Анықтау мүмкін болмады.',
    accuracy: 'дәлдік',
    sslCerts: 'SSL-сертификаттар',
    noCerts: 'Сертификаттар табылмады.',
    issuedTo: 'Кімге берілген',
    issuedBy: 'Кім берген',
    validUntil: 'Жарамды',
    domainMismatch: '⚠ Сертификат бұл сайтқа берілмеген. Браузерлер қауіпті қосылым туралы ескертуі мүмкін.',
    tlsTitle: 'Қосылым қорғау (TLS)',
    tlsNoData: 'Деректер жоқ.',
    tlsPort: 'порт',
    tlsGrade: 'баға',
    headersTitle: 'Қауіпсіздік тақырыптары',
    headersError: 'Тексеру мүмкін болмады',
    headersOk: 'Барлық негізгі қауіпсіздік тақырыптары бар.',
    headersMissing: 'Жоқ тақырыптар:',
    vulnTitle: 'Ықтимал осалдықтар (nmap)',
    niktoTitle: 'Ықтимал мәселелер (nikto сканері)',
    noHosts: 'Тірі хосттар табылмады: сервер тексерулерге жауап бермеді.',
    adminTitle: '⚙️ Әкімші панелі',
    adminSubtitle: 'Пайдаланушыларды, сканерлеулерді басқару және жүйе статистикасы.',
    tabStats: '📊 Статистика',
    tabUsers: '👥 Пайдаланушылар',
    tabScans: '🔍 Барлық сканерлеулер',
    loading: 'Жүктелуде…',
    statUsers: 'Пайдаланушылар',
    statTotal: 'Барлық сканерлеулер',
    statDone: 'Аяқталған',
    statError: 'Қателермен',
    statRunning: 'Орындалуда',
    thId: 'ID',
    thName: 'Аты',
    thRole: 'Рөлі',
    thScans: 'Сканерлер',
    thRegistered: 'Тіркелген',
    thActions: 'Әрекеттер',
    roleAdmin: 'Әкімші',
    roleUser: 'Пайдаланушы',
    demoteAdmin: '↓ Әкімшіні алу',
    promoteAdmin: '↑ Әкімші ету',
    itsYou: 'Бұл сіз',
    thTarget: 'Мақсат',
    thUser: 'Пайдаланушы',
    thStatus: 'Күйі',
    thDate: 'Күні',
    statusDone: '✅ Дайын',
    statusRunning: '⏳ Орындалуда',
    statusError: '❌ Қате',
    noScansAdmin: 'Сканерлеу жоқ',
    confirmDeleteUser: 'Пайдаланушыны жою',
    confirmDeleteScan: 'Сканерлеуді жою',
    aiReportMode: '🤖 SiteScanner AI (Есеп талдау)',
    aiExpertMode: '🤖 SiteScanner AI (Сарапшы)',
    aiWelcomeReport: 'Сәлеметсіз бе! Мен сканерлеу нәтижелерін зерттедім. Сізді не қызықтырады?',
    aiWelcomeExpert: 'Сәлеметсіз бе! Мен киберқауіпсіздік сарапшысымын. Не көмектесе аламын?',
    aiThinking: 'Ойланамын',
    aiPlaceholder: 'Сұрақ қойыңыз...',
    aiYou: '👤 Сіз',
    aiBot: '🤖 AI',
    scanQ1: '💡 Қауіпсіздік деңгейін бағала',
    scanQ2: '⚠️ Негізгі қауіптер қандай?',
    scanQ3: '🛡️ Тақырыптарды қалай түзетуге болады?',
    scanQ4: '🔒 Сертификаттар жағдайы?',
    scanQ5: '📋 Қорғаныс жоспарын құр',
    genQ1: 'OWASP Top 10 дегеніміз не?',
    genQ2: 'Nginx-ті DDoS-тан қалай қорғауға болады?',
    genQ3: 'Ашық 3306 порты неге қауіпті?',
    genQ4: 'HSTS қалай орнатуға болады?',
    ports: 'Порттар',
    printReport: '🖨️ PDF сақтау',
    reportTitle: 'Сканерлеу есебі',
  },
  en: {
    brand: '🛡️ SiteScanner',
    subtitle: 'Web Resource Security Scanner',
    login: 'Login',
    register: 'Register',
    username: 'Username',
    password: 'Password',
    password2: 'Repeat password',
    passwordMismatch: 'Passwords do not match',
    loginBtn: 'Sign In',
    registerBtn: 'Sign Up',
    wait: 'Please wait…',
    serverError: 'Cannot connect to server. Is Flask (python3 app.py) running?',
    logout: 'Logout',
    admin: '⚙️ Admin',
    scannerTitle: 'Website Security Scanner',
    scannerSubtitle: 'Enter a website address or IP and get a clear report.',
    history: '📋 History',
    noScans: 'No scans yet.',
    start: 'Start',
    stop: 'Stop',
    report: 'Report',
    preparing: 'Preparing to scan…',
    done: 'Done! Click "Report" to view the results.',
    scanError: 'Scan finished with an error',
    placeholder: 'example.com or 192.168.1.1',
    checkSsl: 'SSL/TLS Check',
    checkHeaders: 'Security Headers Check',
    checkVuln: 'Known Vulnerabilities (nmap)',
    checkNikto: 'Web Vulnerability Scan (nikto)',
    fast: 'Fast (100 ports)',
    normal: 'Standard (1000 ports)',
    full: 'Full (65535 ports)',
    openPorts: 'Open Ports',
    riskyHint: 'Yellow ports should be closed from the internet if not needed for the website.',
    osGuesses: 'Operating System (guesses)',
    osUnknown: 'Could not determine.',
    accuracy: 'accuracy',
    sslCerts: 'SSL Certificates',
    noCerts: 'No certificates found.',
    issuedTo: 'Issued to',
    issuedBy: 'Issued by',
    validUntil: 'Valid until',
    domainMismatch: '⚠ Certificate is not issued for this domain. Browsers may show a security warning.',
    tlsTitle: 'Connection Security (TLS)',
    tlsNoData: 'No data.',
    tlsPort: 'port',
    tlsGrade: 'grade',
    headersTitle: 'Security Headers',
    headersError: 'Check failed',
    headersOk: 'All essential security headers are present.',
    headersMissing: 'Missing headers:',
    vulnTitle: 'Possible Vulnerabilities (nmap)',
    niktoTitle: 'Issues Found (nikto scanner)',
    noHosts: 'No live hosts found: server did not respond. It may be behind a firewall.',
    adminTitle: '⚙️ Admin Panel',
    adminSubtitle: 'User management, scan management, and system statistics.',
    tabStats: '📊 Statistics',
    tabUsers: '👥 Users',
    tabScans: '🔍 All Scans',
    loading: 'Loading…',
    statUsers: 'Users',
    statTotal: 'Total Scans',
    statDone: 'Completed',
    statError: 'With Errors',
    statRunning: 'Running',
    thId: 'ID',
    thName: 'Name',
    thRole: 'Role',
    thScans: 'Scans',
    thRegistered: 'Registered',
    thActions: 'Actions',
    roleAdmin: 'Admin',
    roleUser: 'User',
    demoteAdmin: '↓ Revoke Admin',
    promoteAdmin: '↑ Make Admin',
    itsYou: 'This is you',
    thTarget: 'Target',
    thUser: 'User',
    thStatus: 'Status',
    thDate: 'Date',
    statusDone: '✅ Done',
    statusRunning: '⏳ Running',
    statusError: '❌ Error',
    noScansAdmin: 'No scans',
    confirmDeleteUser: 'Delete user',
    confirmDeleteScan: 'Delete scan',
    aiReportMode: '🤖 SiteScanner AI (Report Analysis)',
    aiExpertMode: '🤖 SiteScanner AI (Expert)',
    aiWelcomeReport: 'Hi! I\'ve reviewed the scan results. What would you like to know?',
    aiWelcomeExpert: 'Hi! I\'m a cybersecurity expert. How can I help?',
    aiThinking: 'Thinking',
    aiPlaceholder: 'Ask a question...',
    aiYou: '👤 You',
    aiBot: '🤖 AI',
    scanQ1: '💡 Rate overall security level',
    scanQ2: '⚠️ What are the main threats?',
    scanQ3: '🛡️ How to fix headers?',
    scanQ4: '🔒 What about certificates?',
    scanQ5: '📋 Create a protection plan',
    genQ1: 'What is OWASP Top 10?',
    genQ2: 'How to protect Nginx from DDoS?',
    genQ3: 'Why is open port 3306 dangerous?',
    genQ4: 'How to configure HSTS?',
    ports: 'Ports',
    printReport: '🖨️ Save as PDF',
    reportTitle: 'Scan Report',
  },
}

const LANG_LABELS = { ru: 'RU', kz: 'KZ', en: 'EN' }

const LangContext = createContext()
function useT() { return useContext(LangContext) }

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
  if (!res.ok) throw new Error(data.error || 'Server error')
  return data
}

/* ======================================================================== */
/*  Компонент: Форма входа и регистрации                                    */
/* ======================================================================== */

function AuthPage({ onAuth }) {
  const t = useT()
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
      setError(t.passwordMismatch)
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
      setError(err instanceof TypeError ? t.serverError : err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="auth-page">
      <div className="auth-card">
        <h1>{t.brand}</h1>
        <p className="subtitle">{t.subtitle}</p>

        <div className="auth-tabs">
          <button className={isLogin ? 'active' : ''} onClick={() => { setIsLogin(true); setError('') }}>
            {t.login}
          </button>
          <button className={!isLogin ? 'active' : ''} onClick={() => { setIsLogin(false); setError('') }}>
            {t.register}
          </button>
        </div>

        <form onSubmit={submit}>
          <input
            type="text"
            placeholder={t.username}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
          />
          <input
            type="password"
            placeholder={t.password}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={isLogin ? 'current-password' : 'new-password'}
            required
          />
          {!isLogin && (
            <input
              type="password"
              placeholder={t.password2}
              value={password2}
              onChange={(e) => setPassword2(e.target.value)}
              autoComplete="new-password"
              required
            />
          )}
          {error && <div className="auth-error">{error}</div>}
          <button type="submit" disabled={loading}>
            {loading ? t.wait : isLogin ? t.loginBtn : t.registerBtn}
          </button>
        </form>
      </div>
    </main>
  )
}

/* ======================================================================== */
/*  Компонент: Шапка с именем пользователя и выходом                        */
/* ======================================================================== */

function Header({ user, onLogout, onAdminToggle, showAdmin, theme, setTheme, lang, setLang }) {
  const t = useT()
  return (
    <header className="app-header">
      <div className="header-brand">{t.brand}</div>
      <div className="header-user">
        <div className="header-controls">
          <button className="theme-toggle" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} title="Theme">
            {theme === 'dark' ? '☀️' : '🌙'}
          </button>
          <select className="lang-select" value={lang} onChange={(e) => setLang(e.target.value)}>
            {Object.entries(LANG_LABELS).map(([k, v]) => (
              <option key={k} value={k}>{v}</option>
            ))}
          </select>
        </div>
        {user.is_admin && (
          <button
            className={`header-admin-btn ${showAdmin ? 'active' : ''}`}
            onClick={onAdminToggle}
          >
            {t.admin}
          </button>
        )}
        <span className="header-username">
          {user.is_admin && <span className="admin-badge">admin</span>}
          {user.username}
        </span>
        <button className="header-logout" onClick={onLogout}>{t.logout}</button>
      </div>
    </header>
  )
}

/* ======================================================================== */
/*  Компонент: Боковая панель истории сканирований                          */
/* ======================================================================== */

function HistoryPanel({ onSelect, refreshTrigger }) {
  const t = useT()
  const [items, setItems] = useState([])
  const [open, setOpen] = useState(false)

  const load = useCallback(async () => {
    try {
      const data = await api('/api/history')
      setItems(data)
    } catch { /* ignore */ }
  }, [])

  useEffect(() => { load() }, [load, refreshTrigger])

  const statusIcon = (s) => s === 'done' ? '✅' : s === 'running' ? '⏳' : '❌'

  return (
    <div className="history-panel">
      <button className="history-toggle" onClick={() => { setOpen(!open); if (!open) load() }}>
        {t.history} {open ? '▲' : '▼'}
      </button>
      {open && (
        <div className="history-list">
          {items.length === 0 && <p className="muted">{t.noScans}</p>}
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
/*  Компоненты отчёта                                                       */
/* ======================================================================== */

function HostCard({ host }) {
  const t = useT()
  const hasRisky = host.open_ports.some((p) => RISKY_PORTS.has(p.port))
  const hc = host.headers_check

  // Подсчёт статистики для дашборда
  let criticalCount = host.vuln_findings.length
  let warnCount = host.nikto_findings.length
  let infoCount = host.open_ports.length

  if (hasRisky) criticalCount += 1
  if (hc && !hc.error && hc.missing.length > 0) warnCount += hc.missing.length
  host.ssl_certs.forEach(c => {
    if (c.domain_mismatch) criticalCount += 1
  })

  return (
    <section className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <h2>
          {host.hostname || host.ip} <span className="muted">{host.ip}</span>
        </h2>
        
        <div className="host-dashboard">
          <div className={`dash-badge ${criticalCount > 0 ? 'critical' : 'ok'}`}>
            🔴 {criticalCount}
          </div>
          <div className={`dash-badge ${warnCount > 0 ? 'warning' : 'ok'}`}>
            🟠 {warnCount}
          </div>
          <div className="dash-badge info">
            🔵 {infoCount}
          </div>
        </div>
      </div>

      <h3>{t.openPorts}</h3>
      <div className="chips">
        {host.open_ports.map((p) => (
          <span key={p.port} className={`chip ${RISKY_PORTS.has(p.port) ? 'warn' : ''}`}>
            {p.port} · {p.service}
          </span>
        ))}
      </div>
      {hasRisky && <p className="hint">{t.riskyHint}</p>}

      <h3>{t.osGuesses}</h3>
      {host.os_guesses.length === 0 ? (
        <p className="muted">{t.osUnknown}</p>
      ) : (
        <ul>
          {host.os_guesses.map((o, i) => (
            <li key={i}>
              {o.name} <span className="muted">— {t.accuracy} {o.accuracy}%</span>
            </li>
          ))}
        </ul>
      )}

      <h3>{t.sslCerts}</h3>
      {host.ssl_certs.length === 0 ? (
        <p className="muted">{t.noCerts}</p>
      ) : (
        host.ssl_certs.map((c, i) => (
          <div key={i} className={`note ${c.domain_mismatch ? 'warn' : ''}`}>
            <b>{t.ports} {c.ports.join(', ')}</b>
            <div>{t.issuedTo}: {stripCN(c.subject)}</div>
            <div>{t.issuedBy}: {stripCN(c.issuer)}</div>
            <div>{t.validUntil}: {fmtDate(c.valid_after)}</div>
            {c.domain_mismatch && <div className="alert">{t.domainMismatch}</div>}
          </div>
        ))
      )}

      <h3>{t.tlsTitle}</h3>
      {host.ssl_ciphers.length === 0 ? (
        <p className="muted">{t.tlsNoData}</p>
      ) : (
        <div className="chips">
          {host.ssl_ciphers.map((c) => (
            <span key={c.port} className={`chip grade-${c.grade || 'none'}`}>
              {t.tlsPort} {c.port} · {t.tlsGrade} {c.grade || '?'}
            </span>
          ))}
        </div>
      )}

      {hc && (
        <>
          <h3>{t.headersTitle}</h3>
          {hc.error ? (
            <p className="muted">{t.headersError}: {hc.error}</p>
          ) : (
            <>
              {hc.missing.length === 0 ? (
                <p className="muted">{t.headersOk}</p>
              ) : (
                <div className="note warn">
                  <b>{t.headersMissing}</b>
                  <div>{hc.missing.join(', ')}</div>
                </div>
              )}
            </>
          )}
        </>
      )}

      {host.vuln_findings.length > 0 && (
        <>
          <h3>{t.vulnTitle}</h3>
          {host.vuln_findings.map((v, i) => (
            <div key={i} className="note warn">
              <b>{t.tlsPort} {v.port} · {v.script}</b>
              <div style={{ whiteSpace: 'pre-wrap' }}>{v.output}</div>
            </div>
          ))}
        </>
      )}

      {host.nikto_findings.length > 0 && (
        <>
          <h3>{t.niktoTitle}</h3>
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
  const t = useT()
  if (!report.hosts.length) {
    return <div className="card">{t.noHosts}</div>
  }
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '30px' }}>
        <h2 style={{ margin: 0 }}>{t.reportTitle}</h2>
        <button className="secondary" style={{ padding: '8px 16px', borderRadius: '8px', border: '1px solid var(--border-color)', background: 'var(--bg-card)', cursor: 'pointer', color: 'var(--text-primary)' }} onClick={() => window.print()}>
          {t.printReport}
        </button>
      </div>
      {report.hosts.map((h) => <HostCard key={h.ip} host={h} />)}
    </div>
  )
}

/* ======================================================================== */
/*  Компонент: ИИ-чат (Gemini-консультант)                                  */
/* ======================================================================== */

function formatAiText(text) {
  return text
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/^### (.+)$/gm, '<h4>$1</h4>')
    .replace(/^## (.+)$/gm, '<h3 style="margin:12px 0 6px">$1</h3>')
    .replace(/^- (.+)$/gm, '<li>$1</li>')
    .replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>')
    .replace(/\n/g, '<br/>')
}

function AiChat({ scanId }) {
  const t = useT()
  const [open, setOpen] = useState(false)
  const [expanded, setExpanded] = useState(false)
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const messagesEndRef = useCallback((node) => {
    if (node) node.scrollIntoView({ behavior: 'smooth' })
  }, [])

  const scanQuestions = [t.scanQ1, t.scanQ2, t.scanQ3, t.scanQ4, t.scanQ5]
  const generalQuestions = [t.genQ1, t.genQ2, t.genQ3, t.genQ4]
  const quickQuestions = scanId ? scanQuestions : generalQuestions

  const sendQuestion = async (text) => {
    if (!text.trim() || loading) return
    const userMsg = { role: 'user', text: text.trim() }
    const newMessages = [...messages, userMsg]
    setMessages(newMessages)
    setInput('')
    setLoading(true)

    try {
      const data = await api('/api/ask', {
        method: 'POST',
        body: JSON.stringify({
          question: text.trim(),
          history: newMessages.slice(-10),
          scan_id: scanId || null,
        }),
      })
      setMessages((prev) => [...prev, { role: 'ai', text: data.answer }])
    } catch (err) {
      setMessages((prev) => [...prev, { role: 'ai', text: `❌ ${err.message}` }])
    } finally {
      setLoading(false)
    }
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    sendQuestion(input)
  }

  if (!open) {
    return (
      <button className="ai-fab" onClick={() => setOpen(true)} title="AI">
        🤖
      </button>
    )
  }

  return (
    <div className={`ai-chat ${expanded ? 'ai-chat-expanded' : ''}`}>
      <div className="ai-chat-header">
        <span>{scanId ? t.aiReportMode : t.aiExpertMode}</span>
        <div className="ai-chat-header-btns">
          <button className="ai-chat-expand" onClick={() => setExpanded((v) => !v)} title={expanded ? 'Свернуть' : 'Развернуть'}>
            {expanded ? '⊡' : '⛶'}
          </button>
          <button className="ai-chat-close" onClick={() => { setOpen(false); setExpanded(false) }}>✕</button>
        </div>
      </div>

      <div className="ai-chat-messages">
        {messages.length === 0 && (
          <div className="ai-welcome">
            <p>{scanId ? t.aiWelcomeReport : t.aiWelcomeExpert}</p>
            <div className="ai-chips">
              {quickQuestions.map((q, i) => (
                <button key={i} className="ai-chip" onClick={() => sendQuestion(q)}>
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}
        {messages.map((msg, i) => (
          <div key={i} className={`ai-msg ${msg.role}`}>
            <div className="ai-msg-label">{msg.role === 'user' ? t.aiYou : t.aiBot}</div>
            {msg.role === 'ai' ? (
              <div className="ai-msg-text" dangerouslySetInnerHTML={{ __html: formatAiText(msg.text) }} />
            ) : (
              <div className="ai-msg-text">{msg.text}</div>
            )}
          </div>
        ))}
        {loading && (
          <div className="ai-msg ai">
            <div className="ai-msg-label">{t.aiBot}</div>
            <div className="ai-msg-text"><span className="ai-typing">{t.aiThinking}<span className="dots">...</span></span></div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {messages.length > 0 && !loading && (
        <div className="ai-chips-bar">
          {quickQuestions.slice(0, 3).map((q, i) => (
            <button key={i} className="ai-chip small" onClick={() => sendQuestion(q)}>
              {q}
            </button>
          ))}
        </div>
      )}

      <form className="ai-chat-input" onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder={t.aiPlaceholder}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          disabled={loading}
        />
        <button type="submit" disabled={!input.trim() || loading}>➤</button>
      </form>
    </div>
  )
}

/* ======================================================================== */
/*  Компонент: Админ-панель                                                 */
/* ======================================================================== */

function AdminPanel({ currentUserId }) {
  const t = useT()
  const [tab, setTab] = useState('stats')
  const [stats, setStats] = useState(null)
  const [users, setUsers] = useState([])
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(false)

  const loadTab = useCallback(async (tt) => {
    setLoading(true)
    try {
      if (tt === 'stats') {
        setStats(await api('/api/admin/stats'))
      } else if (tt === 'users') {
        setUsers(await api('/api/admin/users'))
      } else if (tt === 'scans') {
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
    if (!confirm(`${t.confirmDeleteUser} «${username}»?`)) return
    try {
      await api(`/api/admin/users/${userId}`, { method: 'DELETE' })
      loadTab('users')
    } catch (err) { alert(err.message) }
  }

  const deleteScan = async (scanId) => {
    if (!confirm(`${t.confirmDeleteScan} #${scanId}?`)) return
    try {
      await api(`/api/admin/scans/${scanId}`, { method: 'DELETE' })
      loadTab('scans')
    } catch (err) { alert(err.message) }
  }

  return (
    <main className="page">
      <h1>{t.adminTitle}</h1>
      <p className="subtitle">{t.adminSubtitle}</p>

      <div className="admin-tabs">
        {[
          ['stats', t.tabStats],
          ['users', t.tabUsers],
          ['scans', t.tabScans],
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

      {loading && <div className="status"><span className="spinner" /> {t.loading}</div>}

      {/* Статистика */}
      {tab === 'stats' && stats && !loading && (
        <div className="admin-stats-grid">
          <div className="stat-card">
            <div className="stat-value">{stats.total_users}</div>
            <div className="stat-label">{t.statUsers}</div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{stats.total_scans}</div>
            <div className="stat-label">{t.statTotal}</div>
          </div>
          <div className="stat-card ok">
            <div className="stat-value">{stats.done_scans}</div>
            <div className="stat-label">{t.statDone}</div>
          </div>
          <div className="stat-card err">
            <div className="stat-value">{stats.error_scans}</div>
            <div className="stat-label">{t.statError}</div>
          </div>
          <div className="stat-card running">
            <div className="stat-value">{stats.running_scans}</div>
            <div className="stat-label">{t.statRunning}</div>
          </div>
        </div>
      )}

      {/* Пользователи */}
      {tab === 'users' && !loading && (
        <div className="admin-table-wrap">
          <table className="admin-table">
            <thead>
              <tr>
                <th>{t.thId}</th>
                <th>{t.thName}</th>
                <th>{t.thRole}</th>
                <th>{t.thScans}</th>
                <th>{t.thRegistered}</th>
                <th>{t.thActions}</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td>{u.id}</td>
                  <td>{u.username}</td>
                  <td>
                    <span className={`role-badge ${u.is_admin ? 'admin' : 'user'}`}>
                      {u.is_admin ? t.roleAdmin : t.roleUser}
                    </span>
                  </td>
                  <td>{u.scan_count}</td>
                  <td>{fmtDate(u.created_at)}</td>
                  <td className="action-cell">
                    {u.id !== currentUserId && (
                      <>
                        <button className="btn-sm" onClick={() => toggleAdmin(u.id)}>
                          {u.is_admin ? t.demoteAdmin : t.promoteAdmin}
                        </button>
                        <button className="btn-sm danger" onClick={() => deleteUser(u.id, u.username)}>
                          🗑
                        </button>
                      </>
                    )}
                    {u.id === currentUserId && <span className="muted">{t.itsYou}</span>}
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
                <th>{t.thId}</th>
                <th>{t.thTarget}</th>
                <th>{t.thUser}</th>
                <th>{t.thStatus}</th>
                <th>{t.thDate}</th>
                <th>{t.thActions}</th>
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
                      {s.status === 'done' ? t.statusDone : s.status === 'running' ? t.statusRunning : t.statusError}
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
                <tr><td colSpan={6} className="muted" style={{ textAlign: 'center' }}>{t.noScansAdmin}</td></tr>
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

  /* --- тема и язык --- */
  const [theme, setTheme] = useState(() => localStorage.getItem('theme') || 'dark')
  const [lang, setLang] = useState(() => localStorage.getItem('lang') || 'ru')
  const t = TRANSLATIONS[lang] || TRANSLATIONS.ru

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('theme', theme)
  }, [theme])

  useEffect(() => {
    localStorage.setItem('lang', lang)
  }, [lang])

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

  const checkLabels = {
    ssl_ciphers: t.checkSsl,
    headers: t.checkHeaders,
    vuln: t.checkVuln,
    nikto: t.checkNikto,
  }

  const portLabels = {
    fast: t.fast,
    normal: t.normal,
    full: t.full,
  }

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
      setError(err instanceof TypeError ? t.serverError : err.message)
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
      setScanId(id)
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
          setError(data.error_message || t.scanError)
          setStatus('error')
        }
      } catch { /* retry */ }
    }, 3000)

    return () => clearInterval(timer)
  }, [status, scanId])

  /* --- рендер --- */
  if (!authChecked) return null
  if (!user) return (
    <LangContext.Provider value={t}>
      <div className="auth-lang-bar">
        <button className="theme-toggle" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>
          {theme === 'dark' ? '☀️' : '🌙'}
        </button>
        <select className="lang-select" value={lang} onChange={(e) => setLang(e.target.value)}>
          {Object.entries(LANG_LABELS).map(([k, v]) => (
            <option key={k} value={k}>{v}</option>
          ))}
        </select>
      </div>
      <AuthPage onAuth={handleAuth} />
    </LangContext.Provider>
  )

  return (
    <LangContext.Provider value={t}>
      <Header
        user={user}
        onLogout={handleLogout}
        onAdminToggle={() => setShowAdmin((v) => !v)}
        showAdmin={showAdmin}
        theme={theme}
        setTheme={setTheme}
        lang={lang}
        setLang={setLang}
      />

      {showAdmin && user.is_admin ? (
        <AdminPanel currentUserId={user.id} />
      ) : (
        <main className="page">
          <h1>{t.scannerTitle}</h1>
          <p className="subtitle">{t.scannerSubtitle}</p>

          <HistoryPanel onSelect={loadHistoryReport} refreshTrigger={status === 'done' ? Date.now() : 0} />

          <form className="scan-form" onSubmit={startScan}>
            <input
              type="text"
              placeholder={t.placeholder}
              value={target}
              onChange={(e) => {
                // Автоматически очищаем ввод от https:// и путей
                let val = e.target.value;
                val = val.replace(/^https?:\/\//, ''); // убираем протокол
                val = val.split('/')[0]; // берем только домен
                setTarget(val);
              }}
            />
            {status === 'running' ? (
              <button type="button" className="danger" onClick={stopScan}>
                {t.stop}
              </button>
            ) : (
              <button type="submit" disabled={!target.trim()}>
                {t.start}
              </button>
            )}
            <button
              type="button"
              className="secondary"
              disabled={!report}
              onClick={() => setShowReport((v) => !v)}
            >
              {t.report}
            </button>
          </form>

          <div className="checks">
            {Object.entries(portLabels).map(([key, label]) => (
              <label key={key} className="check">
                <input
                  type="radio"
                  name="portDepth"
                  checked={portDepth === key}
                  onChange={() => setPortDepth(key)}
                />
                {label}
              </label>
            ))}
          </div>

          <div className="checks">
            {Object.entries(checkLabels).map(([key, label]) => (
              <label key={key} className="check">
                <input
                  type="checkbox"
                  checked={checks.includes(key)}
                  onChange={() => toggleCheck(key)}
                />
                {label}
              </label>
            ))}
          </div>

          {status === 'running' && (
            <div className="status">
              <span className="spinner" />
              {currentStep || t.preparing}
            </div>
          )}
          {status === 'done' && !showReport && (
            <div className="status ok">{t.done}</div>
          )}
          {status === 'error' && <div className="status err">{error}</div>}

          {showReport && report && <Report report={report} />}
        </main>
      )}

      {/* ИИ всегда доступен. Если открыт отчёт — он его видит */}
      <AiChat scanId={showReport ? scanId : null} />
    </LangContext.Provider>
  )
}

export default App