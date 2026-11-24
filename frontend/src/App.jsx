import { useEffect, useMemo, useRef, useState } from 'react'
import ExposureReportPanel from './components/ExposureReportPanel.jsx'
import VerifyEmail, { getStoredToken, verifyHeaders } from './components/VerifyEmail.jsx'
import ScanHistory from './components/ScanHistory.jsx'
import DomainScan from './components/DomainScan.jsx'
import PasswordCheck from './components/PasswordCheck.jsx'

const isEmail = (t) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(t)

const Mark = () => (
  <svg viewBox="0 0 120 120" className="mark" aria-hidden="true">
    <rect x="41" y="18" width="38" height="10" rx="3" fill="#33424F" />
    <path d="M38 33 H82 L90 60 C91 63 90 66 88 69 L60 104 L32 69 C30 66 29 63 30 60 Z" fill="#B6FF3B" />
    <circle cx="60" cy="58" r="7.5" fill="#070B10" />
    <rect x="58" y="64" width="4" height="34" rx="2" fill="#070B10" />
  </svg>
)

function download(name, text, type) {
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([text], { type }))
  a.download = name
  a.click()
  URL.revokeObjectURL(a.href)
}

function UsernameSearch({ config, onScanned }) {
  const [username, setUsername] = useState('')
  const [nsfw, setNsfw] = useState(false)
  const [results, setResults] = useState([])
  const [total, setTotal] = useState(0)
  const [state, setState] = useState('idle') // idle | running | done | error
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('found')
  const [query, setQuery] = useState('')
  const es = useRef(null)
  const collected = useRef([])
  const [report, setReport] = useState(null)
  const [reportErr, setReportErr] = useState('')

  useEffect(() => () => es.current?.close(), [])

  // Sweep finished: save it to history and get the Exposure Report back.
  const buildReport = async (u, checked) => {
    const found = collected.current.filter((r) => r.status === 'found').map((r) => ({ site: r.site, url: r.url }))
    try {
      const r = await fetch('/api/search/report', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u, checked, found }) })
      const j = await r.json()
      if (!r.ok) throw new Error(j.detail || 'Report failed')
      setReport(j); onScanned?.()
    } catch (err) { setReportErr(err.message) }
  }

  const start = (e) => {
    e.preventDefault()
    const u = username.trim()
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(u)) {
      setError('Letters, numbers, dot, underscore and dash only (max 64).'); return
    }
    es.current?.close()
    setError(''); setResults([]); setTotal(0); setState('running'); setQuery(u); setFilter('found')
    setReport(null); setReportErr(''); collected.current = []
    let checked = 0
    const src = new EventSource(`/api/search/stream?username=${encodeURIComponent(u)}&nsfw=${nsfw}`)
    es.current = src
    src.addEventListener('start', (ev) => setTotal(JSON.parse(ev.data).total))
    src.addEventListener('result', (ev) => {
      const r = JSON.parse(ev.data); collected.current.push(r); checked += 1
      setResults((rs) => [...rs, r])
    })
    src.addEventListener('done', () => { setState('done'); src.close(); buildReport(u, checked) })
    src.onerror = () => { src.close(); setState((s) => (s === 'done' ? s : 'error')); setError('Connection to the tracefind server dropped.') }
  }

  const stop = () => { es.current?.close(); setState('done') }

  const counts = useMemo(() => {
    const c = { found: 0, not_found: 0, error: 0, invalid: 0 }
    results.forEach((r) => { c[r.status] = (c[r.status] || 0) + 1 })
    return c
  }, [results])

  const shown = useMemo(() => {
    const list = filter === 'all' ? results : results.filter((r) => r.status === filter)
    return [...list].sort((a, b) => a.site.localeCompare(b.site))
  }, [results, filter])

  const found = results.filter((r) => r.status === 'found').sort((a, b) => a.site.localeCompare(b.site))
  const pct = total ? Math.round((results.length / total) * 100) : 0

  return (
    <section>
      <form className="searchbar" onSubmit={start}>
        <span className="prompt">$ tracefind</span>
        <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="username"
               autoFocus spellCheck={false} autoComplete="off" aria-label="Username" />
        {state === 'running'
          ? <button type="button" className="btn ghost" onClick={stop}>Stop</button>
          : <button className="btn">Search</button>}
      </form>
      <div className="opts">
        <label className="toggle"><input type="checkbox" checked={nsfw} onChange={(e) => setNsfw(e.target.checked)} />
          include adult sites ({config ? config.sites_nsfw - config.sites : '…'})</label>
        <span className="muted">{config ? `${config.sites} sites` : ''}</span>
      </div>
      {error && <div className="alert">{error}</div>}

      {state !== 'idle' && (
        <>
          <div className="progress"><div style={{ width: `${pct}%` }} /></div>
          <div className="stats">
            <span className="mono muted">{query} · {results.length}/{total} checked{state === 'running' ? '…' : ''}</span>
            <div className="chips">
              {[['found', 'Found'], ['not_found', 'Not found'], ['error', 'Errors'], ['all', 'All']].map(([k, label]) => (
                <button key={k} className={`chip ${filter === k ? 'on' : ''} ${k}`} onClick={() => setFilter(k)}>
                  {label} <b>{k === 'all' ? results.length : counts[k] || 0}</b>
                </button>
              ))}
            </div>
          </div>

          <ul className="results">
            {shown.map((r) => (
              <li key={r.site} className={r.status}>
                <span className="dot" />
                <span className="site">{r.site}</span>
                {r.status === 'found'
                  ? <a href={r.url} target="_blank" rel="noreferrer noopener" className="url">{r.url}</a>
                  : <span className="url muted">{r.detail || r.status.replace('_', ' ')}</span>}
                <span className="ms mono">{r.elapsed_ms != null ? `${r.elapsed_ms}ms` : ''}</span>
              </li>
            ))}
            {shown.length === 0 && <li className="empty">{state === 'running' ? 'Checking sites…' : 'Nothing here.'}</li>}
          </ul>

          {state === 'done' && found.length > 0 && (
            <div className="exports">
              <span className="muted">Export {found.length} hits:</span>
              <button className="btn ghost sm" onClick={() => download(`tracefind-${query}.json`,
                JSON.stringify({ username: query, checked: total, generated: new Date().toISOString(), found }, null, 2), 'application/json')}>JSON</button>
              <button className="btn ghost sm" onClick={() => download(`tracefind-${query}.csv`,
                'site,url,http_status\n' + found.map((r) => `"${r.site}","${r.url}",${r.http_status ?? ''}`).join('\n'), 'text/csv')}>CSV</button>
            </div>
          )}
          <p className="note">Hits are leads, not proof: the same username can belong to different people. Open each profile and verify by hand.</p>
        </>
      )}
      {reportErr && <div className="alert">Couldn't build the exposure report: {reportErr}</div>}
      {report && <ExposureReportPanel report={report.report} scanId={report.scan_id} />}
    </section>
  )
}

function BreachSearch({ config, onScanned }) {
  const [term, setTerm] = useState('')
  const [busy, setBusy] = useState(false)
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [needVerify, setNeedVerify] = useState('')  // email awaiting verification
  const providers = config?.providers || {}
  const any = Object.values(providers).some(Boolean)

  const lookup = async (t) => {
    setBusy(true); setError(''); setData(null)
    try {
      const r = await fetch('/api/breach', { method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(isEmail(t) ? verifyHeaders(t) : {}) },
        body: JSON.stringify({ term: t }) })
      const j = await r.json()
      if (r.status === 403 && j.detail?.verify_required) { setNeedVerify(t); return }
      if (!r.ok) throw new Error(typeof j.detail === 'string' ? j.detail : j.detail?.message || 'Lookup failed')
      setData(j); if (j.scan_id) onScanned?.()
    } catch (err) { setError(err.message) } finally { setBusy(false) }
  }

  const run = (e) => {
    e.preventDefault()
    const t = term.trim()
    if (!t) return
    setNeedVerify('')
    if (isEmail(t) && !getStoredToken(t)) { setData(null); setError(''); setNeedVerify(t); return }
    lookup(t)
  }

  const names = { xposedornot: 'XposedOrNot (free)', hibp: 'Have I Been Pwned', dehashed: 'Dehashed', intelx: 'Intelligence X' }
  return (
    <section>
      <form className="searchbar" onSubmit={run}>
        <span className="prompt">$ breach</span>
        <input value={term} onChange={(e) => { setTerm(e.target.value); setNeedVerify('') }} placeholder="email or username" spellCheck={false} aria-label="Email or username" />
        <button className="btn" disabled={busy || !any}>{busy ? 'Checking…' : 'Check'}</button>
      </form>
      <div className="providers">
        {Object.entries(names).map(([k, n]) => (
          <span key={k} className={`pill ${providers[k] ? 'on' : ''}`}>{providers[k] ? '●' : '○'} {n}</span>
        ))}
      </div>
      {!any && <div className="alert">All breach providers are turned off. XposedOrNot is free and needs no key: remove <code>TRACEFIND_DISABLE_XON</code> from <code>.env</code> and restart tracefind.</div>}
      {error && <div className="alert">{error}</div>}
      {needVerify && (
        <VerifyEmail key={needVerify} email={needVerify}
                     onVerified={() => { setNeedVerify(''); lookup(needVerify) }}
                     onCancel={() => setNeedVerify('')} cancelLabel="Cancel" />
      )}
      {data?.results.map((p) => (
        <div key={p.provider} className="provider">
          <h3>{names[p.provider]} {p.count != null && <span className={`badge ${p.count ? 'bad' : 'good'}`}>{p.count ? `${p.count} found` : 'clean'}</span>}</h3>
          {p.error && <p className="alert">{p.error}</p>}
          {p.skipped && <p className="muted">{p.skipped}</p>}
          {p.pastes > 0 && <p className="muted mono">{p.pastes} paste record{p.pastes === 1 ? '' : 's'}</p>}
          {p.total_records != null && <p className="muted mono">{p.total_records} records across {p.count} source{p.count === 1 ? '' : 's'}</p>}
          <ul className="breaches">
            {(p.breaches || []).map((b, i) => (
              <li key={i}>
                <div className="bhead"><b>{b.name}</b>{b.date && <span className="mono muted">{b.date}</span>}
                  {b.accounts && <span className="mono muted">{b.accounts.toLocaleString()} accounts</span>}
                  {b.secrets_exposed && <span className="badge bad">credentials exposed</span>}</div>
                {b.data_types?.length > 0 && <div className="types">{b.data_types.map((t) => <span key={t}>{t}</span>)}</div>}
              </li>
            ))}
          </ul>
        </div>
      ))}
      {data && <p className="note">tracefind shows which breaches and which kinds of data were exposed. It never displays leaked passwords or hashes.</p>}
      {data?.report && <ExposureReportPanel report={data.report} scanId={data.scan_id}
                                            headers={isEmail(data.term) ? verifyHeaders(data.term) : {}} />}
      {data?.results.some((p) => p.attribution) && <p className="note">Breach details from <a href="https://haveibeenpwned.com" target="_blank" rel="noreferrer noopener">Have I Been Pwned</a> (CC BY 4.0).</p>}
      <PasswordCheck />
    </section>
  )
}

function HistoryLookup({ onOpen }) {
  const [q, setQ] = useState('')
  const submit = (e) => {
    e.preventDefault()
    const t = q.trim().toLowerCase()
    if (!t) return
    onOpen({ target: t, target_type: isEmail(t) ? 'email' : 'domain' })
  }
  return (
    <>
      <form className="searchbar" onSubmit={submit}>
        <span className="prompt">$ history</span>
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="your email or domain"
               spellCheck={false} autoComplete="off" aria-label="Email or domain" />
        <button className="btn" disabled={!q.trim()}>Open</button>
      </form>
      <p className="note">History is private. Emails need the 6-digit code. Domains need the TraceFind ownership
        record from the Domain tab.</p>
    </>
  )
}

function HistoryTab({ refreshKey, isPublic }) {
  const [targets, setTargets] = useState([])
  const [sel, setSel] = useState(null)
  const [verifyFor, setVerifyFor] = useState('')
  const [demo, setDemo] = useState(false)

  useEffect(() => {
    if (isPublic) return
    fetch('/api/history/targets').then((r) => r.json()).then(setTargets).catch(() => setTargets([]))
  }, [refreshKey, isPublic])

  const open = (t) => {
    setDemo(false)
    if (t.target_type === 'email' && !getStoredToken(t.target)) { setSel(null); setVerifyFor(t.target); return }
    setVerifyFor(''); setSel(t)
  }

  return (
    <section>
      <div className="hist-head">
        <span className="muted">{isPublic ? 'See how your exposure changed between scans.'
                                          : 'Saved scans are kept on this PC. Pick a target to see what changed between scans.'}</span>
        <button className="btn ghost sm" onClick={() => { setSel(null); setVerifyFor(''); setDemo((d) => !d) }}>
          {demo ? 'Hide demo' : 'Demo report'}</button>
      </div>
      {isPublic && !demo && <HistoryLookup onOpen={open} />}
      {!isPublic && targets.length === 0 && !demo && <p className="muted hist-empty">No saved scans yet. Run a username, email or domain scan first.</p>}
      {targets.length > 0 && (
        <ul className="hist-targets">
          {targets.map((t) => (
            <li key={t.target_type + t.target}>
              <button className={sel?.target === t.target && sel?.target_type === t.target_type ? 'on' : ''} onClick={() => open(t)}>
                <span className={`hist-type ${t.target_type}`}>{t.target_type}</span>
                <span className="hist-name">{t.target}</span>
                <span className={`hist-sev ${t.latest_overall}`}>{t.latest_overall}</span>
                <span className="muted mono">{t.scans} scan{t.scans === 1 ? '' : 's'}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
      {verifyFor && <VerifyEmail key={verifyFor} email={verifyFor}
                                 onVerified={() => { const t = { target: verifyFor, target_type: 'email' }; setVerifyFor(''); setSel(t) }}
                                 onCancel={() => setVerifyFor('')} cancelLabel="Cancel" />}
      {sel && <ScanHistory key={sel.target_type + sel.target} target={sel.target} targetType={sel.target_type}
                           refreshKey={refreshKey} onNeedVerify={() => { setVerifyFor(sel.target); setSel(null) }} />}
      {demo && <ExposureReportPanel demo />}
    </section>
  )
}

export default function App() {
  const [tab, setTab] = useState('user')
  const [scans, setScans] = useState(0)
  const bump = () => setScans((n) => n + 1)
  const [config, setConfig] = useState(null)
  const [offline, setOffline] = useState(false)
  const isPublic = !!config?.public
  useEffect(() => {
    fetch('/api/config').then((r) => r.json()).then((c) => {
      setConfig(c)
      if (c.public) setTab((t) => (t === 'user' ? 'breach' : t))  // no username sweep on the public site
    }).catch(() => setOffline(true))
  }, [])

  return (
    <div className="wrap">
      <header>
        <div className="brand"><Mark /><div><div className="wm">trace<span>find</span></div>
          <div className="sub">by MAYPEN CYBERSECURITY</div></div></div>
        <span className="ver mono">v{config?.version || '1.0.0'}</span>
      </header>
      {offline && <div className="alert">Can't reach the tracefind server. {isPublic ? 'Please try again shortly.' : <>Start it with <code>python -m tracefind serve</code>.</>}</div>}
      <nav className="tabs">
        {!isPublic && <button className={tab === 'user' ? 'on' : ''} onClick={() => setTab('user')}>Username</button>}
        <button className={tab === 'breach' ? 'on' : ''} onClick={() => setTab('breach')}>Breach check</button>
        <button className={tab === 'domain' ? 'on' : ''} onClick={() => setTab('domain')}>Domain</button>
        <button className={tab === 'history' ? 'on' : ''} onClick={() => setTab('history')}>History</button>
      </nav>
      {!isPublic && <div hidden={tab !== 'user'}><UsernameSearch config={config} onScanned={bump} /></div>}
      <div hidden={tab !== 'breach'}><BreachSearch config={config} onScanned={bump} /></div>
      <div hidden={tab !== 'domain'}><DomainScan onScanned={bump} /></div>
      <div hidden={tab !== 'history'}><HistoryTab refreshKey={scans} isPublic={isPublic} /></div>
      <footer>{isPublic
        ? <>Check your own exposure: emails you can receive mail at, and domains you control. Lookups are rate-limited. · <a href="https://maypencs.net">maypencs.net</a> · @MaypenCS</>
        : <>For authorized investigations and checking your own exposure. Respect each site's terms and local law. · @MaypenCS</>}</footer>
    </div>
  )
}
