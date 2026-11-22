import { useEffect, useMemo, useRef, useState } from 'react'

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

function UsernameSearch({ config }) {
  const [username, setUsername] = useState('')
  const [nsfw, setNsfw] = useState(false)
  const [results, setResults] = useState([])
  const [total, setTotal] = useState(0)
  const [state, setState] = useState('idle') // idle | running | done | error
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('found')
  const [query, setQuery] = useState('')
  const es = useRef(null)

  useEffect(() => () => es.current?.close(), [])

  const start = (e) => {
    e.preventDefault()
    const u = username.trim()
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(u)) {
      setError('Letters, numbers, dot, underscore and dash only (max 64).'); return
    }
    es.current?.close()
    setError(''); setResults([]); setTotal(0); setState('running'); setQuery(u); setFilter('found')
    const src = new EventSource(`/api/search/stream?username=${encodeURIComponent(u)}&nsfw=${nsfw}`)
    es.current = src
    src.addEventListener('start', (ev) => setTotal(JSON.parse(ev.data).total))
    src.addEventListener('result', (ev) => setResults((r) => [...r, JSON.parse(ev.data)]))
    src.addEventListener('done', () => { setState('done'); src.close() })
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
    </section>
  )
}

function BreachSearch({ config }) {
  const [term, setTerm] = useState('')
  const [busy, setBusy] = useState(false)
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const providers = config?.providers || {}
  const any = Object.values(providers).some(Boolean)

  const run = async (e) => {
    e.preventDefault()
    if (!term.trim()) return
    setBusy(true); setError(''); setData(null)
    try {
      const r = await fetch('/api/breach', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ term: term.trim() }) })
      const j = await r.json()
      if (!r.ok) throw new Error(j.detail || 'Lookup failed')
      setData(j)
    } catch (err) { setError(err.message) } finally { setBusy(false) }
  }

  const names = { hibp: 'Have I Been Pwned', dehashed: 'Dehashed', intelx: 'Intelligence X' }
  return (
    <section>
      <form className="searchbar" onSubmit={run}>
        <span className="prompt">$ breach</span>
        <input value={term} onChange={(e) => setTerm(e.target.value)} placeholder="email or username" spellCheck={false} aria-label="Email or username" />
        <button className="btn" disabled={busy || !any}>{busy ? 'Checking…' : 'Check'}</button>
      </form>
      <div className="providers">
        {Object.entries(names).map(([k, n]) => (
          <span key={k} className={`pill ${providers[k] ? 'on' : ''}`}>{providers[k] ? '●' : '○'} {n}</span>
        ))}
      </div>
      {!any && <div className="alert">No breach providers configured yet. Copy <code>.env.example</code> to <code>.env</code>, add your API keys and restart tracefind.</div>}
      {error && <div className="alert">{error}</div>}
      {data?.results.map((p) => (
        <div key={p.provider} className="provider">
          <h3>{names[p.provider]} {p.count != null && <span className={`badge ${p.count ? 'bad' : 'good'}`}>{p.count ? `${p.count} found` : 'clean'}</span>}</h3>
          {p.error && <p className="alert">{p.error}</p>}
          {p.skipped && <p className="muted">{p.skipped}</p>}
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
    </section>
  )
}

export default function App() {
  const [tab, setTab] = useState('user')
  const [config, setConfig] = useState(null)
  const [offline, setOffline] = useState(false)
  useEffect(() => {
    fetch('/api/config').then((r) => r.json()).then(setConfig).catch(() => setOffline(true))
  }, [])

  return (
    <div className="wrap">
      <header>
        <div className="brand"><Mark /><div><div className="wm">trace<span>find</span></div>
          <div className="sub">by MAYPEN CYBERSECURITY</div></div></div>
        <span className="ver mono">v{config?.version || '1.0.0'}</span>
      </header>
      {offline && <div className="alert">Can't reach the tracefind server. Start it with <code>python -m tracefind serve</code>.</div>}
      <nav className="tabs">
        <button className={tab === 'user' ? 'on' : ''} onClick={() => setTab('user')}>Username</button>
        <button className={tab === 'breach' ? 'on' : ''} onClick={() => setTab('breach')}>Breach check</button>
      </nav>
      <div hidden={tab !== 'user'}><UsernameSearch config={config} /></div>
      <div hidden={tab !== 'breach'}><BreachSearch config={config} /></div>
      <footer>For authorized investigations and checking your own exposure. Respect each site's terms and local law. · @MaypenCS</footer>
    </div>
  )
}
