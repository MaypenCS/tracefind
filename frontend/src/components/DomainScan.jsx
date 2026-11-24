import { useState } from "react";
import ExposureReportPanel from "./ExposureReportPanel";
import "./DomainScan.css";

/**
 * DomainScan: "Domain Exposure" tab.
 * Passive checks run for any domain. Exposed-file checks need verified ownership.
 *
 * Props: apiBase (default ""), onScanned(data) optional, e.g. to bump ScanHistory's refreshKey.
 */
export default function DomainScan({ apiBase = "", onScanned }) {
  const [domain, setDomain] = useState("");
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState("");
  const [result, setResult] = useState(null);
  const [own, setOwn] = useState(null);          // ownership instructions
  const [ownStatus, setOwnStatus] = useState(null); // {verified, method}
  const [authorized, setAuthorized] = useState(false);
  const [copied, setCopied] = useState("");

  async function call(path, opts) {
    const r = await fetch(`${apiBase}${path}`, opts);
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      const d = data.detail;
      const e = new Error(typeof d === "string" ? d : d?.message || `HTTP ${r.status}`);
      e.detail = d;
      throw e;
    }
    return data;
  }

  async function scan(active) {
    if (!domain.trim()) return;
    setBusy(active ? "full" : "passive");
    setErr("");
    try {
      const data = await call("/api/domain/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, active }),
      });
      setResult(data);
      onScanned?.(data);
    } catch (e) {
      setErr(e.message);
      if (e.detail?.ownership) setOwn(e.detail.ownership);
    } finally {
      setBusy("");
    }
  }

  async function showOwnership() {
    setErr("");
    try {
      setOwn(await call(`/api/domain/ownership?domain=${encodeURIComponent(domain)}`));
      setOwnStatus(null);
    } catch (e) {
      setErr(e.message);
    }
  }

  async function checkOwnership() {
    setBusy("own");
    setErr("");
    try {
      setOwnStatus(await call("/api/domain/ownership/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      }));
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy("");
    }
  }

  function copy(text, key) {
    navigator.clipboard?.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(""), 1500);
  }

  const verified = ownStatus?.verified;

  return (
    <section className="ds">
      <form className="searchbar" onSubmit={(e) => { e.preventDefault(); scan(false); }}>
        <span className="prompt">$ domain</span>
        <input placeholder="yourbusiness.ca" value={domain} aria-label="Domain"
               onChange={(e) => { setDomain(e.target.value); setOwn(null); setOwnStatus(null); setResult(null); }}
               autoCapitalize="none" autoCorrect="off" spellCheck={false} autoComplete="off" />
        <button className="btn" type="submit" disabled={!!busy || !domain.trim()}>
          {busy === "passive" ? "Scanning…" : "Scan"}
        </button>
      </form>
      <p className="ds-muted ds-intro">
        Checks email spoofing protection (SPF, DKIM, DMARC), HTTPS, security headers and public subdomains.
      </p>

      <div className="ds-active">
        <div>
          <b>Exposed files &amp; admin pages</b>
          <p className="ds-muted">
            Looks for leaked .env files, .git folders, database backups and public login pages.
            This actively probes the server, so you have to prove you own the domain first.
          </p>
        </div>
        {!own && <button className="ds-btn" onClick={showOwnership} disabled={!domain.trim()}>Verify ownership</button>}
      </div>

      {own && (
        <div className="ds-own">
          <p>Add <b>one</b> of these, then click <i>Check</i>:</p>
          <div className="ds-opt">
            <div className="ds-label">Option 1: DNS TXT record</div>
            <table className="ds-table"><tbody>
              <tr><td>Type</td><td><code>{own.dns.type}</code></td></tr>
              <tr><td>Name</td><td><code>{own.dns.name}</code>
                <button className="ds-copy" onClick={() => copy(own.dns.name, "n")}>{copied === "n" ? "✓" : "Copy"}</button></td></tr>
              <tr><td>Value</td><td><code>{own.dns.value}</code>
                <button className="ds-copy" onClick={() => copy(own.dns.value, "v")}>{copied === "v" ? "✓" : "Copy"}</button></td></tr>
            </tbody></table>
            <p className="ds-muted">DNS changes can take a few minutes to show up.</p>
          </div>
          <div className="ds-opt">
            <div className="ds-label">Option 2: upload a file</div>
            <p>Create <code>{own.file.url}</code> containing:</p>
            <code className="ds-block">{own.file.content}</code>
            <button className="ds-copy" onClick={() => copy(own.file.content, "f")}>{copied === "f" ? "✓" : "Copy"}</button>
          </div>

          <button className="ds-btn" onClick={checkOwnership} disabled={busy === "own"}>
            {busy === "own" ? "Checking…" : "Check"}
          </button>
          {ownStatus && (
            <p className={verified ? "ds-ok" : "ds-err"}>
              {verified ? `✓ Ownership verified (${ownStatus.method === "dns" ? "DNS record" : "file"})`
                        : "Not found yet. Double-check the record, wait a few minutes, and try again."}
            </p>
          )}

          {verified && (
            <>
              <label className="ds-consent">
                <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
                I own this domain or have written permission to test it.
              </label>
              <button className="ds-primary" onClick={() => scan(true)} disabled={!authorized || !!busy}>
                {busy === "full" ? "Running full scan… (about 30 seconds)" : "Run full scan"}
              </button>
            </>
          )}
        </div>
      )}

      {err && <p className="ds-err" role="alert">{err}</p>}

      {result && (
        <div className="ds-result">
          <ExposureReportPanel report={result.report} scanId={result.scan_id} apiBase={apiBase} />
        </div>
      )}
    </section>
  );
}
