import { useCallback, useEffect, useRef, useState } from "react";
import ExposureReportPanel from "./ExposureReportPanel";
import { verifyHeaders } from "./VerifyEmail";
import "./ScanHistory.css";

/**
 * ScanHistory: timeline of saved scans for one target, with compare and report.
 *
 * Props:
 *   target, targetType – e.g. "maypencs", "username"
 *   apiBase            – backend origin, default ""
 *   refreshKey         – change this after a new scan to reload the list
 *   onNeedVerify       – called if the backend says email verification is required
 */
export default function ScanHistory({ target, targetType, apiBase = "", refreshKey = 0, onNeedVerify }) {
  const [scans, setScans] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [sel, setSel] = useState([]);        // up to 2 scan ids to compare
  const [diff, setDiff] = useState(null);
  const [viewId, setViewId] = useState(null);
  const [viewReport, setViewReport] = useState(null);

  // Keep the latest callback in a ref so an inline prop doesn't retrigger loading every render.
  const needVerifyRef = useRef(onNeedVerify);
  needVerifyRef.current = onNeedVerify;

  const headers = targetType === "email" ? verifyHeaders(target) : {};
  const hk = JSON.stringify(headers);

  const api = useCallback(async (path, opts = {}) => {
    const r = await fetch(`${apiBase}${path}`, { ...opts, headers: { ...headers, ...(opts.headers || {}) } });
    const data = await r.json().catch(() => ({}));
    if (r.status === 403) {
      if (targetType === "email") needVerifyRef.current?.();
      throw new Error(data.detail || "You need to prove you own this to see its history.");
    }
    if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
    return data;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [apiBase, hk, targetType]);

  const load = useCallback(async () => {
    if (!target) return;
    setLoading(true);
    setError("");
    try {
      const q = new URLSearchParams({ target, target_type: targetType });
      const list = await api(`/api/history?${q}`);
      setScans(list);
      setSel(list.length >= 2 ? [list[1].id, list[0].id] : []);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [api, target, targetType]);

  useEffect(() => { load(); }, [load, refreshKey]);

  // Compare whenever two scans are selected.
  useEffect(() => {
    setDiff(null);
    if (sel.length !== 2) return;
    api(`/api/history/compare?from_id=${sel[0]}&to_id=${sel[1]}`).then(setDiff).catch((e) => setError(e.message));
  }, [sel, api]);

  function toggle(id) {
    setSel((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s.slice(-1), id]));
  }

  async function openReport(id) {
    setViewId(id);
    setViewReport(null);
    try {
      setViewReport(await api(`/api/history/scan/${id}/report`));
    } catch (e) {
      setError(e.message);
      setViewId(null);
    }
  }

  async function remove(id) {
    if (!window.confirm("Delete this scan from history?")) return;
    try {
      await api(`/api/history/scan/${id}`, { method: "DELETE" });
      if (viewId === id) { setViewId(null); setViewReport(null); }
      load();
    } catch (e) {
      setError(e.message);
    }
  }

  const fmt = (iso) => new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

  return (
    <section className="sh">
      <header className="sh-head">
        <div>
          <div className="sh-kicker">Scan history</div>
          <h2>{target}</h2>
        </div>
        <span className="sh-muted">{scans.length} scan{scans.length !== 1 ? "s" : ""}</span>
      </header>

      {error && <div className="sh-error">{error}</div>}
      {loading && <p className="sh-muted">Loading…</p>}
      {!loading && scans.length === 0 && !error && (
        <p className="sh-muted">No saved scans yet. Run a scan and it will appear here.</p>
      )}

      {scans.length > 0 && (
        <>
          <p className="sh-hint">Tick two scans to compare them.</p>
          <ol className="sh-list">
            {scans.map((s) => (
              <li key={s.id} className={`sh-item ${sel.includes(s.id) ? "is-sel" : ""}`}>
                <label className="sh-check">
                  <input type="checkbox" checked={sel.includes(s.id)} onChange={() => toggle(s.id)} />
                </label>
                <span className={`sh-badge sev-${s.overall}`}>{s.overall}</span>
                <div className="sh-main">
                  <div className="sh-date">{fmt(s.scanned_at)}</div>
                  <div className="sh-muted">
                    {s.username_hits} account{s.username_hits !== 1 ? "s" : ""}
                    {s.breach_checks ? ` · ${s.breaches} breach${s.breaches !== 1 ? "es" : ""}` : " · breaches not checked"}
                  </div>
                </div>
                <button className="sh-btn" onClick={() => openReport(s.id)}>Report</button>
                <button className="sh-btn sh-danger" onClick={() => remove(s.id)} aria-label="Delete scan">✕</button>
              </li>
            ))}
          </ol>
        </>
      )}

      {diff && (
        <div className="sh-diff">
          <h3>
            {new Date(diff.previous_scanned_at).toLocaleDateString()} → {new Date(diff.current_scanned_at).toLocaleDateString()}
          </h3>
          {!diff.has_changes && <p className="sh-muted">No changes between these scans.</p>}
          {diff.new_accounts.length > 0 && (
            <DiffBlock kind="add" title="New accounts" items={diff.new_accounts.map((h) => (
              <a key={h.url} href={h.url} target="_blank" rel="noreferrer noopener">{h.platform}</a>))} />
          )}
          {diff.removed_accounts.length > 0 && (
            <DiffBlock kind="rem" title="No longer found" items={diff.removed_accounts.map((h) => h.platform)} />
          )}
          {diff.new_breaches.length > 0 && (
            <DiffBlock kind="add" title="New breaches" items={diff.new_breaches.map((b) =>
              `${b.name}${b.data_classes.length ? ` (${b.data_classes.join(", ")})` : ""}`)} />
          )}
          {diff.expanded_breaches.length > 0 && (
            <DiffBlock kind="add" title="Newly reported data" items={diff.expanded_breaches.map((c) =>
              `${c.name}: ${c.new_data_classes.join(", ")}`)} />
          )}
          {diff.new_pastes.length > 0 && (
            <DiffBlock kind="add" title="New paste/leak records" items={diff.new_pastes.map((p) => p.title)} />
          )}
          {diff.breach_coverage_changed && (
            <p className="sh-muted">Breach checks ran in only one of these scans, so breach changes may be incomplete.</p>
          )}
        </div>
      )}

      {viewId != null && (
        <div className="sh-report">
          {viewReport
            ? <ExposureReportPanel report={viewReport} scanId={viewId} apiBase={apiBase} headers={headers} />
            : <p className="sh-muted">Loading report…</p>}
        </div>
      )}
    </section>
  );
}

function DiffBlock({ kind, title, items }) {
  return (
    <div className={`sh-block sh-${kind}`}>
      <div className="sh-block-title">{kind === "add" ? "+" : "−"} {title} ({items.length})</div>
      <ul>{items.map((it, i) => <li key={i}>{it}</li>)}</ul>
    </div>
  );
}
