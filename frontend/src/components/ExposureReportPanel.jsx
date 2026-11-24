import { useEffect, useState } from "react";
import "./ExposureReportPanel.css";

/**
 * ExposureReportPanel
 *
 * Props:
 *   scan     – normalized ScanResult object (see backend/report/models.py), or null
 *   report   – an already-built ExposureReport (e.g. from save_and_report or history);
 *              when given, no request is made
 *   scanId   – saved history scan id; downloads then include "Changes since last scan"
 *   demo     – if true, loads the fictional demo report instead of `scan`
 *   headers  – extra request headers, e.g. verifyHeaders(email)
 *   apiBase  – backend origin, default "" (same origin / Vite proxy)
 *
 * Usage:
 *   <ExposureReportPanel scan={scanResult} />
 *   <ExposureReportPanel demo />
 */
const SEVERITIES = ["high", "medium", "low", "info"];
let pdfViaBrowser = false; // set once the server reports it has no PDF engine

export default function ExposureReportPanel({
  scan = null, report: given = null, scanId = null, demo = false, apiBase = "", headers = {},
}) {
  const [report, setReport] = useState(given);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState({});
  const [downloading, setDownloading] = useState("");

  const headerKey = JSON.stringify(headers);

  useEffect(() => {
    if (given) {
      setReport(given);
      setOpen(Object.fromEntries(given.findings.map((f) => [f.id, f.severity === "high"])));
      return;
    }
    if (!demo && !scan) return;
    const ctrl = new AbortController();
    setLoading(true);
    setError("");
    const req = demo
      ? fetch(`${apiBase}/api/report/demo`, { signal: ctrl.signal })
      : fetch(`${apiBase}/api/report/findings`, {
          method: "POST",
          headers: { "Content-Type": "application/json", ...headers },
          body: JSON.stringify(scan),
          signal: ctrl.signal,
        });
    req
      .then(async (r) => {
        if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
        return r.json();
      })
      .then((data) => {
        setReport(data);
        // Expand high-severity findings by default
        setOpen(Object.fromEntries(data.findings.map((f) => [f.id, f.severity === "high"])));
      })
      .catch((e) => e.name !== "AbortError" && setError(String(e.message || e)))
      .finally(() => setLoading(false));
    return () => ctrl.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scan, given, demo, apiBase, headerKey]);

  function fetchReport(format) {
    return demo
      ? fetch(`${apiBase}/api/report/demo?format=${format}`)
      : scanId != null
      ? fetch(`${apiBase}/api/history/scan/${scanId}/report?format=${format}`, { headers })
      : fetch(`${apiBase}/api/report/${format}`, {
          method: "POST",
          headers: { "Content-Type": "application/json", ...headers },
          body: JSON.stringify(scan ?? report.scan),
        });
  }

  // No server-side PDF engine (e.g. WeasyPrint without GTK on Windows): print the HTML report
  // through the browser instead. The print dialog's "Save as PDF" gives the same file.
  async function printToPdf() {
    const r = await fetchReport("html");
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const html = await r.text();
    const frame = document.createElement("iframe");
    frame.setAttribute("aria-hidden", "true");
    frame.style.cssText = "position:fixed;right:0;bottom:0;width:0;height:0;border:0;visibility:hidden";
    frame.srcdoc = html;
    frame.onload = () => {
      const w = frame.contentWindow;
      w.document.title = `TraceFind-Exposure-Report-${report?.report_id ?? "report"}`; // default PDF file name
      w.focus();
      w.print();
      setTimeout(() => frame.remove(), 60000);
    };
    document.body.appendChild(frame);
  }

  async function download(format) {
    setDownloading(format);
    setError("");
    try {
      if (format === "pdf" && pdfViaBrowser) {
        await printToPdf();
        return;
      }
      const r = await fetchReport(format);
      if (format === "pdf" && r.status === 501) {
        pdfViaBrowser = true; // remember for the rest of the session
        await printToPdf();
        return;
      }
      if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `TraceFind-Exposure-Report-${report?.report_id ?? "report"}.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setDownloading("");
    }
  }

  if (!demo && !scan && !given) return null;
  if (loading) return <div className="erp erp-loading">Analyzing exposure…</div>;
  if (error && !report) return <div className="erp erp-error">Couldn’t build report: {error}</div>;
  if (!report) return null;

  return (
    <section className="erp">
      {report.scan.is_demo && <div className="erp-demo">Demo report — all data is fictional</div>}

      <header className="erp-head">
        <div>
          <div className="erp-kicker">Exposure Report · {report.report_id}</div>
          <h2>{report.scan.target}</h2>
        </div>
        <div className="erp-actions">
          <button onClick={() => download("html")} disabled={!!downloading}>
            {downloading === "html" ? "Preparing…" : "Download HTML"}
          </button>
          <button className="primary" onClick={() => download("pdf")} disabled={!!downloading}>
            {downloading === "pdf" ? "Preparing…" : "Download PDF"}
          </button>
        </div>
      </header>

      {error && <div className="erp-error">{error}</div>}

      <div className={`erp-overall sev-${report.overall}`}>
        <span className="erp-badge big">{report.overall}</span>
        <p>{report.summary}</p>
      </div>

      <div className="erp-counts">
        {SEVERITIES.map((s) => (
          <div key={s} className={`erp-count sev-${s}`}>
            <b>{report.counts[s]}</b>
            <span>{s}</span>
          </div>
        ))}
      </div>

      {report.changes && (
        <div className="erp-changes">
          <h3>Changes since {new Date(report.changes.previous_scanned_at).toLocaleDateString()}</h3>
          <ul>{report.changes_summary.map((c) => <li key={c}>{c}</li>)}</ul>
        </div>
      )}

      <div className="erp-findings">
        {report.findings.map((f) => (
          <article key={f.id} className={`erp-finding sev-${f.severity}`}>
            <button className="erp-finding-head" onClick={() => setOpen((o) => ({ ...o, [f.id]: !o[f.id] }))}
                    aria-expanded={!!open[f.id]}>
              <span className="erp-badge">{f.severity}</span>
              <span className="erp-title">{f.title}</span>
              <span className="erp-chev">{open[f.id] ? "−" : "+"}</span>
            </button>
            {open[f.id] && (
              <div className="erp-body">
                <h4>Why it matters</h4>
                <p>{f.why_it_matters}</p>
                <h4>What to do</h4>
                <ul>{f.actions.map((a) => <li key={a}>{a}</li>)}</ul>
                {f.evidence.length > 0 && (
                  <>
                    <h4>Details</h4>
                    <ul className="erp-evidence">{f.evidence.map((e) => <li key={e}>{e}</li>)}</ul>
                  </>
                )}
              </div>
            )}
          </article>
        ))}
        {report.findings.length === 0 && <p className="erp-muted">No findings in the sources checked.</p>}
      </div>

      {report.unverified.length > 0 && (
        <details className="erp-unverified">
          <summary>What TraceFind could not verify ({report.unverified.length})</summary>
          <ul>{report.unverified.map((u) => <li key={u}>{u}</li>)}</ul>
        </details>
      )}

      {report.scan.sources?.some((s) => s.status === "ok") && (
        <p className="erp-footnote">
          Sources checked: {report.scan.sources.filter((s) => s.status === "ok").map((s) => s.name).join(", ")}.
          {report.scan.sources.some((s) => (s.detail || "").includes("CC BY")) &&
            " Breach details from Have I Been Pwned (CC BY 4.0)."}
        </p>
      )}
      <p className="erp-footnote">Potential exposure identified — verify ownership before acting.</p>
    </section>
  );
}
