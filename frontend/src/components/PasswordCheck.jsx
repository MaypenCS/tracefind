import { useState } from "react";

/** Checks a password against HIBP Pwned Passwords using k-anonymity.
 *  The password is hashed here in the browser; only the first 5 characters of the
 *  SHA-1 hash are sent to the tracefind server (which forwards them to HIBP). */
async function sha1Hex(text) {
  const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

export default function PasswordCheck() {
  const [pw, setPw] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null); // {count}
  const [err, setErr] = useState("");

  const check = async (e) => {
    e.preventDefault();
    if (!pw) return;
    setBusy(true); setErr(""); setResult(null);
    try {
      const hash = await sha1Hex(pw);
      const prefix = hash.slice(0, 5), suffix = hash.slice(5);
      const r = await fetch(`/api/password/range/${prefix}`);
      if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || "Check failed");
      const text = await r.text();
      let count = 0;
      for (const line of text.split("\n")) {
        const [s, c] = line.trim().split(":");
        if (s === suffix) { count = parseInt(c, 10) || 0; break; }
      }
      setResult({ count });
    } catch (e2) { setErr(e2.message) } finally { setBusy(false); setPw(""); }
  };

  return (
    <div className="pwcheck">
      <h3>Check a password</h3>
      <p className="muted">Your password is hashed in this browser. Only the first 5 characters of the hash leave the
        page, so neither tracefind nor Have I Been Pwned ever sees it.</p>
      <form className="searchbar" onSubmit={check}>
        <span className="prompt">$ pwned</span>
        <input type={show ? "text" : "password"} value={pw} onChange={(e) => setPw(e.target.value)}
               placeholder="password" autoComplete="off" spellCheck={false} aria-label="Password to check" />
        <button type="button" className="btn ghost sm" onClick={() => setShow((s) => !s)}>{show ? "Hide" : "Show"}</button>
        <button className="btn" disabled={busy || !pw}>{busy ? "Checking…" : "Check"}</button>
      </form>
      {err && <div className="alert">{err}</div>}
      {result && (result.count > 0
        ? <div className="pw-result bad"><b>Found {result.count.toLocaleString()} times in breaches.</b> Don't use this
            password anywhere. Change it on every account that uses it, and switch to a password manager.</div>
        : <div className="pw-result good"><b>Not found in known breaches.</b> That's good, but it doesn't make it strong.
            Use a long, unique password for each account.</div>)}
    </div>
  );
}
