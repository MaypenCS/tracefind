import { useEffect, useRef, useState } from "react";
import "./VerifyEmail.css";

export const VERIFY_HEADER = "X-TraceFind-Verify";
const KEY = (email) => `tracefind.verify.${email.trim().toLowerCase()}`;

/** Returns a stored, unexpired token for this email, or null. */
export function getStoredToken(email) {
  try {
    const raw = sessionStorage.getItem(KEY(email));
    if (!raw) return null;
    const { token, expires_at } = JSON.parse(raw);
    return Date.now() / 1000 < expires_at ? token : null;
  } catch {
    return null;
  }
}

/** Headers to add to your scan request so the backend shows breach results. */
export function verifyHeaders(email) {
  const t = email && getStoredToken(email);
  return t ? { [VERIFY_HEADER]: t } : {};
}

/**
 * VerifyEmail: two-step ownership check before breach results are shown.
 *
 * Props:
 *   email       – address to verify (pre-filled from the scan box)
 *   onVerified  – called with (token) once verified
 *   onCancel    – optional; "Scan without breach results" link
 *   apiBase     – backend origin, default ""
 */
export default function VerifyEmail({ email, onVerified, onCancel, cancelLabel = "Scan without breach results", apiBase = "" }) {
  const [step, setStep] = useState("start"); // start | code | done
  const [code, setCode] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [cooldown, setCooldown] = useState(0);
  const codeRef = useRef(null);

  // Already verified this session? Skip straight through.
  useEffect(() => {
    const t = getStoredToken(email);
    if (t) {
      setStep("done");
      onVerified?.(t);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [email]);

  useEffect(() => {
    if (cooldown <= 0) return;
    const id = setTimeout(() => setCooldown((c) => c - 1), 1000);
    return () => clearTimeout(id);
  }, [cooldown]);

  useEffect(() => {
    if (step === "code") codeRef.current?.focus();
  }, [step]);

  async function post(path, body) {
    const r = await fetch(`${apiBase}/api/verify/${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      const retry = Number(r.headers.get("Retry-After"));
      if (retry && retry <= 120) setCooldown(retry);
      throw new Error(data.detail || `Request failed (${r.status})`);
    }
    return data;
  }

  async function sendCode() {
    setBusy(true);
    setErr("");
    setMsg("");
    try {
      await post("request", { email });
      setStep("code");
      setCode("");
      setCooldown(60);
      setMsg(`We sent a 6-digit code to ${email}. It expires in 10 minutes.`);
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function confirm(e) {
    e?.preventDefault();
    if (code.length !== 6) return;
    setBusy(true);
    setErr("");
    try {
      const { token, expires_at } = await post("confirm", { email, code });
      sessionStorage.setItem(KEY(email), JSON.stringify({ token, expires_at }));
      setStep("done");
      onVerified?.(token);
    } catch (e) {
      setErr(e.message);
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  // Auto-submit once 6 digits are entered (also handles paste).
  useEffect(() => {
    if (step === "code" && code.length === 6 && !busy) confirm();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [code]);

  if (step === "done") {
    return <div className="ve ve-done">✓ Verified: {email}</div>;
  }

  return (
    <div className="ve">
      
      <h3>Confirm this is your email</h3>
      <p className="ve-muted">
        Breach results are only shown to the owner of the inbox. This keeps TraceFind from being
        used to look up other people.
      </p>

      {step === "start" && (
        <>
          <div className="ve-email">{email}</div>
          <button className="ve-primary" onClick={sendCode} disabled={busy || cooldown > 0}>
            {busy ? "Sending…" : cooldown > 0 ? `Try again in ${cooldown}s` : "Send verification code"}
          </button>
        </>
      )}

      {step === "code" && (
        <form onSubmit={confirm}>
          {msg && <p className="ve-msg">{msg}</p>}
          <input
            ref={codeRef}
            className="ve-code"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            placeholder="••••••"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
            disabled={busy}
            aria-label="6-digit verification code"
          />
          <button className="ve-primary" type="submit" disabled={busy || code.length !== 6}>
            {busy ? "Checking…" : "Verify"}
          </button>
          <button type="button" className="ve-link" onClick={sendCode} disabled={busy || cooldown > 0}>
            {cooldown > 0 ? `Resend code in ${cooldown}s` : "Resend code"}
          </button>
        </form>
      )}

      {err && <p className="ve-err" role="alert">{err}</p>}

      {onCancel && (
        <button type="button" className="ve-link" onClick={onCancel}>
          {cancelLabel}
        </button>
      )}
    </div>
  );
}
