import { useState } from "react";
import { login } from "../services/auth.js";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function LoginPage({ onAuthed, onGoRegister }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [touched, setTouched] = useState({});
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const emailValid = EMAIL_RE.test(email);
  const passwordValid = password.length >= 8;
  const canSubmit = emailValid && passwordValid && !submitting;

  async function handleSubmit(event) {
    event.preventDefault();
    setTouched({ email: true, password: true });
    if (!emailValid || !passwordValid) return;
    setError("");
    setSubmitting(true);
    try {
      const user = await login({ email, password });
      onAuthed(user);
    } catch (err) {
      setError(err.message || "Unable to sign in. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className='auth-page'>
      <div className='card card-elevated auth-card'>
        <div className='auth-head'>
          <div className='auth-icon'>
            <img
              src='/shield.png'
              alt='SentryStrike'
              className='auth-icon-img'
            />
          </div>
          <h1 className='auth-title'>Welcome back</h1>
          <p className='auth-sub'>Sign in to continue to SentryStrike</p>
        </div>

        <form onSubmit={handleSubmit} noValidate>
          {error && <div className='auth-error'>{error}</div>}

          <label className='form-label' htmlFor='login-email'>
            Email
          </label>
          <div
            className={`input-group ${touched.email && !emailValid ? "error" : emailValid ? "valid" : ""}`}
          >
            <input
              id='login-email'
              type='email'
              autoComplete='email'
              placeholder='you@example.com'
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              onBlur={() => setTouched((t) => ({ ...t, email: true }))}
              disabled={submitting}
            />
          </div>
          {touched.email && !emailValid && (
            <p className='field-error'>Enter a valid email address</p>
          )}

          <label
            className='form-label'
            htmlFor='login-password'
            style={{ marginTop: 16 }}
          >
            Password
          </label>
          <div
            className={`input-group ${touched.password && !passwordValid ? "error" : passwordValid ? "valid" : ""}`}
          >
            <input
              id='login-password'
              type='password'
              autoComplete='current-password'
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onBlur={() => setTouched((t) => ({ ...t, password: true }))}
              disabled={submitting}
            />
          </div>
          {touched.password && !passwordValid && (
            <p className='field-error'>
              Password must be at least 8 characters
            </p>
          )}

          <button className='btn-scan' type='submit' disabled={!canSubmit}>
            {submitting ? (
              <>
                <span className='spin'>⟳</span> Signing in…
              </>
            ) : (
              <>Sign In</>
            )}
          </button>
        </form>

        <p className='auth-switch'>
          Don&apos;t have an account?{" "}
          <button type='button' className='auth-link' onClick={onGoRegister}>
            Create one
          </button>
        </p>
      </div>
    </div>
  );
}

export default LoginPage;
