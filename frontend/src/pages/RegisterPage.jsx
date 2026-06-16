import { useState } from "react";
import { register } from "../services/auth.js";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function RegisterPage({ onAuthed, onGoLogin }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [touched, setTouched] = useState({});
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const emailValid = EMAIL_RE.test(email);
  const passwordValid = password.length >= 8;
  const confirmValid = confirm.length > 0 && confirm === password;
  const canSubmit = emailValid && passwordValid && confirmValid && !submitting;

  async function handleSubmit(event) {
    event.preventDefault();
    setTouched({ email: true, password: true, confirm: true });
    if (!emailValid || !passwordValid || !confirmValid) return;
    setError("");
    setSubmitting(true);
    try {
      const user = await register({ email, password });
      onAuthed(user);
    } catch (err) {
      setError(err.message || "Unable to create account. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className='auth-page'>
      <div className='card card-elevated auth-card'>
        <div className='auth-head'>
          <div className='auth-icon'>
            <img src='/shield.png' alt='SentryStrike' className='auth-icon-img' />
          </div>
          <h1 className='auth-title'>Create your account</h1>
          <p className='auth-sub'></p>
        </div>

        <form onSubmit={handleSubmit} noValidate>
          {error && <div className='auth-error'>{error}</div>}

          <label className='form-label' htmlFor='register-email'>
            Email
          </label>
          <div
            className={`input-group ${touched.email && !emailValid ? "error" : emailValid ? "valid" : ""}`}
          >
            <input
              id='register-email'
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
            htmlFor='register-password'
            style={{ marginTop: 16 }}
          >
            Password
          </label>
          <div
            className={`input-group ${touched.password && !passwordValid ? "error" : passwordValid ? "valid" : ""}`}
          >
            <input
              id='register-password'
              type='password'
              autoComplete='new-password'
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

          <label
            className='form-label'
            htmlFor='register-confirm'
            style={{ marginTop: 16 }}
          >
            Confirm password
          </label>
          <div
            className={`input-group ${touched.confirm && !confirmValid ? "error" : confirmValid ? "valid" : ""}`}
          >
            <input
              id='register-confirm'
              type='password'
              autoComplete='new-password'
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              onBlur={() => setTouched((t) => ({ ...t, confirm: true }))}
              disabled={submitting}
            />
          </div>
          {touched.confirm && !confirmValid && (
            <p className='field-error'>Passwords do not match</p>
          )}

          <button className='btn-scan' type='submit' disabled={!canSubmit}>
            {submitting ? (
              <>
                <span className='spin'>⟳</span> Creating account…
              </>
            ) : (
              <>Create Account</>
            )}
          </button>
        </form>

        <p className='auth-switch'>
          Already have an account?{" "}
          <button type='button' className='auth-link' onClick={onGoLogin}>
            Sign in
          </button>
        </p>
      </div>
    </div>
  );
}

export default RegisterPage;
