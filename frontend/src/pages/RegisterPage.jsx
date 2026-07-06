import { useState } from "react";
import {
  EnvelopeSimple,
  Lock,
  CheckCircle,
  WarningCircle,
  CircleNotch,
} from "@phosphor-icons/react";
import { register } from "../services/auth.js";
import AuthBrand from "../components/AuthBrand.jsx";

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
    <div className='auth-split'>
      {/* Inverted: form on the left, brand on the right */}
      <div className='auth-form-panel'>
        <div className='auth-form-inner'>
          <div className='auth-head'>
            <h1 className='auth-title'>Create your account</h1>
            <p className='auth-sub'>Start scanning targets in minutes</p>
          </div>

          <form onSubmit={handleSubmit} noValidate>
            {error && (
              <div className='auth-error'>
                <WarningCircle size={16} weight='fill' /> {error}
              </div>
            )}

            <label className='form-label' htmlFor='register-email'>
              Email
            </label>
            <div
              className={`input-group ${touched.email && !emailValid ? "error" : emailValid ? "valid" : ""}`}
            >
              <EnvelopeSimple className='field-icon' size={17} />
              <input
                id='register-email'
                type='email'
                autoComplete='email'
                placeholder='Email'
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                onBlur={() => setTouched((t) => ({ ...t, email: true }))}
                disabled={submitting}
              />
              {emailValid && (
                <CheckCircle className='input-ok' size={17} weight='fill' />
              )}
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
              <Lock className='field-icon' size={17} />
              <input
                id='register-password'
                type='password'
                autoComplete='new-password'
                placeholder='Password'
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
              <Lock className='field-icon' size={17} />
              <input
                id='register-confirm'
                type='password'
                autoComplete='new-password'
                placeholder='Confirm Password'
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                onBlur={() => setTouched((t) => ({ ...t, confirm: true }))}
                disabled={submitting}
              />
              {confirmValid && (
                <CheckCircle className='input-ok' size={17} weight='fill' />
              )}
            </div>
            {touched.confirm && !confirmValid && (
              <p className='field-error'>Passwords do not match</p>
            )}

            <button className='btn-primary' type='submit' disabled={!canSubmit}>
              {submitting ? (
                <>
                  <CircleNotch className='spin' size={17} weight='bold' />{" "}
                  Creating account
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

      <AuthBrand />
    </div>
  );
}

export default RegisterPage;
