import { useState } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import {
  EnvelopeSimple,
  Lock,
  CheckCircle,
  WarningCircle,
  CircleNotch,
} from "@phosphor-icons/react";
import { useAuth } from "../context/AuthContext.jsx";
import AuthBrand from "../components/AuthBrand.jsx";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  // Return the user to wherever ProtectedRoute bounced them from, else the app.
  const dest = location.state?.from?.pathname || "/app/scan";

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
      await login({ email, password });
      navigate(dest, { replace: true });
    } catch (err) {
      setError(err.message || "Unable to sign in. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className='auth-split'>
      <AuthBrand />

      <div className='auth-form-panel'>
        <div className='auth-form-inner'>
          <div className='auth-head'>
            <h1 className='auth-title'>Welcome back</h1>
            <p className='auth-sub'>Sign in to continue to SentryStrike</p>
          </div>

          <form onSubmit={handleSubmit} noValidate>
            {error && (
              <div className='auth-error'>
                <WarningCircle size={16} weight='fill' /> {error}
              </div>
            )}

            <label className='form-label' htmlFor='login-email'>
              Email
            </label>
            <div
              className={`input-group ${touched.email && !emailValid ? "error" : emailValid ? "valid" : ""}`}
            >
              <EnvelopeSimple className='field-icon' size={17} />
              <input
                id='login-email'
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
              htmlFor='login-password'
              style={{ marginTop: 16 }}
            >
              Password
            </label>
            <div
              className={`input-group ${touched.password && !passwordValid ? "error" : passwordValid ? "valid" : ""}`}
            >
              <Lock className='field-icon' size={17} />
              <input
                id='login-password'
                type='password'
                autoComplete='current-password'
                value={password}
                placeholder='Password'
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

            <button className='btn-primary' type='submit' disabled={!canSubmit}>
              {submitting ? (
                <>
                  <CircleNotch className='spin' size={17} weight='bold' />{" "}
                  Signing in
                </>
              ) : (
                <>Sign In</>
              )}
            </button>
          </form>

          <p className='auth-switch'>
            Don&apos;t have an account?{" "}
            <Link className='auth-link' to='/register'>
              Create one
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}

export default LoginPage;
