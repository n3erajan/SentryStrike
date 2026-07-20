import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { CheckCircle2, Loader2, Eye, EyeOff } from "lucide-react";
import { useAuth } from "../context/AuthContext.jsx";
import AuthBrand from "../components/AuthBrand.jsx";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const dest = location.state?.from?.pathname || "/home";
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [touched, setTouched] = useState({});
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
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
    <div className='auth-shell'>
      <div className='auth-left'>
        <Link to='/' className='brand'>
          <img className='mark-img' src='/shield.png' alt='SentryStrike' />
          SentryStrike
        </Link>
        <div className='auth-box'>
          <h1>Welcome back</h1>
          <p>Sign in to SentryStrike.</p>
          <form onSubmit={handleSubmit} noValidate style={{ marginTop: 26 }}>
            {error && <div className='auth-error'>{error}</div>}
            <div className='field'>
              <label htmlFor='login-email'>Email</label>
              <div
                className={`control${touched.email && !emailValid ? " error" : ""}`}
              >
                <input
                  id='login-email'
                  type='email'
                  autoComplete='email'
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  onBlur={() => setTouched((v) => ({ ...v, email: true }))}
                  disabled={submitting}
                />
                {emailValid && (
                  <CheckCircle2
                    className='ico'
                    style={{ color: "var(--good)" }}
                  />
                )}
              </div>
              {touched.email && !emailValid && (
                <span className='field-error'>Enter a valid email address</span>
              )}
            </div>
            <div className='field'>
              <label htmlFor='login-password'>Password</label>
              <div
                className={`control${touched.password && !passwordValid ? " error" : ""}`}
              >
                <input
                  id='login-password'
                  type={showPassword ? "text" : "password"}
                  autoComplete='current-password'
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onBlur={() => setTouched((v) => ({ ...v, password: true }))}
                  disabled={submitting}
                />
                <button
                  type='button'
                  className='pw-toggle'
                  onClick={() => setShowPassword((v) => !v)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  aria-pressed={showPassword}
                  tabIndex={-1}
                >
                  {showPassword ? (
                    <EyeOff className='ico' />
                  ) : (
                    <Eye className='ico' />
                  )}
                </button>
              </div>
              {touched.password && !passwordValid && (
                <span className='field-error'>
                  Password must be at least 8 characters
                </span>
              )}
            </div>
            <button className='btn primary' type='submit' disabled={!canSubmit}>
              {submitting ? (
                <>
                  <Loader2
                    className='ico'
                    style={{ animation: "spin 1s linear infinite" }}
                  />
                  Signing in
                </>
              ) : (
                "Sign in"
              )}
            </button>
          </form>
          <div className='auth-switch'>
            No account?{" "}
            <Link className='text-btn' to='/register'>
              Create Account
            </Link>
          </div>
        </div>
      </div>
      <AuthBrand mode='login' />
    </div>
  );
}

export default LoginPage;
