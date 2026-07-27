import { useCallback, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { CheckCircle2, Loader2, Eye, EyeOff } from "lucide-react";
import { useAuth } from "../context/AuthContext.jsx";
import AuthBrand from "../components/AuthBrand.jsx";
import ThemeToggle from "../components/ThemeToggle.jsx";
import Tooltip from "../components/Tooltip.jsx";
import ErrorNotice from "../components/ErrorNotice.jsx";
import PageTransitionLink from "../components/PageTransitionLink.jsx";
import TurnstileWidget from "../components/TurnstileWidget.jsx";
import { AnimatedWords } from "../components/motion/primitives.jsx";
import useDelayedTurnstileConfig from "../hooks/useDelayedTurnstileConfig.js";
import { getAuthConfig } from "../services/auth.js";

const Link = PageTransitionLink;

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
  const [turnstileToken, setTurnstileToken] = useState("");
  const [captchaReset, setCaptchaReset] = useState(0);
  const { siteKey: turnstileSiteKey, configError } =
    useDelayedTurnstileConfig(getAuthConfig);
  const emailValid = EMAIL_RE.test(email);
  const passwordValid = password.length >= 8;
  const canSubmit =
    emailValid && passwordValid && Boolean(turnstileToken) && !submitting;

  const handleCaptchaError = useCallback((message) => setError(message), []);

  async function handleSubmit(event) {
    event.preventDefault();
    setTouched({ email: true, password: true });
    if (!canSubmit) return;
    setSubmitting(true);
    try {
      await login({ email, password, turnstileToken });
      navigate(dest, { replace: true });
    } catch (err) {
      setError(err);
      setTurnstileToken("");
      setCaptchaReset((value) => value + 1);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className='auth-shell'>
      <div className='auth-left'>
        <div className='auth-header'>
          <Link to='/' className='brand' viewTransition>
            <img className='mark-img' src='/sentrystrike-logo.svg' alt='SentryStrike' />
            SentryStrike
          </Link>
          <ThemeToggle />
        </div>
        <div className='auth-box'>
          <AnimatedWords text='Welcome back' delay={0.16} />
          <p>Sign in to continue your web security work.</p>
          <form onSubmit={handleSubmit} noValidate style={{ marginTop: 26 }}>
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
                  onChange={(e) => { setEmail(e.target.value); setError(""); }}
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
                  onChange={(e) => { setPassword(e.target.value); setError(""); }}
                  onBlur={() => setTouched((v) => ({ ...v, password: true }))}
                  disabled={submitting}
                />
                <Tooltip label={showPassword ? "Hide password" : "Show password"}>
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
                </Tooltip>
              </div>
              {touched.password && !passwordValid && (
                <span className='field-error'>
                  Password must be at least 8 characters
                </span>
              )}
            </div>
            <TurnstileWidget
              siteKey={turnstileSiteKey}
              action='login'
              onTokenChange={setTurnstileToken}
              onError={handleCaptchaError}
              resetKey={captchaReset}
            />
            <ErrorNotice error={error || configError} fallback='Unable to sign in. Please try again.' compact />
            <button className='btn primary' type='submit' disabled={!canSubmit}>
              {submitting && (
                <Loader2
                  className='ico'
                  style={{ animation: "spin 1s linear infinite" }}
                />
              )}
              Sign in
            </button>
          </form>
          <div className='auth-switch'>
            Need a workspace?{" "}
            <Link className='text-btn' to='/request-access' viewTransition>
              Request access
            </Link>
          </div>
        </div>
      </div>
      <AuthBrand mode='login' />
    </div>
  );
}

export default LoginPage;
