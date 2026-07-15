import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { CheckCircle, CircleNotch, ShieldCheck, WarningCircle } from "@phosphor-icons/react";
import { useAuth } from "../context/AuthContext.jsx";
import AuthBrand from "../components/AuthBrand.jsx";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const dest = location.state?.from?.pathname || "/scan";
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
    <div className='auth-shell'>
      <div className='auth-left'>
        <Link to='/' className='brand auth-brand-link'><span className='mark'><ShieldCheck size={19} weight='bold' /></span>SentryStrike</Link>
        <div className='auth-box'>
          <h1>Welcome back</h1>
          <p>Sign in to manage assessments and reports.</p>
          <form onSubmit={handleSubmit} noValidate>
            {error && <div className='auth-error'><WarningCircle size={16} weight='fill' />{error}</div>}
            <div className='field'>
              <label htmlFor='login-email'>Work email</label>
              <div className={`control auth-control ${touched.email && !emailValid ? "error" : emailValid ? "valid" : ""}`}>
                <input id='login-email' type='email' autoComplete='email' value={email} onChange={(event) => setEmail(event.target.value)} onBlur={() => setTouched((value) => ({ ...value, email: true }))} disabled={submitting} />
                {emailValid && <CheckCircle size={17} weight='fill' />}
              </div>
              {touched.email && !emailValid && <p className='field-error'>Enter a valid email address</p>}
            </div>
            <div className='field'>
              <label htmlFor='login-password'>Password</label>
              <div className={`control auth-control ${touched.password && !passwordValid ? "error" : passwordValid ? "valid" : ""}`}>
                <input id='login-password' type='password' autoComplete='current-password' value={password} onChange={(event) => setPassword(event.target.value)} onBlur={() => setTouched((value) => ({ ...value, password: true }))} disabled={submitting} />
              </div>
              {touched.password && !passwordValid && <p className='field-error'>Password must be at least 8 characters</p>}
            </div>
            <button className='btn primary auth-submit' type='submit' disabled={!canSubmit}>
              {submitting ? <><CircleNotch className='spin' size={17} weight='bold' />Signing in</> : "Sign in"}
            </button>
          </form>
          <div className='auth-switch'>No account? <Link className='text-btn' to='/register'>Create account</Link></div>
        </div>
      </div>
      <AuthBrand mode='login' />
    </div>
  );
}

export default LoginPage;
