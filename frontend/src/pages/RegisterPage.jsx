import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { CheckCircle, CircleNotch, ShieldCheck, WarningCircle } from "@phosphor-icons/react";
import { useAuth } from "../context/AuthContext.jsx";
import AuthBrand from "../components/AuthBrand.jsx";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function RegisterPage() {
  const { register } = useAuth();
  const navigate = useNavigate();
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
      await register({ email, password });
      navigate("/app/scan", { replace: true });
    } catch (err) {
      setError(err.message || "Unable to create account. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className='auth-shell'>
      <div className='auth-left'>
        <Link to='/' className='brand auth-brand-link'><span className='mark'><ShieldCheck size={19} weight='bold' /></span>SentryStrike</Link>
        <div className='auth-box'>
          <h1>Create your account</h1>
          <p>Set up SentryStrike and run your first assessment.</p>
          <form onSubmit={handleSubmit} noValidate>
            {error && <div className='auth-error'><WarningCircle size={16} weight='fill' />{error}</div>}
            <div className='field'>
              <label htmlFor='register-email'>Work email</label>
              <div className={`control auth-control ${touched.email && !emailValid ? "error" : emailValid ? "valid" : ""}`}>
                <input id='register-email' type='email' autoComplete='email' value={email} onChange={(event) => setEmail(event.target.value)} onBlur={() => setTouched((value) => ({ ...value, email: true }))} disabled={submitting} />
                {emailValid && <CheckCircle size={17} weight='fill' />}
              </div>
              {touched.email && !emailValid && <p className='field-error'>Enter a valid email address</p>}
            </div>
            <div className='field'>
              <label htmlFor='register-password'>Password</label>
              <div className={`control auth-control ${touched.password && !passwordValid ? "error" : passwordValid ? "valid" : ""}`}>
                <input id='register-password' type='password' autoComplete='new-password' value={password} onChange={(event) => setPassword(event.target.value)} onBlur={() => setTouched((value) => ({ ...value, password: true }))} disabled={submitting} />
              </div>
              {touched.password && !passwordValid && <p className='field-error'>Password must be at least 8 characters</p>}
            </div>
            <div className='field'>
              <label htmlFor='register-confirm'>Confirm password</label>
              <div className={`control auth-control ${touched.confirm && !confirmValid ? "error" : confirmValid ? "valid" : ""}`}>
                <input id='register-confirm' type='password' autoComplete='new-password' value={confirm} onChange={(event) => setConfirm(event.target.value)} onBlur={() => setTouched((value) => ({ ...value, confirm: true }))} disabled={submitting} />
                {confirmValid && <CheckCircle size={17} weight='fill' />}
              </div>
              {touched.confirm && !confirmValid && <p className='field-error'>Passwords do not match</p>}
            </div>
            <button className='btn primary auth-submit' type='submit' disabled={!canSubmit}>
              {submitting ? <><CircleNotch className='spin' size={17} weight='bold' />Creating account</> : "Create account"}
            </button>
          </form>
          <div className='auth-switch'>Already registered? <Link className='text-btn' to='/login'>Sign in</Link></div>
        </div>
      </div>
      <AuthBrand mode='register' />
    </div>
  );
}

export default RegisterPage;
