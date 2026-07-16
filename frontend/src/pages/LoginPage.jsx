import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { CheckCircle, CircleNotch, ShieldCheck, WarningCircle } from "@phosphor-icons/react";
import { useAuth } from "../context/AuthContext.jsx";
import AuthBrand from "../components/AuthBrand.jsx";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const control = "mt-1.5 flex min-h-[43px] items-center gap-2 rounded-[7px] border bg-[#fafcfe] px-2.5 transition focus-within:border-[#006de2] focus-within:ring-3 focus-within:ring-[#d4eaff]";
const input = "w-full min-w-0 border-0 bg-transparent p-0 text-[13px] text-[#0a1421] outline-none placeholder:text-[#a1aabb] disabled:cursor-not-allowed";

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
    <div className='grid min-h-dvh bg-[#fafcfe] font-sans text-[#0a1421] lg:grid-cols-[minmax(360px,.75fr)_minmax(520px,1.25fr)]'>
      <main className='flex min-h-dvh flex-col px-[clamp(22px,5vw,70px)] py-[25px]'>
        <Link to='/' className='flex w-fit items-center gap-2.5 text-[17px] font-bold text-[#0a1421] no-underline'>
          <span className='grid h-[34px] w-[30px] place-items-center rounded-[48%_48%_40%_40%] bg-[#006de2] text-white'><ShieldCheck size={18} weight='bold' /></span>SentryStrike
        </Link>
        <div className='my-auto w-full max-w-[390px] py-10'>
          <h1 className='text-[34px] font-bold leading-[1.06] tracking-[-.035em]'>Welcome back</h1>
          <p className='mt-1.5 text-[15px] text-[#415166]'>Sign in to manage scans and reports.</p>
          <form className='mt-[26px]' onSubmit={handleSubmit} noValidate>
            {error && <div className='mb-[17px] flex items-start gap-2 rounded-[7px] border border-[#efbbb7] bg-[#fff0ef] px-3 py-2.5 text-[12px] text-[#de3d34]'><WarningCircle className='mt-0.5 shrink-0' size={16} weight='fill' />{error}</div>}
            <label className='mt-[13px] grid gap-1.5 text-[11px] font-semibold text-[#415166]' htmlFor='login-email'>Work email
              <span className={`${control} ${touched.email && !emailValid ? "border-[#de3d34]" : "border-[#cbd5e3]"}`}><input className={input} id='login-email' type='email' autoComplete='email' value={email} onChange={(event) => setEmail(event.target.value)} onBlur={() => setTouched((value) => ({ ...value, email: true }))} disabled={submitting} />{emailValid && <CheckCircle className='shrink-0 text-[#1c8742]' size={17} weight='fill' />}</span>
              {touched.email && !emailValid && <span className='text-[10px] font-normal text-[#de3d34]'>Enter a valid email address</span>}
            </label>
            <label className='mt-[13px] grid gap-1.5 text-[11px] font-semibold text-[#415166]' htmlFor='login-password'>Password
              <span className={`${control} ${touched.password && !passwordValid ? "border-[#de3d34]" : "border-[#cbd5e3]"}`}><input className={input} id='login-password' type='password' autoComplete='current-password' value={password} onChange={(event) => setPassword(event.target.value)} onBlur={() => setTouched((value) => ({ ...value, password: true }))} disabled={submitting} /></span>
              {touched.password && !passwordValid && <span className='text-[10px] font-normal text-[#de3d34]'>Password must be at least 8 characters</span>}
            </label>
            <button className='mt-[19px] inline-flex min-h-[42px] w-full items-center justify-center gap-2 rounded-lg border border-[#006de2] bg-[#006de2] px-[15px] text-[13px] font-semibold text-white transition hover:-translate-y-px hover:bg-[#004bb7] active:translate-y-px disabled:cursor-not-allowed disabled:opacity-45 focus-visible:outline-3 focus-visible:outline-offset-2 focus-visible:outline-[#d4eaff]' type='submit' disabled={!canSubmit}>{submitting ? <><CircleNotch className='animate-spin' size={17} weight='bold' />Signing in</> : "Sign in"}</button>
          </form>
          <div className='mt-4 text-center text-[11px] text-[#6f7c8c]'>No account? <Link className='font-semibold text-[#006de2] no-underline hover:text-[#004bb7]' to='/register'>Create account</Link></div>
        </div>
      </main>
      <AuthBrand mode='login' />
    </div>
  );
}

export default LoginPage;
