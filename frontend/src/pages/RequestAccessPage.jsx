import { useCallback, useState } from "react";
import { CheckCircle2, Loader2 } from "lucide-react";
import AuthBrand from "../components/AuthBrand.jsx";
import ErrorNotice from "../components/ErrorNotice.jsx";
import ThemeToggle from "../components/ThemeToggle.jsx";
import TurnstileWidget from "../components/TurnstileWidget.jsx";
import PageTransitionLink from "../components/PageTransitionLink.jsx";
import { AnimatedWords } from "../components/motion/primitives.jsx";
import useDelayedTurnstileConfig from "../hooks/useDelayedTurnstileConfig.js";
import {
  getAccessRequestConfig,
  submitAccessRequest,
} from "../services/accessRequests.js";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const Link = PageTransitionLink;

export default function RequestAccessPage() {
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [website, setWebsite] = useState("");
  const [turnstileToken, setTurnstileToken] = useState("");
  const [captchaReset, setCaptchaReset] = useState(0);
  const [touched, setTouched] = useState({});
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);

  const { siteKey: turnstileSiteKey, configError } =
    useDelayedTurnstileConfig(getAccessRequestConfig);

  const nameValid = fullName.trim().length >= 2;
  const emailValid = EMAIL_RE.test(email);
  const organizationValid = organizationName.trim().length >= 2;
  const canSubmit =
    nameValid &&
    emailValid &&
    organizationValid &&
    Boolean(turnstileToken) &&
    !submitting;

  const handleCaptchaError = useCallback((message) => setError(message), []);

  async function handleSubmit(event) {
    event.preventDefault();
    setTouched({ fullName: true, email: true, organizationName: true });
    if (!canSubmit) return;

    setSubmitting(true);
    setError("");
    try {
      await submitAccessRequest({
        full_name: fullName,
        email,
        organization_name: organizationName,
        turnstile_token: turnstileToken,
        website,
      });
      setSubmitted(true);
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
            <img src='/sentrystrike-logo.svg' alt='' className='mark-img' />
            SentryStrike
          </Link>
          <ThemeToggle />
        </div>
        <div className='auth-box'>
          {submitted ? (
            <div className='access-request-success'>
              <CheckCircle2 aria-hidden='true' />
              <AnimatedWords text='Request submitted' delay={0.08} />
              <p>
                If your request is approved, we will send a one-time link to <b>{email}</b> to create your workspace and owner account.
              </p>
              <Link className='btn primary' to='/' viewTransition>Return home</Link>
            </div>
          ) : (
            <>
              <AnimatedWords text='Request a workspace' delay={0.16} />
              <p>Tell us about your organization. If approved, we will email you a one-time link to create the workspace and owner account.</p>
              <form onSubmit={handleSubmit} noValidate style={{ marginTop: 26 }}>
                <div className='access-request-honeypot' aria-hidden='true'>
                  <label htmlFor='request-website'>Website</label>
                  <input
                    id='request-website'
                    name='website'
                    tabIndex={-1}
                    autoComplete='off'
                    value={website}
                    onChange={(event) => setWebsite(event.target.value)}
                  />
                </div>
                <div className='field'>
                  <label htmlFor='request-name'>Full name</label>
                  <div className={`control${touched.fullName && !nameValid ? " error" : ""}`}>
                    <input
                      id='request-name'
                      autoComplete='name'
                      value={fullName}
                      onChange={(event) => { setFullName(event.target.value); setError(""); }}
                      onBlur={() => setTouched((value) => ({ ...value, fullName: true }))}
                      disabled={submitting}
                    />
                  </div>
                  {touched.fullName && !nameValid && <span className='field-error'>Enter your full name</span>}
                </div>
                <div className='field'>
                  <label htmlFor='request-email'>Email address</label>
                  <div className={`control${touched.email && !emailValid ? " error" : ""}`}>
                    <input
                      id='request-email'
                      type='email'
                      autoComplete='email'
                      value={email}
                      onChange={(event) => { setEmail(event.target.value); setError(""); }}
                      onBlur={() => setTouched((value) => ({ ...value, email: true }))}
                      disabled={submitting}
                    />
                  </div>
                  {touched.email && !emailValid && <span className='field-error'>Enter a valid email address</span>}
                </div>
                <div className='field'>
                  <label htmlFor='request-organization'>Organization name</label>
                  <div className={`control${touched.organizationName && !organizationValid ? " error" : ""}`}>
                    <input
                      id='request-organization'
                      autoComplete='organization'
                      value={organizationName}
                      onChange={(event) => { setOrganizationName(event.target.value); setError(""); }}
                      onBlur={() => setTouched((value) => ({ ...value, organizationName: true }))}
                      disabled={submitting}
                    />
                  </div>
                  {touched.organizationName && !organizationValid && <span className='field-error'>Enter your organization name</span>}
                </div>
                <TurnstileWidget
                  siteKey={turnstileSiteKey}
                  onTokenChange={setTurnstileToken}
                  onError={handleCaptchaError}
                  resetKey={captchaReset}
                />
                <ErrorNotice error={error || configError} fallback='Unable to submit your request.' compact />
                <button className='btn primary' type='submit' disabled={!canSubmit}>
                  {submitting && <Loader2 className='ico spin' />}
                  Request workspace
                </button>
              </form>
              <div className='auth-switch'>Already have an account? <Link className='text-btn' to='/login' viewTransition>Sign in</Link></div>
            </>
          )}
        </div>
      </div>
      <AuthBrand mode='request' />
    </div>
  );
}
