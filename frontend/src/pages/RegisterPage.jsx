import { useCallback, useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Loader2, Eye, EyeOff } from "lucide-react";
import { useAuth } from "../context/AuthContext.jsx";
import { getAuthConfig, previewInvite } from "../services/auth.js";
import AuthBrand from "../components/AuthBrand.jsx";
import ThemeToggle from "../components/ThemeToggle.jsx";
import Tooltip from "../components/Tooltip.jsx";
import ErrorNotice from "../components/ErrorNotice.jsx";
import PageTransitionLink from "../components/PageTransitionLink.jsx";
import TurnstileWidget from "../components/TurnstileWidget.jsx";
import { AnimatedWords } from "../components/motion/primitives.jsx";
import useDelayedTurnstileConfig from "../hooks/useDelayedTurnstileConfig.js";

const Link = PageTransitionLink;

function RegisterPage() {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const inviteToken = params.get("invite") || params.get("token") || "";
  const [invite, setInvite] = useState(null);
  const [inviteState, setInviteState] = useState(inviteToken ? "loading" : "missing");
  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [touched, setTouched] = useState({});
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [turnstileToken, setTurnstileToken] = useState("");
  const [captchaReset, setCaptchaReset] = useState(0);
  const { siteKey: turnstileSiteKey, configError } =
    useDelayedTurnstileConfig(getAuthConfig);

  useEffect(() => {
    if (!inviteToken) return;
    const controller = new AbortController();
    previewInvite(inviteToken, controller.signal)
      .then((data) => {
        setInvite(data);
        // Prefill from the backend invite: email is pinned (rendered read-only
        // below; the server re-checks it on register regardless), name is a
        // starting value the invitee can edit.
        setEmail(data.email || "");
        setFullName(data.full_name || "");
        setInviteState("valid");
      })
      .catch((err) => {
        if (err.name !== "AbortError") { setError(err); setInviteState("invalid"); }
      });
    return () => controller.abort();
  }, [inviteToken]);

  const emailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  const nameValid = fullName.trim().length >= 2;
  const passwordValid = password.length >= 8;
  const confirmValid = confirmPassword.length > 0 && confirmPassword === password;
  const canSubmit =
    inviteState === "valid" &&
    emailValid &&
    nameValid &&
    passwordValid &&
    confirmValid &&
    Boolean(turnstileToken) &&
    !submitting;
  const ownsWorkspace = invite?.owns_workspace === true;

  const handleCaptchaError = useCallback((message) => setError(message), []);

  async function handleSubmit(event) {
    event.preventDefault();
    setTouched({ email: true, fullName: true, password: true, confirmPassword: true });
    if (!canSubmit) return;
    setSubmitting(true);
    try {
      await register({
        email,
        password,
        fullName,
        inviteToken,
        turnstileToken,
      });
      navigate("/home", { replace: true });
    } catch (err) {
      setError(err);
      setTurnstileToken("");
      setCaptchaReset((value) => value + 1);
    } finally { setSubmitting(false); }
  }

  const fields = [
    { key: "fullName", id: "reg-name", label: "Full name", type: "text", autoComplete: "name", value: fullName, set: setFullName, valid: nameValid, error: "Enter your full name" },
    { key: "password", id: "reg-password", label: "Password", type: "password", autoComplete: "new-password", value: password, set: setPassword, valid: passwordValid, error: "Password must be at least 8 characters" },
    { key: "confirmPassword", id: "reg-confirm-password", label: "Confirm password", type: "password", autoComplete: "new-password", value: confirmPassword, set: setConfirmPassword, valid: confirmValid, error: "Passwords do not match" },
  ];

  return (
    <div className='auth-shell'>
      <div className='auth-left'>
        <div className='auth-header'><Link to='/' className='brand' viewTransition><img src='/sentrystrike-logo.svg' alt='' className='mark-img' />SentryStrike</Link><ThemeToggle /></div>
        <div className='auth-box'>
          <AnimatedWords
            text={ownsWorkspace ? "Set up your workspace" : "Join your workspace"}
            delay={0.16}
          />
          <p>{invite ? (ownsWorkspace ? <>Your request for <b>{invite.org_name}</b> was approved. Create your account to set up the workspace.</> : <>You were invited to join <b>{invite.org_name}</b> as <b>{invite.role}</b>. Create your account to continue.</>) : "Open the invitation link sent to your email."}</p>
          {inviteState === "loading" && <div className='empty-state'><Loader2 className='ico spin' /> Checking invitation…</div>}
          {inviteState === "missing" && <ErrorNotice error='Registration requires a valid invitation link. Ask a workspace owner or admin to send you one.' compact />}
          {inviteState === "invalid" && <ErrorNotice error={error} fallback='This invitation is invalid or has expired.' compact />}
          {inviteState === "valid" && (
            <form onSubmit={handleSubmit} noValidate style={{ marginTop: 26 }}>
              <div className='field'>
                <label htmlFor='reg-email'>Work email</label>
                <div className='control'>
                  <input id='reg-email' type='email' autoComplete='email' value={email} readOnly aria-readonly='true' tabIndex={-1} title='This is the address your invitation was sent to and cannot be changed here.' />
                </div>
              </div>
              {fields.map((f) => {
                const passwordField = f.type === "password";
                return <div key={f.key} className='field'>
                  <label htmlFor={f.id}>{f.label}</label>
                  <div className={`control${touched[f.key] && !f.valid ? " error" : ""}`}>
                    <input id={f.id} type={passwordField && showPassword ? "text" : f.type} autoComplete={f.autoComplete} value={f.value} onChange={(e) => { f.set(e.target.value); setError(""); }} onBlur={() => setTouched((v) => ({ ...v, [f.key]: true }))} disabled={submitting} />
                    {passwordField && <Tooltip label={showPassword ? "Hide password" : "Show password"}><button type='button' className='pw-toggle' onClick={() => setShowPassword((v) => !v)} aria-label={showPassword ? "Hide password" : "Show password"}>{showPassword ? <EyeOff className='ico' /> : <Eye className='ico' />}</button></Tooltip>}
                  </div>
                  {touched[f.key] && !f.valid && <span className='field-error'>{f.error}</span>}
                </div>;
              })}
              <TurnstileWidget
                siteKey={turnstileSiteKey}
                action='register'
                onTokenChange={setTurnstileToken}
                onError={handleCaptchaError}
                resetKey={captchaReset}
              />
              <ErrorNotice error={error || configError} fallback='Unable to create your account.' compact />
              <button className='btn primary' type='submit' disabled={!canSubmit}>{submitting && <Loader2 className='ico spin' />}{ownsWorkspace ? "Create account and workspace" : "Create account and join"}</button>
            </form>
          )}
          <div className='auth-switch'>Already have an account? <Link className='text-btn' to='/login' viewTransition>Sign in</Link></div>
        </div>
      </div>
      <AuthBrand mode='register' />
    </div>
  );
}

export default RegisterPage;
