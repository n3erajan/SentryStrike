import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { CheckCircle2, Loader2, Eye, EyeOff } from "lucide-react";
import { useAuth } from "../context/AuthContext.jsx";
import { previewInvite } from "../services/auth.js";
import AuthBrand from "../components/AuthBrand.jsx";
import ThemeToggle from "../components/ThemeToggle.jsx";

function RegisterPage() {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const inviteToken = params.get("invite") || params.get("token") || "";
  const [invite, setInvite] = useState(null);
  const [inviteState, setInviteState] = useState(inviteToken ? "loading" : "missing");
  const [fullName, setFullName] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [touched, setTouched] = useState({});
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  useEffect(() => {
    if (!inviteToken) return;
    const controller = new AbortController();
    previewInvite(inviteToken, controller.signal)
      .then((data) => { setInvite(data); setInviteState("valid"); })
      .catch((err) => {
        if (err.name !== "AbortError") { setError(err.message || "This invite is invalid."); setInviteState("invalid"); }
      });
    return () => controller.abort();
  }, [inviteToken]);

  const nameValid = fullName.trim().length >= 2;
  const passwordValid = password.length >= 8;
  const confirmValid = confirmPassword.length > 0 && confirmPassword === password;
  const canSubmit = inviteState === "valid" && nameValid && passwordValid && confirmValid && !submitting;

  async function handleSubmit(event) {
    event.preventDefault();
    setTouched({ fullName: true, password: true, confirmPassword: true });
    if (!canSubmit) return;
    setError(""); setSubmitting(true);
    try {
      await register({ email: invite.email, password, fullName, inviteToken });
      navigate("/home", { replace: true });
    } catch (err) {
      setError(err.message || "Unable to create your account.");
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
        <div className='auth-header'><Link to='/' className='brand'><img src='/shield.png' alt='' className='mark-img' />SentryStrike</Link><ThemeToggle /></div>
        <div className='auth-box'>
          <h1>Join your workspace</h1>
          <p>{invite ? <>You were invited to <b>{invite.org_name}</b> as <b>{invite.role}</b>.</> : "Use the invitation link sent by your workspace administrator."}</p>
          {inviteState === "loading" && <div className='empty-state'><Loader2 className='ico spin' /> Validating invitation…</div>}
          {inviteState === "missing" && <div className='auth-error'>Registration is invite-only. Ask a workspace owner or admin for an invitation.</div>}
          {error && <div className='auth-error'>{error}</div>}
          {inviteState === "valid" && (
            <form onSubmit={handleSubmit} noValidate style={{ marginTop: 26 }}>
              <div className='field'><label>Work email</label><div className='control'><input value={invite.email} readOnly /><CheckCircle2 className='ico' style={{ color: "var(--good)" }} /></div></div>
              {fields.map((f) => {
                const passwordField = f.type === "password";
                return <div key={f.key} className='field'>
                  <label htmlFor={f.id}>{f.label}</label>
                  <div className={`control${touched[f.key] && !f.valid ? " error" : ""}`}>
                    <input id={f.id} type={passwordField && showPassword ? "text" : f.type} autoComplete={f.autoComplete} value={f.value} onChange={(e) => f.set(e.target.value)} onBlur={() => setTouched((v) => ({ ...v, [f.key]: true }))} disabled={submitting} />
                    {passwordField && <button type='button' className='pw-toggle' onClick={() => setShowPassword((v) => !v)} aria-label={showPassword ? "Hide password" : "Show password"}>{showPassword ? <EyeOff className='ico' /> : <Eye className='ico' />}</button>}
                  </div>
                  {touched[f.key] && !f.valid && <span className='field-error'>{f.error}</span>}
                </div>;
              })}
              <button className='btn primary' type='submit' disabled={!canSubmit}>{submitting ? <><Loader2 className='ico spin' />Creating account</> : "Accept invite and join"}</button>
            </form>
          )}
          <div className='auth-switch'>Already registered? <Link className='text-btn' to='/login'>Sign in</Link></div>
        </div>
      </div>
      <AuthBrand mode='register' />
    </div>
  );
}

export default RegisterPage;
