import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ShieldCheck, CheckCircle2, Loader2, Eye, EyeOff } from "lucide-react";
import { useAuth } from "../context/AuthContext.jsx";
import AuthBrand from "../components/AuthBrand.jsx";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function RegisterPage() {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [touched, setTouched] = useState({});
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const emailValid = EMAIL_RE.test(email);
  const passwordValid = password.length >= 8;
  const confirmValid = confirmPassword.length > 0 && confirmPassword === password;
  const canSubmit = emailValid && passwordValid && confirmValid && !submitting;

  async function handleSubmit(event) {
    event.preventDefault();
    setTouched({ email: true, password: true, confirmPassword: true });
    if (!canSubmit) return;
    setError("");
    setSubmitting(true);
    try {
      await register({ email, password });
      navigate("/home", { replace: true });
    } catch (err) {
      setError(err.message || "Unable to create Account. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  const fields = [
    {
      key: "email",
      id: "reg-email",
      label: "Work email",
      type: "email",
      autoComplete: "email",
      value: email,
      set: setEmail,
      valid: emailValid,
      error: "Enter a valid email address",
    },
    {
      key: "password",
      id: "reg-password",
      label: "Password",
      type: "password",
      autoComplete: "new-password",
      value: password,
      set: setPassword,
      valid: passwordValid,
      error: "Password must be at least 8 characters",
    },
    {
      key: "confirmPassword",
      id: "reg-confirm-password",
      label: "Confirm password",
      type: "password",
      autoComplete: "new-password",
      value: confirmPassword,
      set: setConfirmPassword,
      valid: confirmValid,
      error: "Passwords do not match",
    },
  ];

  const isPasswordField = (key) =>
    key === "password" || key === "confirmPassword";

  return (
    <div className='auth-shell'>
      <div className='auth-left'>
        <Link to='/' className='brand'>
          <span className='mark'>
            <ShieldCheck className='ico' />
          </span>
          SentryStrike
        </Link>
        <div className='auth-box'>
          <h1>Create your Account</h1>
          <p>Set up your company and run your first VAPT assessment.</p>
          <form onSubmit={handleSubmit} noValidate style={{ marginTop: 26 }}>
            {error && <div className='auth-error'>{error}</div>}
            {fields.map((f) => (
              <div key={f.key} className='field'>
                <label htmlFor={f.id}>{f.label}</label>
                <div
                  className={`control${touched[f.key] && !f.valid ? " error" : ""}`}
                >
                  <input
                    id={f.id}
                    type={
                      isPasswordField(f.key) && showPassword ? "text" : f.type
                    }
                    autoComplete={f.autoComplete}
                    value={f.value}
                    onChange={(e) => f.set(e.target.value)}
                    onBlur={() => setTouched((v) => ({ ...v, [f.key]: true }))}
                    disabled={submitting}
                  />
                  {isPasswordField(f.key) ? (
                    <button
                      type='button'
                      className='pw-toggle'
                      onClick={() => setShowPassword((v) => !v)}
                      aria-label={
                        showPassword ? "Hide password" : "Show password"
                      }
                      aria-pressed={showPassword}
                      tabIndex={-1}
                    >
                      {showPassword ? (
                        <EyeOff className='ico' />
                      ) : (
                        <Eye className='ico' />
                      )}
                    </button>
                  ) : (
                    f.valid && (
                      <CheckCircle2
                        className='ico'
                        style={{ color: "var(--good)" }}
                      />
                    )
                  )}
                </div>
                {touched[f.key] && !f.valid && (
                  <span className='field-error'>{f.error}</span>
                )}
              </div>
            ))}
            <button className='btn primary' type='submit' disabled={!canSubmit}>
              {submitting ? (
                <>
                  <Loader2
                    className='ico'
                    style={{ animation: "spin 1s linear infinite" }}
                  />
                  Creating Account
                </>
              ) : (
                "Create Account"
              )}
            </button>
          </form>
          <div className='auth-switch'>
            Already registered?{" "}
            <Link className='text-btn' to='/login'>
              Sign in
            </Link>
          </div>
        </div>
      </div>
      <AuthBrand mode='register' />
    </div>
  );
}

export default RegisterPage;
