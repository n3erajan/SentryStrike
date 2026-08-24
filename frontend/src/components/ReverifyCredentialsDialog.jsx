import { useEffect, useState } from "react";
import { X } from "lucide-react";
import Tooltip from "./Tooltip.jsx";
import { CRED_FIELDS } from "../data/constants.js";

// Access-control re-verification needs a second identity to prove the
// difference - the backend rejects the job otherwise (see
// utils/reverifyPolicy.js). This collects a second and/or admin test account,
// posted with the job and never persisted beyond the Redis payload.
const ROLES = [
  {
    key: "second",
    label: "Second user",
    desc: "A second standard user for horizontal access checks.",
  },
  {
    key: "admin",
    label: "Admin user",
    desc: "A privileged user for vertical access checks.",
  },
];

function accountPopulated(account = {}) {
  return Boolean(
    (account.username && account.password) || account.cookie || account.header,
  );
}

export default function ReverifyCredentialsDialog({
  open,
  reason,
  onConfirm,
  onCancel,
}) {
  const [credentials, setCredentials] = useState({});

  useEffect(() => {
    if (!open) return undefined;
    const handler = (e) => {
      if (e.key === "Escape") onCancel();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onCancel]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (open) setCredentials({});
  }, [open]);

  if (!open) return null;

  function setField(role, key, value) {
    setCredentials((prev) => {
      const account = { ...(prev[role] || {}) };
      if (value === "") delete account[key];
      else account[key] = value;
      const next = { ...prev };
      if (Object.keys(account).length) next[role] = account;
      else delete next[role];
      return next;
    });
  }

  const ready = ROLES.some(({ key }) => accountPopulated(credentials[key]));

  function submit(e) {
    e.preventDefault();
    if (!ready) return;
    onConfirm(credentials);
  }

  return (
    <div className='modal-backdrop' onMouseDown={onCancel}>
      <div
        className='modal-card modal-wide'
        onMouseDown={(e) => e.stopPropagation()}
      >
        <Tooltip label='Close'>
          <button className='modal-close' onClick={onCancel} type='button'>
            <X className='ico' />
          </button>
        </Tooltip>
        <h2>Re-verify with a second identity</h2>
        <p className='muted-text'>{reason}</p>
        <form onSubmit={submit}>
          {ROLES.map((role) => (
            <section key={role.key} className='reverify-cred-role'>
              <div className='reverify-cred-head'>
                <h3>{role.label}</h3>
                <p className='muted-text'>{role.desc}</p>
              </div>
              <div className='grid2'>
                {CRED_FIELDS.map((f) => (
                  <div key={f.key} className='field'>
                    <label htmlFor={`reverify-${role.key}-${f.key}`}>
                      {f.label}
                    </label>
                    <div className='control'>
                      <input
                        id={`reverify-${role.key}-${f.key}`}
                        type={f.type}
                        autoComplete='off'
                        maxLength={f.maxLength}
                        placeholder={f.placeholder}
                        value={credentials[role.key]?.[f.key] ?? ""}
                        onChange={(e) =>
                          setField(role.key, f.key, e.target.value)
                        }
                      />
                    </div>
                  </div>
                ))}
              </div>
            </section>
          ))}
          <p className='field-description'>
            Add at least one dedicated test account. Do not use personal or
            production credentials.
          </p>
          <button className='btn primary' type='submit' disabled={!ready}>
            Queue re-verification
          </button>
          <button className='btn' type='button' onClick={onCancel}>
            Cancel
          </button>
        </form>
      </div>
    </div>
  );
}
