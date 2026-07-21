import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ChevronDown } from "lucide-react";
import { useScanForm } from "../hooks/useScan.js";
import { useToast } from "../components/Toast.jsx";
import {
  CONFIG_GROUPS,
  CRED_FIELDS,
  CRED_ROLES,
  SCAN_MODES,
} from "../data/constants.js";

function coerce(field, raw) {
  if (raw === "") return "";
  if (field.type === "int") {
    const v = parseInt(raw, 10);
    return Number.isNaN(v) ? "" : v;
  }
  if (field.type === "float") {
    const v = parseFloat(raw);
    return Number.isNaN(v) ? "" : v;
  }
  return raw;
}

function ConfigField({ field, value, onChange, disabled }) {
  const id = `cfg-${field.key}`;
  const descriptionId = `${id}-description`;
  const commonProps = {
    id,
    "aria-describedby": descriptionId,
    value: value ?? "",
    onChange: (event) =>
      onChange(
        field.key,
        field.type === "select"
          ? event.target.value
          : coerce(field, event.target.value),
      ),
    disabled,
  };
  return (
    <div className='field'>
      <label htmlFor={id}>
        {field.label}
        {field.unit && (
          <span style={{ color: "var(--muted)", marginLeft: 4 }}>
            ({field.unit})
          </span>
        )}
      </label>
      <div className='control'>
        {field.type === "select" ? (
          <select {...commonProps}>
            <option value=''>Default</option>
            {field.options.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
        ) : (
          <input
            {...commonProps}
            type={field.type === "text" ? "text" : "number"}
            inputMode={field.type === "int" ? "numeric" : undefined}
            min={field.min}
            max={field.max}
            step={field.step ?? (field.type === "int" ? 1 : "any")}
            maxLength={field.maxLength}
            placeholder={field.placeholder || "Default"}
          />
        )}
      </div>
      <p className='field-description' id={descriptionId}>
        {field.description}
      </p>
    </div>
  );
}

function CredentialAccount({ role, account, onField, disabled }) {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const basic = CRED_FIELDS.filter((f) => !f.advanced);
  const advanced = CRED_FIELDS.filter((f) => f.advanced);

  return (
    <section style={{ borderTop: "1px solid var(--line)", padding: "15px 0" }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "baseline",
          gap: 10,
        }}
      >
        <h3 style={{ fontSize: "0.85rem" }}>{role.label}</h3>
        <p style={{ fontSize: "0.65rem", color: "var(--muted)" }}>
          {role.desc}
        </p>
      </div>
      <div className='grid2'>
        {basic.map((f) => (
          <div key={f.key} className='field'>
            <label htmlFor={`credential-${role.key}-${f.key}`}>{f.label}</label>
            <div className='control'>
              <input
                id={`credential-${role.key}-${f.key}`}
                type={f.type}
                autoComplete='off'
                maxLength={f.maxLength}
                value={account[f.key] ?? ""}
                onChange={(e) => onField(role.key, f.key, e.target.value)}
                disabled={disabled}
                aria-describedby={`credential-${role.key}-${f.key}-description`}
              />
            </div>
            <p
              className='field-description'
              id={`credential-${role.key}-${f.key}-description`}
            >
              {f.description}
            </p>
          </div>
        ))}
      </div>
      <button
        type='button'
        className='text-btn'
        style={{ marginTop: 10, fontSize: "0.7rem" }}
        onClick={() => setShowAdvanced((v) => !v)}
      >
        {showAdvanced
          ? "Hide login-flow overrides"
          : "Show login-flow overrides"}
      </button>
      {showAdvanced && (
        <div className='grid2'>
          {advanced.map((f) => (
            <div key={f.key} className='field'>
              <label htmlFor={`credential-${role.key}-${f.key}`}>
                {f.label}
              </label>
              <div className='control'>
                <input
                  id={`credential-${role.key}-${f.key}`}
                  type='text'
                  autoComplete='off'
                  maxLength={f.maxLength}
                  placeholder={f.placeholder || f.label}
                  value={account[f.key] ?? ""}
                  onChange={(e) => onField(role.key, f.key, e.target.value)}
                  disabled={disabled}
                  aria-describedby={`credential-${role.key}-${f.key}-description`}
                />
              </div>
              <p
                className='field-description'
                id={`credential-${role.key}-${f.key}-description`}
              >
                {f.description}
              </p>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function ScanPage() {
  const navigate = useNavigate();
  const toast = useToast();
  const [usersOpen, setUsersOpen] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const {
    url,
    setUrl,
    crawlMode,
    setCrawlMode,
    consent,
    setConsent,
    touched,
    setTouched,
    config,
    setConfigField,
    credentials,
    setCredentialField,
    submitting,
    error,
    valid,
    canStart,
    startScan,
  } = useScanForm();
  // Backend default is "verified"; reflect that as pre-selected in the UI.
  const scanMode = config.scan_mode || "verified";
  const primary = credentials.main || {};

  async function handleStart() {
    const result = await startScan();
    if (result) {
      toast("Assessment started");
      navigate(`/active/${result.scanId}`, {
        state: { target: result.target },
      });
    }
  }

  return (
    <div className='view'>
      <div className='head'>
        <div>
          <h1>New Scan</h1>
          <p>Configure an OWASP Top 10 2025 VAPT assessment.</p>
        </div>
      </div>

      {error && (
        <div className='auth-error' style={{ margin: "0 0 16px" }}>
          {error}
        </div>
      )}

      <div className='formlayout'>
        <main>
          <section className='formsection'>
            <h3>Application URL</h3>
            <div className='grid2'>
              <div className='field wide'>
                <div
                  className={`control${touched && url && !valid ? " error" : ""}`}
                >
                  <input
                    id='target-url'
                    type='url'
                    placeholder='https://example.com'
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    onBlur={() => setTouched(true)}
                    disabled={submitting}
                    aria-describedby='target-url-description'
                  />
                </div>
                {touched && url && !valid && (
                  <span className='field-error'>
                    Enter a valid URL including http:// or https://
                  </span>
                )}
                <p className='field-description' id='target-url-description'>
                  Enter the public or staging URL where the assessment should
                  begin.
                </p>
              </div>
            </div>
          </section>

          <section className='formsection'>
            <h3 className='form-subhead'>Crawl scope</h3>
            <div
              className='mode-choice'
              style={{ gridTemplateColumns: "1fr 1fr" }}
            >
              <button
                type='button'
                className={crawlMode === "full" ? "active" : ""}
                onClick={() => setCrawlMode("full")}
                disabled={submitting}
              >
                <b>Full site</b>
                <small>Crawl every reachable page.</small>
              </button>
              <button
                type='button'
                className={crawlMode === "single" ? "active" : ""}
                onClick={() => setCrawlMode("single")}
                disabled={submitting}
              >
                <b>Single page</b>
                <small>Only the target URL.</small>
              </button>
            </div>

            <h3 className='form-subhead'>Verification mode</h3>
            <div className='mode-choice'>
              {SCAN_MODES.map(([value, title, desc]) => (
                <button
                  key={value}
                  type='button'
                  className={scanMode === value ? "active" : ""}
                  onClick={() =>
                    setConfigField("scan_mode", scanMode === value ? "" : value)
                  }
                  disabled={submitting}
                >
                  <b>{title}</b>
                  <small>{desc}</small>
                </button>
              ))}
            </div>
          </section>

          <button
            type='button'
            className={`advanced-toggle${usersOpen ? " open" : ""}`}
            onClick={() => setUsersOpen((value) => !value)}
            aria-expanded={usersOpen}
            aria-controls='test-users-panel'
          >
            Test users
            <span className='advanced-toggle-hint'>
              Optional accounts for authenticated and access-control testing
            </span>
            <ChevronDown className='ico chev' />
          </button>

          {usersOpen && (
            <div className='advanced-panel users-panel' id='test-users-panel'>
              <p className='panel-intro'>
                Add up to three dedicated test accounts to improve authenticated
                coverage. Do not use personal or production credentials.
              </p>
              {CRED_ROLES.map((role) => (
                <CredentialAccount
                  key={role.key}
                  role={role}
                  account={credentials[role.key] || {}}
                  onField={setCredentialField}
                  disabled={submitting}
                />
              ))}

              <label className='consent secondary-provisioning'>
                <input
                  type='checkbox'
                  checked={Boolean(config.allow_secondary_provisioning)}
                  onChange={(e) =>
                    setConfigField(
                      "allow_secondary_provisioning",
                      e.target.checked ? true : "",
                    )
                  }
                  disabled={submitting}
                />
                <span>
                  Auto-provision a throwaway second identity for horizontal IDOR
                  testing when none is supplied.
                </span>
              </label>
            </div>
          )}

          <button
            type='button'
            className={`advanced-toggle${advancedOpen ? " open" : ""}`}
            onClick={() => setAdvancedOpen((v) => !v)}
            aria-expanded={advancedOpen}
          >
            Advanced configuration
            <span className='advanced-toggle-hint'>
              Crawler, scanner, injection, and browser tuning
            </span>
            <ChevronDown className='ico chev' />
          </button>

          {advancedOpen && (
            <div className='advanced-panel'>
              {CONFIG_GROUPS.map((group) => (
                <div key={group.title}>
                  <h3>{group.title}</h3>
                  <p className='muted-text'>{group.blurb}</p>
                  <div className='grid2'>
                    {group.fields.map((field) => (
                      <ConfigField
                        key={field.key}
                        field={field}
                        value={config[field.key]}
                        onChange={setConfigField}
                        disabled={submitting}
                      />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}

          <label className='consent' style={{ marginTop: 20 }}>
            <input
              type='checkbox'
              checked={consent}
              onChange={(e) => setConsent(e.target.checked)}
              disabled={submitting}
            />
            <span>
              I confirm I am authorized to scan this target. Unauthorized
              scanning may be illegal.
            </span>
          </label>
        </main>

        <aside className='review'>
          <h2>Assessment summary</h2>
          <dl>
            <div>
              <dt>Standard</dt>
              <dd>OWASP 2025</dd>
            </div>
            <div>
              <dt>Scope</dt>
              <dd>{crawlMode === "single" ? "Single page" : "Full site"}</dd>
            </div>
            <div>
              <dt>Access</dt>
              <dd>
                {primary.username
                  ? credentials.second?.username
                    ? "2 users"
                    : "1 user"
                  : "Public"}
              </dd>
            </div>
            <div>
              <dt>Evidence</dt>
              <dd>
                {scanMode
                  ? scanMode.charAt(0).toUpperCase() + scanMode.slice(1)
                  : "Verified"}
              </dd>
            </div>
          </dl>
          <button
            className='btn primary'
            onClick={handleStart}
            disabled={!canStart}
          >
            {submitting ? "Starting…" : "Start assessment"}
          </button>
        </aside>
      </div>
    </div>
  );
}

export default ScanPage;
