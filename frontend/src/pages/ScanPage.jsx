import {
  Globe,
  CheckCircle,
  WarningCircle,
  CircleNotch,
  TreeStructure,
  File as FileIcon,
  Check,
  ShieldCheck,
  SealCheck,
  FileArrowDown,
  CaretDown,
  Sliders,
  User,
  Lock,
} from "@phosphor-icons/react";
import { useState } from "react";
import { useScan } from "../hooks/useScan.js";
import {
  SCAN_STAGES,
  SCAN_MODES,
  CONFIG_GROUPS,
  CRED_ROLES,
  CRED_FIELDS,
} from "../data/constants.js";

const STATUS_LABEL = {
  queued: "Queued",
  running: "Scanning",
  completed: "Complete",
  failed: "Failed",
  cancelled: "Cancelled",
};

const NOTES = [
  {
    icon: ShieldCheck,
    title: "OWASP Top 10 detectors",
    desc: "Injection, XSS, access control, SSRF, misconfiguration and more. A06, A08 and A09 are out of automated scope.",
  },
  {
    icon: SealCheck,
    title: "Evidence-based",
    desc: "Findings are verified against real request and response evidence to cut down false positives.",
  },
  {
    icon: FileArrowDown,
    title: "Export ready",
    desc: "Hand results to your team as a formatted PDF or raw JSON.",
  },
];

// Coerce an <input> value to the type the backend field expects. Empty string
// clears the field (falls back to the backend default); NaN is treated as
// empty so half-typed numbers don't get submitted.
function coerce(field, raw) {
  if (raw === "") return "";
  if (field.type === "int") {
    const n = parseInt(raw, 10);
    return Number.isNaN(n) ? "" : n;
  }
  if (field.type === "float") {
    const n = parseFloat(raw);
    return Number.isNaN(n) ? "" : n;
  }
  return raw;
}

// A single ScanConfig override input, rendered from field metadata.
function ConfigField({ field, value, onChange, disabled }) {
  const id = `cfg-${field.key}`;
  return (
    <div className='config-field'>
      <label className='config-field-label' htmlFor={id}>
        {field.label}
        {field.unit && <span className='config-unit'>{field.unit}</span>}
      </label>
      {field.type === "select" ? (
        <select
          id={id}
          className='config-input'
          value={value ?? ""}
          onChange={(e) => onChange(field.key, e.target.value)}
          disabled={disabled}
        >
          <option value=''>Default</option>
          {field.options.map(([val, label]) => (
            <option key={val} value={val}>
              {label}
            </option>
          ))}
        </select>
      ) : (
        <input
          id={id}
          className='config-input'
          type={field.type === "text" ? "text" : "number"}
          inputMode={field.type === "int" ? "numeric" : undefined}
          min={field.min}
          max={field.max}
          step={field.step ?? (field.type === "int" ? 1 : "any")}
          maxLength={field.maxLength}
          placeholder={field.placeholder || "Default"}
          value={value ?? ""}
          onChange={(e) => onChange(field.key, coerce(field, e.target.value))}
          disabled={disabled}
        />
      )}
      {field.help && <p className='config-help'>{field.help}</p>}
    </div>
  );
}

// A single credential account (main/second/admin). Basic identity fields are
// always shown; the login-flow overrides live behind a per-account toggle.
function CredentialAccount({ role, account, onField, disabled, lead }) {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const basic = CRED_FIELDS.filter((f) => !f.advanced);
  const advanced = CRED_FIELDS.filter((f) => f.advanced);
  const filled = Object.keys(account).length > 0;

  return (
    <div className={`cred-account ${lead ? "cred-account-lead" : ""}`}>
      <div className='cred-account-head'>
        <span className='cred-role'>
          {role.label}
          {lead && <span className='cred-role-tag'>drives the crawl</span>}
          {filled && !lead && <span className='cred-role-dot' aria-hidden />}
        </span>
        <span className='cred-role-desc'>{role.desc}</span>
      </div>
      {basic.map((field) => (
        <div className='input-group cred-input' key={field.key}>
          {field.key === "username" ? (
            <User className='field-icon' size={17} />
          ) : (
            <Lock className='field-icon' size={17} />
          )}
          <input
            type={field.type}
            autoComplete='off'
            maxLength={field.maxLength}
            placeholder={field.label}
            value={account[field.key] ?? ""}
            onChange={(e) => onField(role.key, field.key, e.target.value)}
            disabled={disabled}
          />
        </div>
      ))}
      <button
        type='button'
        className='cred-advanced-toggle'
        onClick={() => setShowAdvanced((o) => !o)}
        aria-expanded={showAdvanced}
      >
        Login-flow overrides
        <CaretDown
          className={`chevron ${showAdvanced ? "open" : ""}`}
          size={13}
          weight='bold'
        />
      </button>
      {showAdvanced && (
        <div className='cred-advanced'>
          {advanced.map((field) => (
            <div className='config-field' key={field.key}>
              <label
                className='config-field-label'
                htmlFor={`cred-${role.key}-${field.key}`}
              >
                {field.label}
              </label>
              <input
                id={`cred-${role.key}-${field.key}`}
                className='config-input'
                type='text'
                autoComplete='off'
                maxLength={field.maxLength}
                placeholder={field.placeholder || ""}
                value={account[field.key] ?? ""}
                onChange={(e) => onField(role.key, field.key, e.target.value)}
                disabled={disabled}
              />
              {field.help && <p className='config-help'>{field.help}</p>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ScanPage({ onComplete }) {
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const {
    url,
    setUrl,
    crawlMode,
    setCrawlMode,
    authText,
    setAuthText,
    consent,
    setConsent,
    touched,
    setTouched,
    config,
    setConfigField,
    credentials,
    setCredentialField,
    scanning,
    status,
    progress,
    stageIdx,
    error,
    valid,
    canStart,
    startScan,
    cancel,
  } = useScan(onComplete);

  const scanMode = config.scan_mode || "";

  return (
    <div className='page'>
      <div className='scan-hero'>
        <div className='scan-pill'>
          <span className='pulse-dot' /> Live Scanner
        </div>
        <h1 className='scan-title'>
          Audit any web target,
          <br />
          <span>end to end.</span>
        </h1>
        <p className='scan-sub'>
          SentryStrike crawls your target, runs OWASP Top 10 detectors, and
          verifies findings against real evidence. A full scan runs in the
          background and can take a while.
        </p>
      </div>

      <div className='card scan-form'>
        {error && (
          <div className='auth-error'>
            <WarningCircle size={16} weight='fill' /> {error}
          </div>
        )}

        <label className='form-label' htmlFor='target-url'>
          Target URL
        </label>
        <div
          className={`input-group ${touched && url && !valid ? "error" : valid ? "valid" : ""}`}
        >
          <Globe className='field-icon' size={17} />
          <input
            id='target-url'
            type='url'
            placeholder='https://example.com'
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            onBlur={() => setTouched(true)}
            disabled={scanning}
          />
          {valid && <CheckCircle className='input-ok' size={17} weight='fill' />}
        </div>
        {touched && url && !valid && (
          <p className='field-error'>
            Enter a valid URL including http:// or https://
          </p>
        )}

        <label className='form-label' style={{ marginTop: 20 }}>
          Crawl mode
        </label>
        <div className='segmented' role='group' aria-label='Crawl mode'>
          <button
            type='button'
            className={`segmented-btn ${crawlMode === "full" ? "active" : ""}`}
            onClick={() => setCrawlMode("full")}
            disabled={scanning}
          >
            <span className='segmented-title'>
              <TreeStructure size={16} weight='bold' /> Full site
            </span>
            <span className='segmented-desc'>
              Crawl and test every reachable page
            </span>
          </button>
          <button
            type='button'
            className={`segmented-btn ${crawlMode === "single" ? "active" : ""}`}
            onClick={() => setCrawlMode("single")}
            disabled={scanning}
          >
            <span className='segmented-title'>
              <FileIcon size={16} weight='bold' /> Single page
            </span>
            <span className='segmented-desc'>Test only the URL above</span>
          </button>
        </div>

        <label
          className='form-label'
          htmlFor='auth-text'
          style={{ marginTop: 20 }}
        >
          Authorization reference{" "}
          <span className='label-optional'>optional</span>
        </label>
        <div className='input-group'>
          <input
            id='auth-text'
            type='text'
            maxLength={1000}
            placeholder='Ticket, contract, or scope note'
            value={authText}
            onChange={(event) => setAuthText(event.target.value)}
            disabled={scanning}
          />
        </div>

        <button
          type='button'
          className='advanced-toggle'
          onClick={() => setAdvancedOpen((o) => !o)}
          aria-expanded={advancedOpen}
        >
          <Sliders size={15} weight='bold' /> Advanced options
          <CaretDown
            className={`chevron ${advancedOpen ? "open" : ""}`}
            size={14}
            weight='bold'
          />
        </button>
        {advancedOpen && (
          <div className='advanced-panel'>
            {/* Region 1 — tuning knobs that shape scan behaviour. */}
            <div className='advanced-section'>
              <div className='advanced-section-head'>
                <span className='advanced-section-title'>Scan tuning</span>
                <span className='advanced-section-note'>
                  Every field is optional. Blank means the server default.
                </span>
              </div>

              {/* Scan verification mode → config.scan_mode */}
              <div className='config-block'>
                <div className='config-block-head'>
                  <ShieldCheck
                    className='config-block-icon'
                    size={16}
                    weight='bold'
                  />
                  <div>
                    <div className='config-block-title'>Verification mode</div>
                    <p className='config-block-blurb'>
                      How strict the evidence bar is before a finding is
                      reported.
                    </p>
                  </div>
                </div>
                <div
                  className='segmented segmented-3'
                  role='group'
                  aria-label='Scan mode'
                >
                  {SCAN_MODES.map(([val, title, desc]) => (
                    <button
                      key={val}
                      type='button'
                      className={`segmented-btn ${scanMode === val ? "active" : ""}`}
                      onClick={() =>
                        setConfigField("scan_mode", scanMode === val ? "" : val)
                      }
                      disabled={scanning}
                    >
                      <span className='segmented-title'>{title}</span>
                      <span className='segmented-desc'>{desc}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Every remaining ScanConfig override, one block per group. */}
              {CONFIG_GROUPS.map((group) => {
                const GroupIcon = group.icon;
                return (
                  <div className='config-block' key={group.title}>
                    <div className='config-block-head'>
                      <GroupIcon
                        className='config-block-icon'
                        size={16}
                        weight='bold'
                      />
                      <div>
                        <div className='config-block-title'>{group.title}</div>
                        <p className='config-block-blurb'>{group.blurb}</p>
                      </div>
                    </div>
                    <div className='config-grid'>
                      {group.fields.map((field) => (
                        <ConfigField
                          key={field.key}
                          field={field}
                          value={config[field.key]}
                          onChange={setConfigField}
                          disabled={scanning}
                        />
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Region 2 — credentials, visually separated from tuning knobs. */}
            <div className='advanced-section'>
              <div className='advanced-section-head'>
                <span className='advanced-section-title'>
                  Authenticated testing
                </span>
                <span className='advanced-section-note'>
                  Used for this scan only, never stored.
                </span>
              </div>
              <p className='advanced-hint'>
                Add test accounts to reach logged-in pages and check for
                access-control and IDOR issues. A second or admin account proves
                horizontal and vertical privilege escalation.
              </p>
              {CRED_ROLES.map((role) => (
                <CredentialAccount
                  key={role.key}
                  role={role}
                  account={credentials[role.key] || {}}
                  onField={setCredentialField}
                  disabled={scanning}
                  lead={role.key === "main"}
                />
              ))}

              <label className='config-checkbox'>
                <input
                  type='checkbox'
                  checked={Boolean(config.allow_secondary_provisioning)}
                  onChange={(e) =>
                    setConfigField(
                      "allow_secondary_provisioning",
                      e.target.checked ? true : "",
                    )
                  }
                  disabled={scanning}
                />
                <span>
                  Auto-provision a throwaway second identity when no second
                  account is supplied (for horizontal IDOR testing).
                </span>
              </label>
            </div>
          </div>
        )}

        <label className='consent-label'>
          <input
            type='checkbox'
            checked={consent}
            onChange={(event) => setConsent(event.target.checked)}
            disabled={scanning}
          />
          <span className='consent-text'>
            I confirm I am authorized to scan this target. Unauthorized scanning
            may be illegal.
          </span>
        </label>

        <button className='btn-primary' disabled={!canStart} onClick={startScan}>
          {scanning ? (
            <>
              <CircleNotch className='spin' size={17} weight='bold' /> Scanning
            </>
          ) : (
            <>
              <ShieldCheck size={17} weight='bold' /> Start Security Scan
            </>
          )}
        </button>
      </div>

      {scanning && (
        <div className='card scan-progress'>
          <div className='progress-header'>
            <div className='progress-stage'>
              <CircleNotch className='spin' size={16} weight='bold' />
              {SCAN_STAGES[stageIdx]}
            </div>
            <div className='progress-meta'>
              <span className={`status-pill status-${status || "queued"}`}>
                {STATUS_LABEL[status] || "Queued"}
              </span>
              <span className='progress-pct'>{Math.round(progress)}%</span>
            </div>
          </div>
          <div className='progress-bar'>
            <div className='progress-fill' style={{ width: `${progress}%` }} />
          </div>
          <div className='stage-chips'>
            {SCAN_STAGES.slice(0, -1).map((stage, index) => (
              <div
                key={stage}
                className={`stage-chip ${index <= stageIdx ? "done" : "pending"}`}
              >
                {index <= stageIdx && <Check size={12} weight='bold' />}
                {stage.replace("...", "")}
              </div>
            ))}
          </div>
          <button type='button' className='btn-ghost' onClick={cancel}>
            Cancel scan
          </button>
        </div>
      )}

      {!scanning && (
        <div className='scan-notes'>
          {NOTES.map(({ icon: Icon, title, desc }) => (
            <div key={title} className='scan-note'>
              <Icon className='scan-note-icon' size={24} weight='bold' />
              <div className='scan-note-title'>{title}</div>
              <div className='scan-note-desc'>{desc}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default ScanPage;
