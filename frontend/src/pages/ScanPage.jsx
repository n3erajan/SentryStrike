import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { ChevronDown } from "lucide-react";
import { useScanForm } from "../hooks/useScan.js";
import { useToast } from "../components/Toast.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import Select from "../components/Select.jsx";
import ConfigField, { configValid } from "../components/ConfigField.jsx";
import { listApplications } from "../services/applications.js";
import {
  CONFIG_GROUPS,
  CRED_FIELDS,
  CRED_ROLES,
  SCAN_MODES,
} from "../data/constants.js";

function CredentialAccount({ role, account, onField, disabled }) {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const basic = CRED_FIELDS.filter((f) => !f.advanced);
  const advanced = CRED_FIELDS.filter((f) => f.advanced);

  return (
    <section className='credential-account'>
      <div className='credential-account-head'>
        <h3>{role.label}</h3>
        <p>{role.desc}</p>
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
          ? "Hide session alternatives"
          : "Use a cookie or header instead"}
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

function credentialPresent(account = {}) {
  return Boolean(
    (account.username && account.password) || account.cookie || account.header,
  );
}

function ScanPage() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const applicationId = searchParams.get("app") || "";
  const [apps, setApps] = useState([]);
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
    defaultsLoading,
    setConfigField,
    credentials,
    setCredentialField,
    submitting,
    error,
    conflict,
    valid,
    canStart,
    startScan,
  } = useScanForm({ applicationId });

  // The picker is a convenience only — a scan can always be run against a raw
  // URL, so a failed application fetch is silently ignored.
  useEffect(() => {
    const controller = new AbortController();
    listApplications({ signal: controller.signal })
      .then((data) => setApps(data.items || []))
      .catch(() => {});
    return () => controller.abort();
  }, []);

  if (user?.role === "viewer") {
    return (
      <div className='view'>
        <div className='head'>
          <div>
            <h1>New scan</h1>
            <p>Viewers cannot start scans.</p>
          </div>
        </div>
        <div className='empty-state'>
          Ask a workspace owner or admin to change your role.
        </div>
      </div>
    );
  }
  // Backend default is "verified"; reflect that as pre-selected in the UI.
  const scanMode = config.scan_mode || "verified";
  const credentialCount = CRED_ROLES.filter(({ key }) =>
    credentialPresent(credentials[key]),
  ).length;
  const configIsValid = configValid(CONFIG_GROUPS, config);
  const selectedApp = apps.find((a) => a.id === applicationId);

  function selectApplication(nextId) {
    if (nextId) setSearchParams({ app: nextId });
    else setSearchParams({});
  }

  async function handleStart() {
    if (!configIsValid) return;
    const result = await startScan();
    if (result) {
      toast("Scan started");
      navigate(`/active/${result.scanId}`, {
        state: { target: result.target },
      });
    }
  }

  return (
    <div className='view'>
      <div className='head'>
        <div>
          <h1>New scan</h1>
          <p>Choose a target and how deeply to test it.</p>
        </div>
      </div>

      {error && (
        <div
          className={conflict ? "scan-conflict" : "auth-error"}
          style={{ margin: "0 0 16px" }}
        >
          {error}
        </div>
      )}

      <div className='formlayout'>
        <main>
          <section className='formsection'>
            <h3>Target</h3>
            {apps.length > 0 && (
              <div className='grid2'>
                <div className='field wide'>
                  <label htmlFor='scan-application'>Web application</label>
                  <div className='control'>
                    <Select
                      value={applicationId}
                      onChange={selectApplication}
                      disabled={submitting}
                      options={[
                        { value: "", label: "None" },
                        ...apps.map((a) => ({ value: a.id, label: a.name })),
                      ]}
                    />
                  </div>
                  <p
                    className='field-description'
                    id='scan-application-description'
                  >
                    Select a saved app to load its URL and scan defaults.
                  </p>
                </div>
              </div>
            )}
            <div className='grid2'>
              <div className='field wide'>
                <label htmlFor='target-url'>URL</label>
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
                    disabled={submitting || defaultsLoading}
                    aria-describedby='target-url-description'
                  />
                </div>
                {touched && url && !valid && (
                  <span className='field-error'>
                    Enter a valid URL including http:// or https://
                  </span>
                )}
                <p className='field-description' id='target-url-description'>
                  {selectedApp
                    ? `Loaded from ${selectedApp.name}. You can edit the path for this scan.`
                    : "Enter the public or staging URL where the scan should begin."}
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
            <span className='advanced-toggle-title'>
              Test users <span className='muted-text'>(optional)</span>
            </span>
            <span className='advanced-toggle-hint'>
              Accounts for authenticated and access-control testing
            </span>
            <ChevronDown className='ico chev' />
          </button>

          {usersOpen && (
            <div className='advanced-panel users-panel' id='test-users-panel'>
              <p className='panel-intro'>
                Add dedicated test accounts for authenticated and access-control
                checks. Do not use personal or production credentials.
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
                  Create a temporary second user for horizontal access checks
                  when none is supplied.
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
            <span className='advanced-toggle-title'>
              Advanced configuration{" "}
              <span className='muted-text'>(optional)</span>
            </span>
            <span className='advanced-toggle-hint'>
              Crawl limits, timeouts, and verification thresholds
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
          <h2>Scan summary</h2>
          <dl>
            {selectedApp && (
              <div>
                <dt>Application</dt>
                <dd>{selectedApp.name}</dd>
              </div>
            )}
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
                {credentialCount
                  ? `${credentialCount} test user${credentialCount === 1 ? "" : "s"}`
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
            disabled={!canStart || !configIsValid}
          >
            {defaultsLoading
              ? "Loading defaults…"
              : submitting
                ? "Starting…"
                : "Start scan"}
          </button>
        </aside>
      </div>
    </div>
  );
}

export default ScanPage;
