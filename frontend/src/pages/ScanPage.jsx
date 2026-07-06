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
import { SCAN_STAGES } from "../data/constants.js";

const SCAN_MODES = [
  ["verified", "Verified", "Only evidence-verified findings"],
  ["heuristic", "Heuristic", "Adds strong heuristic matches"],
  ["aggressive", "Aggressive", "Widest checks, more noise"],
];

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
    scanMode,
    setScanMode,
    authUsername,
    setAuthUsername,
    authPassword,
    setAuthPassword,
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
            <label className='form-label'>
              Scan mode <span className='label-optional'>optional</span>
            </label>
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
                  onClick={() => setScanMode(scanMode === val ? "" : val)}
                  disabled={scanning}
                >
                  <span className='segmented-title'>{title}</span>
                  <span className='segmented-desc'>{desc}</span>
                </button>
              ))}
            </div>

            <label className='form-label' style={{ marginTop: 20 }}>
              Authenticated testing{" "}
              <span className='label-optional'>optional</span>
            </label>
            <p className='advanced-hint'>
              Add a test account to crawl authenticated pages and check for
              access-control and IDOR issues. Used for this scan only, never
              stored.
            </p>
            <div className='input-group'>
              <User className='field-icon' size={17} />
              <input
                type='text'
                autoComplete='off'
                placeholder='Username or email'
                value={authUsername}
                onChange={(event) => setAuthUsername(event.target.value)}
                disabled={scanning}
              />
            </div>
            <div className='input-group' style={{ marginTop: 10 }}>
              <Lock className='field-icon' size={17} />
              <input
                type='password'
                autoComplete='off'
                placeholder='Password'
                value={authPassword}
                onChange={(event) => setAuthPassword(event.target.value)}
                disabled={scanning}
              />
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
