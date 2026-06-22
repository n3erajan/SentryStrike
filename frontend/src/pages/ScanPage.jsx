import { useScan } from "../hooks/useScan.js";
import { SCAN_STAGES } from "../data/constants.js";

const STATUS_LABEL = {
  queued: "Queued",
  running: "Scanning",
  completed: "Complete",
  failed: "Failed",
  cancelled: "Cancelled",
};

function ScanPage({ onComplete }) {
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
    scanning,
    status,
    progress,
    stageIdx,
    eta,
    logs,
    logRef,
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
          Audit any web target
          <br />
          in <span className='gtext'>seconds</span>
        </h1>
        <p className='scan-sub'>
          SentryStrike crawls your target, runs OWASP Top 10 checks, and
          validates findings with AI.
        </p>
      </div>

      <div className='card card-elevated scan-form'>
        {error && <div className='auth-error'>{error}</div>}

        <label className='form-label' htmlFor='target-url'>
          Target URL
        </label>
        <div
          className={`input-group ${touched && url && !valid ? "error" : valid ? "valid" : ""}`}
        >
          <span className='input-icon'>🌐</span>
          <input
            id='target-url'
            type='url'
            placeholder='https://example.com'
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            onBlur={() => setTouched(true)}
            disabled={scanning}
          />
          {valid && (
            <span style={{ color: "var(--accent)", fontSize: 16 }}>✓</span>
          )}
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
            <span className='segmented-title'>Full site</span>
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
            <span className='segmented-title'>Single page</span>
            <span className='segmented-desc'>Test only the URL above</span>
          </button>
        </div>

        <label
          className='form-label'
          htmlFor='auth-text'
          style={{ marginTop: 20 }}
        >
          Authorization reference <span className='label-optional'>optional</span>
        </label>
        <div className='input-group'>
          <span className='input-icon'>📝</span>
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

        <button className='btn-scan' disabled={!canStart} onClick={startScan}>
          {scanning ? (
            <>
              <span className='spin'>⟳</span> Scanning…
            </>
          ) : (
            <>Start Security Scan</>
          )}
        </button>
      </div>

      {scanning && (
        <div className='card card-elevated scan-progress'>
          <div className='progress-header'>
            <div className='progress-stage'>
              <span className='spin' style={{ color: "var(--accent)" }}>
                ⟳
              </span>
              {SCAN_STAGES[stageIdx]}
            </div>
            <div className='progress-meta'>
              <span className={`status-pill status-${status || "queued"}`}>
                {STATUS_LABEL[status] || "Queued"}
              </span>
              {eta != null && eta > 0 && <span>~{eta}s left</span>}
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
                {stage.replace("...", "")}
              </div>
            ))}
          </div>
          <div className='terminal'>
            <div className='terminal-bar'>
              <span style={{ color: "var(--accent)", fontSize: 14 }}>▶</span> Live
              Log
            </div>
            <div className='terminal-body' ref={logRef}>
              {logs.map((line, index) => (
                <div
                  key={index}
                  className={line.kind === "ok" ? "log-ok" : "log-warn"}
                >
                  {line.text}
                </div>
              ))}
              <div className='log-cursor'>▮</div>
            </div>
          </div>
          <button type='button' className='btn-ghost' onClick={cancel}>
            Cancel scan
          </button>
        </div>
      )}
    </div>
  );
}

export default ScanPage;
