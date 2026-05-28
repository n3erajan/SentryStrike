import { useScan } from "../hooks/useScan.js";
import { SCAN_STAGES } from "../data/constants.js";

function ScanPage({ onComplete }) {
  const {
    url,
    setUrl,
    consent,
    setConsent,
    touched,
    setTouched,
    scanning,
    setScanning,
    progress,
    stageIdx,
    logs,
    logRef,
    valid,
    canStart,
    eta,
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

      <div className='card card-elevated' style={{ marginBottom: 20 }}>
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
          <p style={{ fontSize: 12, color: "#ef4444", marginTop: 6 }}>
            Enter a valid URL including http:// or https://
          </p>
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
        <button
          className='btn-scan'
          disabled={!canStart}
          onClick={() => canStart && setScanning(true)}
        >
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
        <div className='card card-elevated'>
          <div className='progress-header'>
            <div className='progress-stage'>
              <span className='spin' style={{ color: "var(--accent)" }}>
                ⟳
              </span>
              {SCAN_STAGES[stageIdx]}
            </div>
            <div className='progress-meta'>
              <span>ETA {eta}s</span>
              <span className='progress-pct'>{progress.toFixed(0)}%</span>
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
              <span style={{ color: "var(--accent)", fontSize: 14 }}>▶</span>{" "}
              Live Log
            </div>
            <div className='terminal-body' ref={logRef}>
              {logs.map((l, i) => (
                <div
                  key={i}
                  className={l.kind === "ok" ? "log-ok" : "log-warn"}
                >
                  {l.text}
                </div>
              ))}
              <div className='log-cursor'>▮</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default ScanPage;
