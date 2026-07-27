import { useEffect } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { ArrowRight, Check, Loader2, ShieldCheck } from "lucide-react";
import { useScanStatus } from "../hooks/useScanStatus.js";
import { SCAN_PHASES } from "../data/constants.js";
import { useAuth } from "../context/AuthContext.jsx";
import ErrorNotice from "../components/ErrorNotice.jsx";

const STATUS_LABEL = {
  queued: "Queued",
  running: "Scanning",
  completed: "Complete",
  failed: "Failed",
  cancelled: "Cancelled",
};

const ANALYSIS_LABEL = {
  not_requested: "Queueing AI analysis",
  queued: "AI analysis queued",
  running: "AI analysis running",
  completed: "AI analysis complete",
  failed: "AI analysis failed",
  cancelled: "AI analysis cancelled",
};

function formatEta(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) return "N/A";
  if (seconds < 60) return `${Math.ceil(seconds)}s`;
  const mins = Math.ceil(seconds / 60);
  if (mins < 60) return `${mins}m`;
  const hours = Math.floor(mins / 60);
  const rem = mins % 60;
  return rem ? `${hours}h ${rem}m` : `${hours}h`;
}

function timeStr(date) {
  return date.toTimeString().slice(0, 8);
}

function hostnameOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url || "target";
  }
}

function ActiveScanPage() {
  const { user } = useAuth();
  const { scanId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const target = location.state?.target || "";
  const {
    status,
    progress,
    phaseMessage,
    stageIdx,
    eta,
    analysis,
    siteTitle,
    targetUrl,
    statistics,
    logs,
    logRef,
    error,
    active,
    cancelling,
    cancel,
  } = useScanStatus(scanId);

  const displayName = siteTitle || hostnameOf(targetUrl || target);

  // The deterministic report is ready the moment the scan completes; AI
  // enrichment continues in the analyzer worker, and the report page renders
  // its own banner for that. So navigate as soon as the scan itself is done.
  useEffect(() => {
    if (status !== "completed") return undefined;
    const id = setTimeout(() => navigate(`/report/${scanId}`), 1200);
    return () => clearTimeout(id);
  }, [status, scanId, navigate]);

  const surfaces = statistics?.total_urls_crawled ?? Math.max(1, stageIdx * 20);
  const alerts = statistics?.total_vulnerabilities ?? logs.filter((l) => l.kind === "warn").length;
  const analysisStatus = analysis?.status;
  const showAnalysis =
    Boolean(analysisStatus) && status === "completed";

  return (
    <div className='view'>
      <button className='back' onClick={() => navigate("/active")}>
        ← All active scans
      </button>
      <div className='head'>
        <div>
          <h1>Scanning {displayName || "target"}</h1>
          <p>
            {targetUrl || target || `Scan ${scanId}`}
          </p>
        </div>
        {active && user?.role !== "viewer" ? (
          <button className='btn danger' onClick={cancel} disabled={cancelling}>
            {cancelling ? "Cancelling…" : "Cancel"}
          </button>
        ) : status === "completed" ? (
          <Link className='btn primary' to={`/report/${scanId}`}>
            <ShieldCheck className='ico' />
            View report
            <ArrowRight className='ico' />
          </Link>
        ) : user?.role !== "viewer" ? (
          <Link className='btn' to='/scan'>
            Start a new scan
          </Link>
        ) : null}
      </div>

      <div className='summary'>
        <div className='stat'>
          <strong>{Math.round(progress)}%</strong>
          <span>Complete</span>
        </div>
        <div className='stat'>
          <strong>{surfaces}</strong>
          <span>Surfaces</span>
        </div>
        <div className='stat'>
          <strong>{alerts}</strong>
          <span>Alerts</span>
        </div>
        <div className='stat'>
          <strong>{formatEta(eta)}</strong>
          <span>Remaining</span>
        </div>
      </div>

      <div className='app-progress'>
        <span style={{ width: `${progress}%` }} />
      </div>

      <ErrorNotice error={error} title='Scan interrupted' className='scan-error-notice' />

      {showAnalysis && (
        <div className={`analysis-banner ${analysisStatus}`}>
          <div>
            <b>{ANALYSIS_LABEL[analysisStatus] || "AI analysis"}</b>
            <span>
              {analysis.message ||
                analysis.error_message ||
                "Analyzing findings and preparing the final report."}
            </span>
            {Number.isFinite(analysis.progress) && (
              <small>
                {analysis.progress}% complete · revision{" "}
                {analysis.revision || 1}
              </small>
            )}
          </div>
        </div>
      )}

      <div className='activity'>
        {SCAN_PHASES.slice(1).map((p, i) => {
          const idx = i + 1;
          const done = status === "completed" || idx < stageIdx;
          const current = active && idx === stageIdx;
          const state = done ? "Complete" : current ? "Running" : "Pending";
          const cls = done ? "low" : current ? "" : "small";
          return (
            <div key={p.key}>
              <time>
                {done ? (
                  <Check size={13} />
                ) : current ? (
                  <Loader2
                    size={13}
                    style={{ animation: "spin 1s linear infinite" }}
                  />
                ) : (
                  "N/A"
                )}
              </time>
              <span>{p.label}</span>
              <b className={cls}>{state}</b>
            </div>
          );
        })}
      </div>

      <div className='panel'>
        <div className='panel-h'>Activity log</div>
        <div className='panel-b'>
          <div className='scan-log' ref={logRef}>
            {logs.length ? (
              logs.map((line, i) => (
                <div
                  key={i}
                  className={
                    line.kind === "warn"
                      ? "warn"
                      : line.kind === "ok"
                        ? "ok"
                        : ""
                  }
                >
                  [{timeStr(new Date(line.time))}] {line.text}
                </div>
              ))
            ) : (
              <div>Waiting for scanner activity…</div>
            )}
          </div>
        </div>
      </div>

      <p className='muted-text' style={{ marginTop: 12 }}>
        Current phase: <b>{phaseMessage || STATUS_LABEL[status] || "Queued"}</b>
      </p>
    </div>
  );
}

export default ActiveScanPage;
