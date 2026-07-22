import { useEffect } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { ArrowRight, Check, Loader2, ShieldCheck } from "lucide-react";
import { useScanStatus } from "../hooks/useScanStatus.js";
import { SCAN_PHASES } from "../data/constants.js";
import { useAuth } from "../context/AuthContext.jsx";

const STATUS_LABEL = {
  queued: "Queued",
  running: "Scanning",
  completed: "Complete",
  failed: "Failed",
  cancelled: "Cancelled",
};

function formatEta(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) return "—";
  if (seconds < 60) return `${Math.ceil(seconds)}s`;
  const mins = Math.ceil(seconds / 60);
  if (mins < 60) return `${mins}m`;
  const hours = Math.floor(mins / 60);
  const rem = mins % 60;
  return rem ? `${hours}h ${rem}m` : `${hours}h`;
}

function formatDuration(iso) {
  if (!iso) return "";
  const start = new Date(iso).getTime();
  if (Number.isNaN(start)) return "";
  const diff = Math.max(0, Date.now() - start);
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} minutes ago`;
  return `${Math.floor(mins / 60)}h ago`;
}

function timeStr(date) {
  return date.toTimeString().slice(0, 8);
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
    logs,
    logRef,
    error,
    active,
    cancelling,
    cancel,
  } = useScanStatus(scanId);

  useEffect(() => {
    if (status !== "completed") return undefined;
    const id = setTimeout(() => navigate(`/report/${scanId}`), 1200);
    return () => clearTimeout(id);
  }, [status, scanId, navigate]);

  const surfaces = Math.max(1, stageIdx * 20);
  const now = new Date();

  return (
    <div className='view'>
      <button className='back' onClick={() => navigate("/active")}>
        ← All active scans
      </button>
      <div className='head'>
        <div>
          <h1>Assessing {target ? new URL(target).hostname : "target"}</h1>
          <p>
            {target || `Scan ${scanId}`} · started {formatDuration()}{" "}
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
            Start a new Scan
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
          <strong>{logs.filter((l) => l.kind === "warn").length}</strong>
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

      {error && (
        <div className='auth-error' style={{ marginBottom: 16 }}>
          {error}
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
                  "—"
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
                  [{timeStr(now)}] {line.text}
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
