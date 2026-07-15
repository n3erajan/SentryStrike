import { useEffect } from "react";
import { useParams, useNavigate, useLocation, Link } from "react-router-dom";
import {
  CircleNotch,
  Check,
  ArrowLeft,
  ArrowRight,
  Globe,
  WarningCircle,
  ShieldCheck,
} from "@phosphor-icons/react";
import { useScanStatus } from "../hooks/useScanStatus.js";
import { SCAN_STAGES } from "../data/constants.js";

const STATUS_LABEL = {
  queued: "Queued",
  running: "Scanning",
  completed: "Complete",
  failed: "Failed",
  cancelled: "Cancelled",
};

// Live view for one running scan (route /active/:scanId). Polls status via
// useScanStatus and shows progress, stage chips, and a running log. On
// completion it surfaces a CTA to the report; while running the user can cancel
// or leave — the scan keeps running on the backend and stays visible under
// /active.
function ActiveScanPage() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const target = location.state?.target || "";
  const { status, progress, stageIdx, eta, logs, logRef, error, active, cancel } =
    useScanStatus(scanId);

  // When the scan finishes, nudge toward the report after a short beat so the
  // "complete" state is visible first.
  useEffect(() => {
    if (status !== "completed") return undefined;
    const id = setTimeout(() => navigate(`/report/${scanId}`), 1200);
    return () => clearTimeout(id);
  }, [status, scanId, navigate]);

  return (
    <div className='page'>
      <button className='report-back' onClick={() => navigate("/active")}>
        <ArrowLeft size={15} weight='bold' /> All active scans
      </button>

      <div className='scan-hero'>
        <div className='scan-pill'>
          <span className='pulse-dot' /> {STATUS_LABEL[status] || "Queued"}
        </div>
        <h1 className='scan-title'>
          Scanning in <span>progress</span>
        </h1>
        {target && (
          <div className='target-url' style={{ marginTop: "0.75rem" }}>
            <Globe size={16} weight='bold' />
            <code>{target}</code>
          </div>
        )}
      </div>

      <div className='card scan-progress'>
        <div className='progress-header'>
          <div className='progress-stage'>
            {active ? (
              <CircleNotch className='spin' size={16} weight='bold' />
            ) : (
              <Check size={16} weight='bold' />
            )}
            {SCAN_STAGES[stageIdx]}
          </div>
          <div className='progress-meta'>
            <span className={`status-pill status-${status || "queued"}`}>
              {STATUS_LABEL[status] || "Queued"}
            </span>
            <span className='progress-pct'>{Math.round(progress)}%</span>
            {eta != null && eta > 0 && (
              <span className='progress-eta'>~{eta}s left</span>
            )}
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

        {error && (
          <div className='auth-error' style={{ marginTop: 14 }}>
            <WarningCircle size={16} weight='fill' /> {error}
          </div>
        )}

        {logs.length > 0 && (
          <div className='scan-log' ref={logRef}>
            {logs.map((line, i) => (
              <div key={i} className={`scan-log-line ${line.kind}`}>
                {line.text}
              </div>
            ))}
          </div>
        )}

        <div className='scan-progress-actions'>
          {active ? (
            <button type='button' className='btn-ghost' onClick={cancel}>
              Cancel scan
            </button>
          ) : status === "completed" ? (
            <Link
              to={`/report/${scanId}`}
              className='btn-dl btn-dl-primary'
            >
              <ShieldCheck size={16} weight='bold' /> View report
              <ArrowRight size={15} weight='bold' />
            </Link>
          ) : (
            <Link to='/scan' className='btn-ghost'>
              Start a new scan
            </Link>
          )}
        </div>
      </div>
    </div>
  );
}

export default ActiveScanPage;
