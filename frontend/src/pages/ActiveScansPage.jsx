import { useNavigate } from "react-router-dom";
import { ArrowUpRight, ShieldCheck } from "lucide-react";
import { useActiveScans } from "../hooks/useActiveScans.js";
import { useBackendHealth } from "../hooks/useBackendHealth.js";

function formatRelative(iso) {
  if (!iso) return "-";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "-";
  const diff = Math.max(0, Date.now() - then);
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function ActiveScansPage() {
  const navigate = useNavigate();
  const { scans, loading, error } = useActiveScans();
  const { health } = useBackendHealth();
  const workerCount = health?.active_scanners;

  return (
    <div className='view'>
      <div className='head'>
        <div>
          <h1>Active scans</h1>
        </div>
        {Number.isInteger(workerCount) && (
          <span className={workerCount === 0 ? "high" : "low"}>
            ●{" "}
            {workerCount === 0
              ? "No scanner workers online"
              : `${workerCount} scanner ${workerCount === 1 ? "worker" : "workers"} online`}
          </span>
        )}
      </div>

      {loading && scans.length === 0 ? (
        <div className='empty-state'>Loading active scans…</div>
      ) : error ? (
        <div className='auth-error'>{error}</div>
      ) : scans.length === 0 ? (
        <div className='empty-state'>
          <ShieldCheck size={30} />
          <h2>No scans are running</h2>
          <p>
            Create a new scan and its live phase, progress, and worker state
            will appear here.
          </p>
          <button className='btn primary' onClick={() => navigate("/scan")}>
            New Scan
          </button>
        </div>
      ) : (
        <div className='scans-table'>
          <div className='scans-head'>
            <span>Target</span>
            <span>Status</span>
            <span>Progress</span>
            <span>Phase</span>
            <span></span>
          </div>
          {scans.map((scan) => (
            <article
              key={scan.id}
              className='scans-row'
              onClick={() =>
                navigate(`/active/${scan.id}`, {
                  state: { target: scan.target_url },
                })
              }
            >
              <div>
                <div className='rowtitle'>{scan.target_url}</div>
                <div className='small'>
                  {scan.crawl_mode === "single" ? "Single page" : "Full site"} ·{" "}
                  {formatRelative(scan.created_at)}
                </div>
              </div>
              <span className={`status-pill ${scan.status}`}>
                {scan.status}
              </span>
              <span>{Math.round(scan.progress || 0)}%</span>
              <span className='small'>{scan.phase_message || "Scanning"}</span>
              <span className='rowactions'>
                <button aria-label='Open scan' type='button'>
                  <ArrowUpRight className='ico' />
                </button>
              </span>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}

export default ActiveScansPage;
