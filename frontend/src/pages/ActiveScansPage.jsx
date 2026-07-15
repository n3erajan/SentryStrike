import { useNavigate } from "react-router-dom";
import {
  CircleNotch,
  WarningCircle,
  Pulse,
  TreeStructure,
  File as FileIcon,
  ArrowRight,
  ShieldCheck,
} from "@phosphor-icons/react";
import { useActiveScans } from "../hooks/useActiveScans.js";

const STATUS_LABEL = {
  queued: "Queued",
  running: "Running",
};

function formatDate(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "-" : d.toLocaleString();
}

// Dashboard of all in-flight scans (route /active). Because the backend
// runs scans concurrently, several can be live at once; each row links to its
// own active-scan page. The list polls via the shared useActiveScans hook.
function ActiveScansPage() {
  const navigate = useNavigate();
  const { scans, loading, error } = useActiveScans();

  return (
    <div className='page-wide'>
      <div className='history-head'>
        <div>
          <h1 className='report-title'>
            Active <span>Scans</span>
          </h1>
          <p className='scan-sub' style={{ marginTop: "0.6rem" }}>
            Scans currently queued or running. SentryStrike runs them in
            parallel — start another any time.
          </p>
        </div>
        <button
          className='btn-dl btn-dl-primary'
          onClick={() => navigate("/scan")}
        >
          <ShieldCheck size={16} weight='bold' /> New scan
        </button>
      </div>

      {loading && scans.length === 0 ? (
        <div className='card report-state'>
          <CircleNotch className='spin' size={26} weight='bold' />
          <p>Loading active scans</p>
        </div>
      ) : error ? (
        <div className='card report-state'>
          <div className='auth-error' style={{ marginBottom: 8 }}>
            <WarningCircle size={16} weight='fill' /> {error}
          </div>
        </div>
      ) : scans.length === 0 ? (
        <div className='empty-state'>
          <Pulse size={30} weight='bold' />
          No scans are running right now.
          <button
            className='btn-dl btn-dl-primary'
            style={{ marginTop: 6 }}
            onClick={() => navigate("/scan")}
          >
            Start a scan
          </button>
        </div>
      ) : (
        <div className='history-list'>
          {scans.map((scan) => {
            const CrawlIcon =
              scan.crawl_mode === "single" ? FileIcon : TreeStructure;
            return (
              <div
                key={scan.id}
                className='history-row is-open'
                role='button'
                tabIndex={0}
                onClick={() =>
                  navigate(`/active/${scan.id}`, {
                    state: { target: scan.target_url },
                  })
                }
                onKeyDown={(e) =>
                  e.key === "Enter" &&
                  navigate(`/active/${scan.id}`, {
                    state: { target: scan.target_url },
                  })
                }
              >
                <span className={`status-pill status-${scan.status}`}>
                  {STATUS_LABEL[scan.status] || scan.status}
                </span>
                <div className='history-target'>
                  <div className='history-url'>{scan.target_url}</div>
                  <div className='history-meta'>
                    <span>
                      <CrawlIcon size={12} weight='bold' />
                      {scan.crawl_mode === "single" ? "Single page" : "Full site"}
                    </span>
                    <span>{formatDate(scan.created_at)}</span>
                    <span>{scan.progress}%</span>
                  </div>
                </div>
                <div className='active-row-right'>
                  <div className='active-progress-bar'>
                    <div
                      className='active-progress-fill'
                      style={{ width: `${scan.progress || 0}%` }}
                    />
                  </div>
                  <span className='history-open'>
                    Open <ArrowRight size={14} weight='bold' />
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default ActiveScansPage;
