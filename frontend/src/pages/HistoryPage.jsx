import { useState, useEffect, useCallback } from "react";
import {
  CircleNotch,
  WarningCircle,
  ArrowRight,
  ClockCounterClockwise,
  TreeStructure,
  File as FileIcon,
} from "@phosphor-icons/react";
import { listScans } from "../services/scan.js";

const STATUS_LABEL = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
};

function formatDate(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "-" : d.toLocaleString();
}

// Lists the signed-in user's past scans (GET /scans). Completed scans open
// straight into their report; the rest show their last known status.
function HistoryPage({ onOpenReport, onNewScan }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async (signal) => {
    setLoading(true);
    setError("");
    try {
      const data = await listScans({ signal });
      setScans(Array.isArray(data?.items) ? data.items : []);
    } catch (err) {
      if (err.name === "AbortError") return;
      setError(err.message || "Could not load your scans.");
    } finally {
      if (!signal || !signal.aborted) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch-on-mount
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  return (
    <div className='page-wide'>
      <div className='history-head'>
        <div>
          <h1 className='report-title'>
            Scan <span>History</span>
          </h1>
          <p className='scan-sub' style={{ marginTop: "0.6rem" }}>
            Every target you have scanned. Open a completed scan to review its
            report.
          </p>
        </div>
        <button className='btn-dl btn-dl-primary' onClick={onNewScan}>
          New scan
        </button>
      </div>

      {loading ? (
        <div className='card report-state'>
          <CircleNotch className='spin' size={26} weight='bold' />
          <p>Loading your scans</p>
        </div>
      ) : error ? (
        <div className='card report-state'>
          <div className='auth-error' style={{ marginBottom: 8 }}>
            <WarningCircle size={16} weight='fill' /> {error}
          </div>
          <button
            className='btn-ghost'
            style={{ maxWidth: 200 }}
            onClick={() => load()}
          >
            Retry
          </button>
        </div>
      ) : scans.length === 0 ? (
        <div className='empty-state'>
          <ClockCounterClockwise size={30} weight='bold' />
          You have not run any scans yet.
          <button
            className='btn-dl btn-dl-primary'
            style={{ marginTop: 6 }}
            onClick={onNewScan}
          >
            Start your first scan
          </button>
        </div>
      ) : (
        <div className='history-list'>
          {scans.map((scan) => {
            const completed = scan.status === "completed";
            const CrawlIcon =
              scan.crawl_mode === "single" ? FileIcon : TreeStructure;
            return (
              <div
                key={scan.id}
                className={`history-row ${completed ? "is-open" : ""}`}
                role={completed ? "button" : undefined}
                tabIndex={completed ? 0 : undefined}
                onClick={
                  completed
                    ? () =>
                        onOpenReport({
                          scanId: scan.id,
                          target: scan.target_url,
                        })
                    : undefined
                }
                onKeyDown={
                  completed
                    ? (e) =>
                        e.key === "Enter" &&
                        onOpenReport({
                          scanId: scan.id,
                          target: scan.target_url,
                        })
                    : undefined
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
                    {scan.status === "running" && (
                      <span>{scan.progress}%</span>
                    )}
                  </div>
                </div>
                {completed ? (
                  <span className='history-open'>
                    Open report <ArrowRight size={14} weight='bold' />
                  </span>
                ) : (
                  <span className='history-phase'>{scan.phase_message}</span>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default HistoryPage;
