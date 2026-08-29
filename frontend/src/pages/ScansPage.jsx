import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { mergeLiveScans, useActiveScans } from "../hooks/useActiveScans.js";
import { listAllScans } from "../services/scan.js";
import { useAuth } from "../context/AuthContext.jsx";
import ErrorNotice from "../components/ErrorNotice.jsx";
import Pagination from "../components/Pagination.jsx";
import {
  formatAbsolute,
  formatRelative,
  hostnameOf,
  navigableRowProps,
  toISOString,
} from "../utils/helpers.js";
import useQuery from "../hooks/useQuery.js";
import QuerySwap, { QuerySkeleton, QueryContent } from "../components/QuerySwap.jsx";

const PAGE_SIZE = 25;

const FILTERS = [
  { value: "", label: "All" },
  { value: "running", label: "Running" },
  { value: "completed", label: "Completed" },
  { value: "failed", label: "Failed" },
  { value: "cancelled", label: "Cancelled" },
];

const STATUS_LABELS = {
  queued: "Queued",
  running: "Scanning",
  completed: "Complete",
  failed: "Failed",
  cancelled: "Cancelled",
};

// Which fill the progress bar uses. Terminal states stop looking "in flight":
// a completed run reads green, a cancelled one neutral, a failure red at the
// point it stopped.
function progressTone(status) {
  if (status === "completed") return "done";
  if (status === "cancelled") return "stopped";
  if (status === "failed") return "failed";
  return "";
}

function ScansPage() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const { count, allScans } = useActiveScans();
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState("");

  const {
    data,
    error,
    hasData,
    contentEntered,
    isLoading: loading,
    refetch,
  } = useQuery({
    queryKey: "scans:list:all",
    queryFn: listAllScans,
    staleTime: 30_000,
  });

  // `scans:list:all` only refetches when a scan finishes, so fold in the
  // records from the polled active-scans query to keep the progress and phase
  // columns moving while a scan is in flight.
  const allItems = useMemo(
    () => mergeLiveScans(Array.isArray(data?.items) ? data.items : [], allScans),
    [data, allScans],
  );

  const filtered = useMemo(
    () =>
      statusFilter
        ? allItems.filter((s) => s.status === statusFilter)
        : allItems,
    [allItems, statusFilter],
  );

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const items = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  return (
    <div className='view'>
      <div className='head'>
        <div>
          <h1>
            Scans
            {count > 0 && (
              <span className='badge' style={{ marginLeft: 10, verticalAlign: "middle" }}>
                {count} active
              </span>
            )}
          </h1>
          <p>Every scan this workspace has run, newest first.</p>
        </div>
      </div>

      <div className='reports-controls'>
        <div className='seg' role='group' aria-label='Filter scans by status'>
          {FILTERS.map((f) => (
            <button
              key={f.value}
              type='button'
              aria-pressed={statusFilter === f.value}
              onClick={() => { setStatusFilter(f.value); setPage(1); }}
            >
              {f.label}
            </button>
          ))}
        </div>
        {!loading && filtered.length > 0 && (
          <span className='result-count'>
            {filtered.length} {filtered.length === 1 ? "scan" : "scans"}
          </span>
        )}
      </div>

      {error && hasData && (
        <ErrorNotice
          error={error}
          fallback='Scans may be out of date.'
          onRetry={refetch}
        />
      )}

      <QuerySwap>
        {loading ? (
          <QuerySkeleton
            className='scans-table query-skeleton'
            aria-label='Loading scans'
          >
            <div className='scans-head' aria-hidden='true'>
              <span>Target</span>
              <span>Status</span>
              <span>Progress</span>
              <span>Phase</span>
              <span>Started</span>
            </div>
            {[0, 1, 2, 3, 4].map((item) => (
              <div
                className='scans-row skeleton-table-row'
                key={item}
                aria-hidden='true'
              >
                <span className='skeleton-target'>
                  <span className='skeleton-block skeleton-heading' />
                  <span className='skeleton-block skeleton-copy' />
                </span>
                <span className='skeleton-block skeleton-pill' />
                <span className='skeleton-block skeleton-copy' />
                <span className='skeleton-block skeleton-copy' />
                <span className='skeleton-block skeleton-copy' />
              </div>
            ))}
          </QuerySkeleton>
        ) : error && !hasData ? (
          <ErrorNotice
            key='error'
            error={error}
            fallback='Could not load scans.'
            onRetry={refetch}
          />
        ) : filtered.length === 0 ? (
          <div className='empty-state' key='empty'>
            <ShieldCheck size={30} />
            <h2>
              {statusFilter
                ? `No ${statusFilter} scans`
                : "No scans yet"}
            </h2>
            <p>
              {statusFilter
                ? `Nothing in this workspace has status "${statusFilter}".`
                : "Scans appear here once you start them."}
            </p>
            {statusFilter ? (
              <button className='btn' onClick={() => setStatusFilter("")}>
                Show all scans
              </button>
            ) : (
              user?.role !== "viewer" && (
                <button
                  className='btn primary'
                  onClick={() => navigate("/scan")}
                >
                  New scan
                </button>
              )
            )}
          </div>
        ) : (
          <QueryContent settled={contentEntered} className='scans-table' role='table' aria-label='Scans'>
          <div className='scans-head' role='row'>
            <span role='columnheader'>Target</span>
            <span role='columnheader'>Status</span>
            <span role='columnheader'>Progress</span>
            <span role='columnheader'>Phase</span>
            <span role='columnheader'>Started</span>
          </div>
          {items.map((scan) => {
            const analysisPending =
              scan.status === "completed" &&
              ["queued", "running"].includes(scan.analysis?.status);
            const displayStatus = analysisPending ? "incomplete" : scan.status;
            const statusLabel = analysisPending
              ? "Analysing"
              : STATUS_LABELS[scan.status] || scan.status;
            const progress = Math.round(scan.progress || 0);
            const startedAt = scan.started_at || scan.created_at;
            const host =
              scan.application_name ||
              scan.site_title ||
              hostnameOf(scan.target_url);
            // Phase only earns its column while something is still moving.
            // On a finished row it repeated the status word for word
            // ("Complete" / "Scan completed") in every single row.
            const phase = analysisPending
              ? "AI analysis"
              : ["queued", "running"].includes(scan.status)
                ? scan.phase_message || statusLabel
                : scan.status === "completed"
                  ? ""
                  : scan.phase_message || "";

            return (
              <article
                key={scan.id}
                className='scans-row'
                {...navigableRowProps(() =>
                  navigate(`/scans/${scan.id}`, {
                    state: { target: scan.target_url },
                  }),
                )}
              >
                <div className='rep-target' role='cell'>
                  <Link
                    className='rowtitle row-link'
                    to={`/scans/${scan.id}`}
                    state={{ target: scan.target_url }}
                  >
                    {host}
                  </Link>
                  <div className='small mono' title={scan.target_url}>
                    {scan.target_url}
                  </div>
                  {scan.crawl_mode === "single" && (
                    <span className='row-tag'>Single page</span>
                  )}
                </div>
                <span role='cell'>
                  <span className={`status-pill ${displayStatus}`}>
                    {statusLabel}
                  </span>
                </span>
                <span
                  className={`scan-progress${progress >= 100 ? " settled" : ""}`}
                  role='cell'
                  data-label='Progress'
                >
                  {progress < 100 && (
                    <span className='scan-progress-track'>
                      <span
                        className={`scan-progress-fill ${progressTone(scan.status)}`}
                        style={{ width: `${progress}%` }}
                      />
                    </span>
                  )}
                  <span>{progress}%</span>
                </span>
                <span className='small' role='cell' data-label='Phase'>{phase}</span>
                <span className='small' role='cell' data-label='Started'>
                  <time
                    dateTime={toISOString(startedAt)}
                    title={formatAbsolute(startedAt)}
                  >
                    {formatRelative(startedAt)}
                  </time>
                </span>
              </article>
            );
          })}
          <Pagination
            page={page}
            totalPages={totalPages}
            onChange={setPage}
            label='Scans pagination'
          />
          </QueryContent>
        )}
      </QuerySwap>
    </div>
  );
}

export default ScansPage;
