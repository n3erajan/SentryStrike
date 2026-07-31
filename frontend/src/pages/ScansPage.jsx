import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { useActiveScans } from "../hooks/useActiveScans.js";
import { listAllScans } from "../services/scan.js";
import { useAuth } from "../context/AuthContext.jsx";
import ErrorNotice from "../components/ErrorNotice.jsx";
import { parseUTCDate } from "../utils/helpers.js";
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

function formatRelative(iso) {
  const d = parseUTCDate(iso);
  if (!d) return "-";
  const diff = Math.max(0, Date.now() - d.getTime());
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function hostnameOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url || "unknown";
  }
}

function pages(current, total) {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  const always = [1, total];
  const around = [current - 1, current, current + 1].filter(
    (p) => p > 1 && p < total,
  );
  const set = new Set([...always, ...around]);
  const result = [];
  let prev = 0;
  for (const p of [...set].sort((a, b) => a - b)) {
    if (p - prev > 1) result.push("…");
    result.push(p);
    prev = p;
  }
  return result;
}

function ScansPage() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const { count } = useActiveScans();
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

  const allItems = useMemo(
    () => (Array.isArray(data?.items) ? data.items : []),
    [data],
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

  function handleRowClick(scan) {
    navigate(`/scans/${scan.id}`, {
      state: { target: scan.target_url },
    });
  }

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
        </div>
      </div>

      <div className='reports-controls'>
        {FILTERS.map((f) => (
          <button
            key={f.value}
            className={`btn${statusFilter === f.value ? " primary" : ""}`}
            style={{ minHeight: 36, fontSize: "0.72rem", paddingInline: 12 }}
            onClick={() => { setStatusFilter(f.value); setPage(1); }}
          >
            {f.label}
          </button>
        ))}
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
                ? `No scans have status "${statusFilter}".`
                : "Scans appear here once you start them."}
            </p>
            {!statusFilter && user?.role !== "viewer" && (
              <button
                className='btn primary'
                onClick={() => navigate("/scan")}
              >
                New scan
              </button>
            )}
          </div>
        ) : (
          <QueryContent settled={contentEntered} className='scans-table'>
          <div className='scans-head'>
            <span>Target</span>
            <span>Status</span>
            <span>Progress</span>
            <span>Phase</span>
            <span>Started</span>
          </div>
          {items.map((scan) => {
            const analysisPending =
              scan.status === "completed" &&
              ["queued", "running"].includes(scan.analysis?.status);
            const displayStatus = analysisPending ? "incomplete" : scan.status;
            const statusLabel =
              scan.status === "queued"
                ? "Queued"
                : scan.status === "running"
                  ? "Scanning"
                  : scan.status === "completed"
                    ? "Complete"
                    : scan.status === "failed"
                      ? "Failed"
                      : scan.status === "cancelled"
                        ? "Cancelled"
                        : scan.status;
            const displayPhase = analysisPending
              ? "AI analysis"
              : scan.phase_message || statusLabel;

            return (
              <article
                key={scan.id}
                className='scans-row'
                onClick={() => handleRowClick(scan)}
              >
                <div className='rep-target'>
                  <div className='rowtitle'>
                    {scan.application_name ||
                      scan.site_title ||
                      hostnameOf(scan.target_url)}
                  </div>
                  <div className='small mono'>{scan.target_url}</div>
                  <div className='small'>
                    {scan.crawl_mode === "single" ? "Single page" : "Full site"}
                  </div>
                </div>
                <span className={`status-pill ${displayStatus}`}>
                  {statusLabel}
                </span>
                <span>{Math.round(scan.progress || 0)}%</span>
                <span className='small'>{displayPhase}</span>
                <span className='small'>
                  {formatRelative(scan.started_at || scan.created_at)}
                </span>
              </article>
            );
          })}
          {totalPages > 1 && (
            <div className='pagination'>
              <button
                className='btn page-btn'
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
              >
                ‹ Prev
              </button>
              {pages(page, totalPages).map((p, i) =>
                p === "…" ? (
                  <span key={`ellipsis-${i}`} className='page-ellipsis'>
                    …
                  </span>
                ) : (
                  <button
                    key={p}
                    className={`btn page-btn${p === page ? " active" : ""}`}
                    onClick={() => setPage(p)}
                  >
                    {p}
                  </button>
                ),
              )}
              <button
                className='btn page-btn'
                disabled={page >= totalPages}
                onClick={() => setPage((p) => p + 1)}
              >
                Next ›
              </button>
            </div>
          )}
          </QueryContent>
        )}
      </QuerySwap>
    </div>
  );
}

export default ScansPage;
