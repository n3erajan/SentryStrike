import { useNavigate, useParams } from "react-router-dom";
import { FileBarChart, Plus } from "lucide-react";
import {
  getApplication,
  listAllApplicationScans,
} from "../services/applications.js";
import { severityClass } from "../data/constants.js";
import { useAuth } from "../context/AuthContext.jsx";
import ErrorNotice from "../components/ErrorNotice.jsx";
import useQuery from "../hooks/useQuery.js";

const ACTIVE_STATUSES = new Set(["queued", "running"]);

function severityBand(level, score) {
  const lvl = (level || "").toString().toLowerCase();
  if (lvl) return lvl.charAt(0).toUpperCase() + lvl.slice(1);
  if (score >= 75) return "Critical";
  if (score >= 50) return "High";
  if (score >= 25) return "Medium";
  return "Low";
}

function formatDate(iso) {
  if (!iso) return "N/A";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "N/A";
  return d.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function ApplicationPage() {
  const { user } = useAuth();
  const { appId } = useParams();
  const navigate = useNavigate();
  const applicationQuery = useQuery({
    queryKey: `applications:detail:${appId}`,
    queryFn: () => getApplication(appId),
  });
  const scansQuery = useQuery({
    queryKey: `applications:scans:${appId}`,
    queryFn: () => listAllApplicationScans(appId),
    staleTime: 30_000,
  });
  const app = applicationQuery.data;
  const scans = Array.isArray(scansQuery.data?.items)
    ? scansQuery.data.items
    : [];
  const loading = applicationQuery.isLoading || scansQuery.isLoading;
  const error = applicationQuery.error || scansQuery.error;
  const hasData = applicationQuery.hasData && scansQuery.hasData;
  const contentEntered =
    applicationQuery.isFetchedAfterMount || scansQuery.isFetchedAfterMount;

  function refetch() {
    return Promise.allSettled([
      applicationQuery.refetch(),
      scansQuery.refetch(),
    ]);
  }

  if (loading)
    return (
      <div className='view'>
        <div className='app-detail-skeleton query-skeleton' role='status' aria-label='Loading application'>
          <span className='skeleton-block skeleton-heading' />
          <span className='skeleton-block skeleton-copy' />
          <div className='summary' aria-hidden='true'>
            {[0, 1, 2].map((item) => <div className='stat' key={item}><strong><span className='skeleton-block skeleton-value' /></strong><span className='skeleton-block skeleton-copy' /></div>)}
          </div>
        </div>
      </div>
    );
  if (error && !hasData)
    return (
      <div className='view'>
        <button className='back' onClick={() => navigate("/apps")}>
          ← All applications
        </button>
        <ErrorNotice error={error} fallback='Could not load this application.' onRetry={refetch} />
      </div>
    );
  if (!app) return null;

  return (
    <div className={`view${contentEntered ? " query-content-enter" : ""}`}>
      <button className='back' onClick={() => navigate("/apps")}>
        ← All applications
      </button>
      {error && (
        <ErrorNotice
          error={error}
          fallback='Application data may be out of date.'
          onRetry={refetch}
        />
      )}
      <div className='head'>
        <div>
          <h1>{app.name}</h1>
          <p className='mono' style={{ wordBreak: "break-all" }}>
            {app.target_url}
          </p>
        </div>
        {user?.role !== "viewer" && (
          <button
            className='btn primary'
            onClick={() => navigate(`/scan?app=${app.id}`)}
          >
            <Plus className='ico' />
            New scan
          </button>
        )}
      </div>

      {scans.length === 0 ? (
        <div className='empty-state'>
          <FileBarChart size={30} />
          <h2>No scans yet</h2>
          <p>Start a scan to build this app's history.</p>
          {user?.role !== "viewer" && (
            <button
              className='btn primary'
              onClick={() => navigate(`/scan?app=${app.id}`)}
            >
              <Plus className='ico' />
              New scan
            </button>
          )}
        </div>
      ) : (
        <div className='reports-table'>
          <div className='reports-head'>
            <span>Target</span>
            <span>Started</span>
            <span>Score</span>
            <span>Status</span>
            <span></span>
          </div>
          {scans.map((s) => {
            const score = Math.round(s.overall_risk_score ?? 0);
            const band = severityBand(s.overall_risk_level, score);
            const active = ACTIVE_STATUSES.has(s.status);
            return (
              <article
                key={s.id}
                className='reports-row'
                onClick={() =>
                  navigate(active ? `/active/${s.id}` : `/report/${s.id}`, {
                    state: { target: s.target_url },
                  })
                }
              >
                <div className='rep-target'>
                  <div className='rowtitle'>{s.target_url}</div>
                  <div className='small'>
                    {s.crawl_mode === "single" ? "Single page" : "Full site"}
                  </div>
                </div>
                <span>{formatDate(s.created_at)}</span>
                <span className='rep-score'>
                  {s.status === "completed" ? (
                    <>
                      <b className={severityClass(band)}>{score}/100</b>
                      <span className={`sev-tag ${severityClass(band)}`}>
                        {band}
                      </span>
                    </>
                  ) : (
                    <span className='small'>N/A</span>
                  )}
                </span>
                <span className={`status-pill ${s.status}`}>{s.status}</span>
                <span className='small'>
                  {active
                    ? `${Math.round(s.progress || 0)}% · ${s.phase_message || "Scanning"}`
                    : ""}
                </span>
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default ApplicationPage;
