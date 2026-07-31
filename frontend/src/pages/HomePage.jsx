import { Link } from "react-router-dom";
import { listApplications } from "../services/applications.js";
import { useActiveScans } from "../hooks/useActiveScans.js";
import useQuery from "../hooks/useQuery.js";
import { useAuth } from "../context/AuthContext.jsx";
import { displayName } from "../components/Sidebar.jsx";
import QuerySwap, { QuerySkeleton, QueryContent } from "../components/QuerySwap.jsx";

function greeting() {
  const hour = new Date().getHours();
  if (hour < 12) return "Good morning";
  if (hour < 18) return "Good afternoon";
  return "Good evening";
}

function postureLetter(scans) {
  if (!scans.length) return "N/A";
  const avg =
    scans.reduce((sum, s) => sum + (s.risk_score || 0), 0) / scans.length;
  if (avg >= 80) return "D";
  if (avg >= 60) return "C";
  if (avg >= 40) return "B";
  if (avg >= 20) return "A-";
  return "A";
}

function hostnameOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function HomePage() {
  const { user } = useAuth();
  const {
    scans: active,
    allScans: scans,
    count,
    loading: scansLoading,
    contentEntered: scansContentEntered,
  } = useActiveScans();
  const applicationsQuery = useQuery({
    queryKey: "applications:list:count",
    queryFn: () => listApplications({ limit: 1 }),
  });
  const appCount = applicationsQuery.data?.total ?? null;
  const loading = scansLoading || applicationsQuery.isLoading;
  const contentEntered =
    scansContentEntered || applicationsQuery.contentEntered;

  const completed = scans.filter((s) => s.status === "completed");
  const latestPerApp = Object.values(
    completed.reduce((map, s) => {
      const key = s.application_id || s.target_url;
      if (!map[key] || new Date(s.created_at) > new Date(map[key].created_at))
        map[key] = s;
      return map;
    }, {}),
  );
  const highRisk = latestPerApp.reduce(
    (sum, s) =>
      sum +
      ((s.severity_breakdown?.critical ?? 0) +
        (s.severity_breakdown?.high ?? 0)),
    0,
  );
  const latestCompleted = completed[0];
  const runningScan = active[0];

  return (
    <div className='view'>
      <div className='head'>
        <div>
          <h1>
            {greeting()}, {displayName(user).split(" ")[0]}
          </h1>
          <p>Your apps, scans, and latest results.</p>
        </div>
      </div>

      <QuerySwap>
      {loading ? (
        <QuerySkeleton key='skeleton' aria-label='Loading workspace overview'>
          <div className='summary query-skeleton'>
            {["Web applications", "Scans running", "High-risk findings", "Workspace grade"].map(
              (label) => (
                <div className='stat' key={label}>
                  <strong><span className='skeleton-block skeleton-value' /></strong>
                  <span>{label}</span>
                </div>
              ),
            )}
          </div>
          <div className='app-grid query-skeleton' aria-hidden='true'>
            {[0, 1, 2].map((item) => (
              <article className='card skeleton-card' key={item}>
                <span className='skeleton-block skeleton-heading' />
                <span className='skeleton-block skeleton-copy' />
                <div className='skeleton-cardfoot'>
                  <span className='skeleton-block skeleton-action' />
                </div>
              </article>
            ))}
          </div>
        </QuerySkeleton>
      ) : (
        <QueryContent settled={contentEntered}>
      <div className='summary'>
        <div className='stat'>
          <strong>{appCount ?? "N/A"}</strong>
          <span>Web applications</span>
        </div>
        <div className='stat'>
          <strong>{count}</strong>
          <span>
            {count === 1 ? "Scan running" : "Scans running"}
          </span>
        </div>
        <div className='stat'>
          <strong>{highRisk}</strong>
          <span>High-risk findings</span>
        </div>
        <div className='stat'>
          <strong>{postureLetter(latestPerApp)}</strong>
          <span>Workspace grade</span>
        </div>
      </div>

      <div className='app-grid'>
        {latestCompleted && (
          <article className='card'>
            <h2>{latestCompleted.application_name || latestCompleted.site_title || hostnameOf(latestCompleted.target_url)} report ready</h2>
            <p>
              {Math.round(latestCompleted.risk_score || 0)}/100 · Review the
              findings and fix status.
            </p>
            <div className='cardfoot'>
              <span
                className={
                  Math.round(latestCompleted.risk_score || 0) >= 60
                    ? "high"
                    : Math.round(latestCompleted.risk_score || 0) >= 30
                      ? "medium"
                      : "low"
                }
              >
                {Math.round(latestCompleted.risk_score || 0) >= 60
                  ? "High risk"
                  : Math.round(latestCompleted.risk_score || 0) >= 30
                    ? "Medium"
                    : "Low"}
              </span>
              <Link className='text-btn' to={`/report/${latestCompleted.id}`}>
                Open report
              </Link>
            </div>
          </article>
        )}
        {runningScan && (
          <article className='card'>
            <h2>
              Scanning{" "}
              {runningScan.application_name ||
                runningScan.site_title ||
                hostnameOf(runningScan.target_url)}
            </h2>
            <p>
              {Math.round(runningScan.progress || 0)}% complete.
            </p>
            <div className='cardfoot'>
              <span>{runningScan.phase_message || "Scanning"}</span>
              <Link className='text-btn' to={`/scans/${runningScan.id}`}>
                View progress
              </Link>
            </div>
          </article>
        )}
        <article className='card'>
          <h2>Scan another app</h2>
          <p>Choose a saved app or enter a new target URL.</p>
          <div className='cardfoot'>
            <span>Authorized targets only</span>
            <Link className='text-btn' to='/scan'>
              New scan
            </Link>
          </div>
        </article>
      </div>
        </QueryContent>
      )}
      </QuerySwap>
    </div>
  );
}

export default HomePage;
