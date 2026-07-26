import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { listScans } from "../services/scan.js";
import { listApplications } from "../services/applications.js";
import { useActiveScans } from "../hooks/useActiveScans.js";
import { useAuth } from "../context/AuthContext.jsx";
import { displayName } from "../components/Sidebar.jsx";

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
  const { scans: active, count } = useActiveScans();
  const [scans, setScans] = useState([]);
  const [appCount, setAppCount] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async (signal) => {
    setLoading(true);
    try {
      const [scanData, appData] = await Promise.all([
        listScans({ limit: 25, signal }),
        listApplications({ limit: 1, signal }),
      ]);
      setScans(Array.isArray(scanData?.items) ? scanData.items : []);
      setAppCount(appData?.total ?? null);
    } catch {
      /* handled quietly on Home */
    } finally {
      if (!signal || !signal.aborted) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    // eslint-disable-next-line react-hooks/set-state-in-effect
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

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

      <div className='summary'>
        <div className='stat'>
          <strong>{loading ? "N/A" : appCount ?? "N/A"}</strong>
          <span>Web applications</span>
        </div>
        <div className='stat'>
          <strong>{count}</strong>
          <span>
            {count === 1 ? "Scan running" : "Scans running"}
          </span>
        </div>
        <div className='stat'>
          <strong>{loading ? "N/A" : highRisk}</strong>
          <span>High-risk findings</span>
        </div>
        <div className='stat'>
          <strong>{loading ? "N/A" : postureLetter(latestPerApp)}</strong>
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
            <h2>Scanning {hostnameOf(runningScan.target_url)}</h2>
            <p>
              {Math.round(runningScan.progress || 0)}% complete.
            </p>
            <div className='cardfoot'>
              <span>{runningScan.phase_message || "Scanning"}</span>
              <Link className='text-btn' to={`/active/${runningScan.id}`}>
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
    </div>
  );
}

export default HomePage;
