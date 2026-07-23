import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { listScans } from "../services/scan.js";
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
  if (!scans.length) return "—";
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
  const [loading, setLoading] = useState(true);

  const load = useCallback(async (signal) => {
    setLoading(true);
    try {
      const data = await listScans({ limit: 25, signal });
      setScans(Array.isArray(data?.items) ? data.items : []);
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
  const apps = new Set(completed.map((s) => hostnameOf(s.target_url))).size;
  const highRisk = completed.reduce(
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
          <p>Security posture across your web applications.</p>
        </div>
      </div>

      <div className='summary'>
        <div className='stat'>
          <strong>{loading ? "—" : apps}</strong>
          <span>Web applications</span>
        </div>
        <div className='stat'>
          <strong>{count}</strong>
          <span>
            {count === 1 ? "Assessment running" : "Assessments running"}
          </span>
        </div>
        <div className='stat'>
          <strong>{loading ? "—" : highRisk}</strong>
          <span>High-risk findings</span>
        </div>
        <div className='stat'>
          <strong>{loading ? "—" : postureLetter(completed)}</strong>
          <span>Workspace Security posture</span>
        </div>
      </div>

      <div className='app-grid'>
        {latestCompleted && (
          <article className='card'>
            <h2>{hostnameOf(latestCompleted.target_url)} report ready</h2>
            <p>
              {Math.round(latestCompleted.risk_score || 0)}/100 · review
              verified findings and remediation.
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
            <h2>{hostnameOf(runningScan.target_url)} assessment running</h2>
            <p>
              Security testing is {Math.round(runningScan.progress || 0)}%
              complete.
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
          <h2>Assess another application</h2>
          <p>Run an OWASP Top 10 2025 VAPT assessment.</p>
          <div className='cardfoot'>
            <span>Ready when you are</span>
            <Link className='text-btn' to='/scan'>
              Start now
            </Link>
          </div>
        </article>
      </div>
    </div>
  );
}

export default HomePage;
