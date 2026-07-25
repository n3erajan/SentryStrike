import { useCallback, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { FileBarChart, Plus } from "lucide-react";
import {
  getApplication,
  listApplicationScans,
} from "../services/applications.js";
import { severityClass } from "../data/constants.js";
import { useAuth } from "../context/AuthContext.jsx";

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
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
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
  const [app, setApp] = useState(null);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(
    async (signal) => {
      setLoading(true);
      setError("");
      try {
        const [appData, scanData] = await Promise.all([
          getApplication(appId, signal),
          listApplicationScans(appId, { signal }),
        ]);
        setApp(appData);
        setScans(Array.isArray(scanData?.items) ? scanData.items : []);
      } catch (err) {
        if (err.name !== "AbortError")
          setError(err.message || "Could not load this application.");
      } finally {
        if (!signal || !signal.aborted) setLoading(false);
      }
    },
    [appId],
  );

  useEffect(() => {
    const controller = new AbortController();
    // eslint-disable-next-line react-hooks/set-state-in-effect
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  if (loading)
    return (
      <div className='view'>
        <div className='empty-state'>Loading application…</div>
      </div>
    );
  if (error)
    return (
      <div className='view'>
        <button className='back' onClick={() => navigate("/apps")}>
          ← All applications
        </button>
        <div className='auth-error'>{error}</div>
      </div>
    );
  if (!app) return null;

  return (
    <div className='view'>
      <button className='back' onClick={() => navigate("/apps")}>
        ← All applications
      </button>
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
          <h2>No scans recorded for this application</h2>
          <p>
            Scans are matched to an application by their exact target URL, so
            assessments started from a different URL for the same site will not
            appear here. Start a scan from this page to keep it linked.
          </p>
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
                    <span className='small'>—</span>
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
