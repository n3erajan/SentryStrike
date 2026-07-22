import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Boxes } from "lucide-react";
import { listScans } from "../services/scan.js";

function hostnameOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url || "unknown";
  }
}

function niceName(host) {
  const clean = host.replace(/^www\./, "").split(".")[0];
  return clean ? clean.charAt(0).toUpperCase() + clean.slice(1) : host;
}

function riskBand(score) {
  if (score >= 60) return { cls: "high", label: "High risk" };
  if (score >= 30) return { cls: "medium", label: "Medium" };
  return { cls: "low", label: "Low" };
}

function AppsPage() {
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async (signal) => {
    setLoading(true);
    setError("");
    try {
      const data = await listScans({ limit: 200, signal });
      setScans(Array.isArray(data?.items) ? data.items : []);
    } catch (err) {
      if (err.name !== "AbortError")
        setError(err.message || "Could not load applications.");
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

  const apps = useMemo(() => {
    const byHost = new Map();
    for (const s of scans) {
      if (s.status !== "completed") continue;
      const host = hostnameOf(s.target_url);
      const existing = byHost.get(host);
      const ts = new Date(
        s.completed_at || s.updated_at || s.created_at || 0,
      ).getTime();
      if (!existing || existing.ts < ts) {
        byHost.set(host, {
          host,
          ts,
          id: s.id,
          score: Math.round(s.risk_score || 0),
        });
      }
    }
    return Array.from(byHost.values()).sort((a, b) => b.ts - a.ts);
  }, [scans]);

  return (
    <div className='view'>
      <div className='head'>
        <div>
          <h1>Web applications</h1>
          <p>Track security posture across production and staging.</p>
        </div>
        <button className='btn primary' onClick={() => navigate("/scan")}>
          Add application
        </button>
      </div>

      {loading ? (
        <div className='empty-state'>Loading applications…</div>
      ) : error ? (
        <div className='auth-error'>{error}</div>
      ) : apps.length === 0 ? (
        <div className='empty-state'>
          <Boxes size={30} />
          <h2>No applications yet</h2>
          <p>
            Once you complete an assessment, the target application appears
            here.
          </p>
          <button className='btn primary' onClick={() => navigate("/scan")}>
            New Scan
          </button>
        </div>
      ) : (
        <div className='app-grid'>
          {apps.map((a) => {
            const band = riskBand(a.score);
            return (
              <article key={a.host} className='card'>
                <h2>{niceName(a.host)}</h2>
                <p>{a.host}</p>
                <div className='cardfoot'>
                  <span className={band.cls}>
                    {a.score}/100 {band.label}
                  </span>
                  <Link className='text-btn' to={`/report/${a.id}`}>
                    Reports
                  </Link>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default AppsPage;
