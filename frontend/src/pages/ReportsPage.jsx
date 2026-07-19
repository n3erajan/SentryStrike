import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowUpRight, Download, FileBarChart, Search } from "lucide-react";
import { listScans } from "../services/scan.js";
import { downloadReportPdf } from "../services/reports.js";
import { saveBlob } from "../utils/helpers.js";
import { useToast } from "../components/Toast.jsx";
import { severityClass } from "../data/constants.js";

function severityBand(level, score) {
  const lvl = (level || "").toString().toLowerCase();
  if (lvl) return lvl.charAt(0).toUpperCase() + lvl.slice(1);
  if (score >= 75) return "Critical";
  if (score >= 50) return "High";
  if (score >= 25) return "Medium";
  return "Low";
}

function crawlLabel(mode) {
  return mode === "single" ? "Single page" : "Full site";
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

function hostnameOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url || "unknown";
  }
}

function ReportsPage() {
  const navigate = useNavigate();
  const toast = useToast();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState("");

  const load = useCallback(async (signal) => {
    setLoading(true);
    setError("");
    try {
      const data = await listScans({ limit: 100, signal });
      const items = Array.isArray(data?.items) ? data.items : [];
      setScans(items.filter((s) => s.status === "completed"));
    } catch (err) {
      if (err.name !== "AbortError")
        setError(err.message || "Could not load reports.");
    } finally {
      if (!signal || !signal.aborted) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const rows = useMemo(() => {
    const q = query.toLowerCase();
    return scans
      .map((s) => ({
        id: s.id,
        target: s.target_url,
        host: hostnameOf(s.target_url),
        crawl: crawlLabel(s.crawl_mode),
        date: formatDate(s.started_at || s.created_at),
        score: Math.round(s.risk_score ?? 0),
        band: severityBand(s.risk_level, Math.round(s.risk_score ?? 0)),
        count: s.total_findings ?? s.finding_count ?? 0,
      }))
      .filter((r) => (r.host + r.target).toLowerCase().includes(q));
  }, [scans, query]);

  async function handleDownload(id) {
    setBusy(id);
    toast("PDF generation started");
    try {
      const blob = await downloadReportPdf(id);
      saveBlob(blob, `sentrystrike-${id}.pdf`);
    } catch (err) {
      toast(err.message || "PDF failed");
    } finally {
      setBusy("");
    }
  }

  return (
    <div className='view'>
      <div className='head'>
        <div>
          <h1>Assessment reports</h1>
        </div>
      </div>

      <label className='search'>
        <Search className='ico' />
        <input
          placeholder='Search reports'
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </label>

      {loading ? (
        <div className='empty-state'>Loading reports…</div>
      ) : error ? (
        <div className='auth-error'>{error}</div>
      ) : rows.length === 0 ? (
        <div className='empty-state'>
          <FileBarChart size={30} />
          <h2>No reports yet</h2>
          <p>Reports appear here after an assessment completes.</p>
          <button
            className='btn primary'
            onClick={() => navigate("/scan")}
          >
            New Scan
          </button>
        </div>
      ) : (
        <div className='reports-table'>
          <div className='reports-head'>
            <span>Target</span>
            <span>Started</span>
            <span>Score</span>
            <span>Findings</span>
            <span>Report</span>
          </div>
          {rows.map((r) => (
            <article key={r.id} className='reports-row'>
              <div className='rep-target'>
                <div className='rowtitle'>{r.host}</div>
                <div className='small mono'>{r.target}</div>
                <div className='small'>{r.crawl}</div>
              </div>
              <span>{r.date}</span>
              <span className='rep-score'>
                <b className={severityClass(r.band)}>{r.score}/100</b>
                <span className={`sev-tag ${severityClass(r.band)}`}>
                  {r.band}
                </span>
              </span>
              <span>{r.count} findings</span>
              <span className='rowactions'>
                <button
                  type='button'
                  aria-label='Download PDF'
                  onClick={() => handleDownload(r.id)}
                  disabled={busy === r.id}
                >
                  <Download className='ico' />
                </button>
                <button
                  type='button'
                  className='btn'
                  onClick={() =>
                    navigate(`/report/${r.id}`, { state: { target: r.target } })
                  }
                >
                  <ArrowUpRight className='ico' />
                </button>
              </span>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}

export default ReportsPage;
