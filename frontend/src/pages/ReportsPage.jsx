import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Download, FileBarChart, Search } from "lucide-react";
import { listAllScans } from "../services/scan.js";
import { listAllApplications } from "../services/applications.js";
import { downloadReportPdf } from "../services/reports.js";
import { saveBlob } from "../utils/helpers.js";
import { useToast } from "../components/Toast.jsx";
import { severityClass } from "../data/constants.js";
import { useAuth } from "../context/AuthContext.jsx";
import Tooltip from "../components/Tooltip.jsx";
import Select from "../components/Select.jsx";
import { belongsToApplication } from "../utils/reportFilters.js";

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
  if (!iso) return "N/A";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "N/A";
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
  const { user } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const PAGE_SIZE = 25;
  const [scans, setScans] = useState([]);
  const [applications, setApplications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [applicationId, setApplicationId] = useState("");
  const [page, setPage] = useState(1);
  const [busy, setBusy] = useState("");

  const load = useCallback(async (signal) => {
    setLoading(true);
    setError("");
    try {
      const [scanData, applicationData] = await Promise.all([
        listAllScans({ signal }),
        listAllApplications({ signal }),
      ]);
      const items = Array.isArray(scanData?.items) ? scanData.items : [];
      setScans(items.filter((s) => s.status === "completed"));
      setApplications(
        Array.isArray(applicationData?.items) ? applicationData.items : [],
      );
    } catch (err) {
      if (err.name !== "AbortError")
        setError(err.message || "Could not load reports.");
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

  const rows = useMemo(() => {
    const q = query.toLowerCase();
    const selectedApplication = applications.find(
      (application) => application.id === applicationId,
    );
    return scans
      .filter(
        (scan) =>
          !applicationId || belongsToApplication(scan, selectedApplication),
      )
      .map((s) => ({
        id: s.id,
        target: s.target_url,
        host: s.site_title || hostnameOf(s.target_url),
        crawl: crawlLabel(s.crawl_mode),
        date: formatDate(s.started_at || s.created_at),
        score: Math.round(s.risk_score ?? 0),
        band: severityBand(s.risk_level, Math.round(s.risk_score ?? 0)),
        count: s.total_findings ?? 0,
        analysisStatus: s.analysis?.status || "not_requested",
      }))
      .filter((r) => (r.host + r.target).toLowerCase().includes(q));
  }, [scans, applications, query, applicationId]);

  const totalPages = Math.ceil(rows.length / PAGE_SIZE);
  const pageRows = rows.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  async function handleDownload(id) {
    setBusy(id);
    toast("Building PDF");
    try {
      const blob = await downloadReportPdf(id);
      saveBlob(blob, `sentrystrike-${id}.pdf`);
    } catch (err) {
      toast(err.message || "Could not build the PDF.");
    } finally {
      setBusy("");
    }
  }

  return (
    <div className='view'>
      <div className='head'>
        <div>
          <h1>Reports</h1>
        </div>
      </div>

      <div className='reports-controls'>
        <label className='search'>
          <Search className='ico' />
          <input
            placeholder='Search reports'
            value={query}
            onChange={(e) => { setQuery(e.target.value); setPage(1); }}
          />
        </label>
        {applications.length > 0 && (
          <div className='reports-app-filter'>
            <Select
              value={applicationId}
              onChange={(id) => { setApplicationId(id); setPage(1); }}
              ariaLabel='Filter reports by web application'
              options={[
                { value: "", label: "All reports" },
                ...applications.map((application) => ({
                  value: application.id,
                  label: application.name,
                })),
              ]}
            />
          </div>
        )}
      </div>

      {loading ? (
        <div className='empty-state'>Loading reports…</div>
      ) : error ? (
        <div className='auth-error'>{error}</div>
      ) : rows.length === 0 && !loading ? (
        <div className='empty-state'>
          <FileBarChart size={30} />
          <h2>
            {applicationId ? "No reports for this application" : "No reports yet"}
          </h2>
          <p>
            {applicationId
              ? "Completed scans of this app will appear here."
              : "Reports appear here after a scan and its analysis finish."}
          </p>
          {user?.role !== "viewer" && <button
            className='btn primary'
            onClick={() =>
              navigate(applicationId ? `/scan?app=${applicationId}` : "/scan")
            }
          >
            New scan
          </button>}
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
          {pageRows.map((r) => (
            <article
              key={r.id}
              className='reports-row'
              onClick={() =>
                navigate(`/report/${r.id}`, { state: { target: r.target } })
              }
            >
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
                <Tooltip label={r.analysisStatus !== "completed" ? `AI analysis: ${r.analysisStatus.replaceAll("_", " ")}` : "Download PDF"}>
                  <button
                    type='button'
                    aria-label='Download PDF'
                    onClick={(e) => {
                      e.stopPropagation();
                      if (r.analysisStatus === "completed") handleDownload(r.id);
                    }}
                    disabled={busy === r.id}
                    aria-disabled={r.analysisStatus !== "completed"}
                  >
                    <Download className='ico' />
                  </button>
                </Tooltip>
              </span>
            </article>
          ))}
        </div>
      )}
      {totalPages > 1 && (
        <div className='pagination'>
          <button className='btn page-btn' disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
            ‹ Prev
          </button>
          {pages(page, totalPages).map((p, i) =>
            p === "…" ? (
              <span key={`ellipsis-${i}`} className='page-ellipsis'>…</span>
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
          <button className='btn page-btn' disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
            Next ›
          </button>
        </div>
      )}
    </div>
  );
}

export default ReportsPage;
