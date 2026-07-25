import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Download, FileBarChart, Search } from "lucide-react";
import { listAllScans } from "../services/scan.js";
import { listApplications } from "../services/applications.js";
import { downloadReportPdf } from "../services/reports.js";
import { saveBlob } from "../utils/helpers.js";
import { useToast } from "../components/Toast.jsx";
import { severityClass } from "../data/constants.js";
import { useAuth } from "../context/AuthContext.jsx";
import Tooltip from "../components/Tooltip.jsx";
import Select from "../components/Select.jsx";
import { belongsToApplication } from "../utils/reportFilters.js";

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
  const { user } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const [scans, setScans] = useState([]);
  const [applications, setApplications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [applicationId, setApplicationId] = useState("");
  const [busy, setBusy] = useState("");

  const load = useCallback(async (signal) => {
    setLoading(true);
    setError("");
    try {
      const [scanData, applicationData] = await Promise.all([
        listAllScans({ signal }),
        listApplications({ limit: 100, signal }),
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
        host: hostnameOf(s.target_url),
        crawl: crawlLabel(s.crawl_mode),
        date: formatDate(s.started_at || s.created_at),
        score: Math.round(s.risk_score ?? 0),
        band: severityBand(s.risk_level, Math.round(s.risk_score ?? 0)),
        count: s.total_findings ?? s.finding_count ?? 0,
        analysisStatus: s.analysis?.status || "not_requested",
      }))
      .filter((r) => (r.host + r.target).toLowerCase().includes(q));
  }, [scans, applications, query, applicationId]);

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

      <div className='reports-controls'>
        <label className='search'>
          <Search className='ico' />
          <input
            placeholder='Search reports'
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </label>
        {applications.length > 0 && (
          <div className='reports-app-filter'>
            <Select
              value={applicationId}
              onChange={setApplicationId}
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
      ) : rows.length === 0 ? (
        <div className='empty-state'>
          <FileBarChart size={30} />
          <h2>
            {applicationId ? "No reports for this application" : "No reports yet"}
          </h2>
          <p>
            {applicationId
              ? "Completed assessments for this web application will appear here."
              : "Reports appear here after an assessment completes."}
          </p>
          {user?.role !== "viewer" && <button
            className='btn primary'
            onClick={() =>
              navigate(applicationId ? `/scan?app=${applicationId}` : "/scan")
            }
          >
            New Scan
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
          {rows.map((r) => (
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
    </div>
  );
}

export default ReportsPage;
