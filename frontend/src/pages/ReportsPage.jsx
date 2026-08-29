import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Download, FileBarChart, Search } from "lucide-react";
import { listAllScans } from "../services/scan.js";
import { listAllApplications } from "../services/applications.js";
import { downloadReportPdf } from "../services/reports.js";
import {
  formatAbsolute,
  formatRelative,
  hostnameOf,
  navigableRowProps,
  saveBlob,
  toISOString,
} from "../utils/helpers.js";
import { useToast } from "../components/Toast.jsx";
import { severityClass } from "../data/constants.js";
import { useAuth } from "../context/AuthContext.jsx";
import Tooltip from "../components/Tooltip.jsx";
import Select from "../components/Select.jsx";
import Pagination from "../components/Pagination.jsx";
import { belongsToApplication } from "../utils/reportFilters.js";
import ErrorNotice from "../components/ErrorNotice.jsx";
import useQuery from "../hooks/useQuery.js";
import QuerySwap, { QuerySkeleton, QueryContent } from "../components/QuerySwap.jsx";

const EMPTY_ITEMS = [];
const PAGE_SIZE = 25;

function severityBand(level, score) {
  const lvl = (level || "").toString().toLowerCase();
  if (lvl) return lvl.charAt(0).toUpperCase() + lvl.slice(1);
  if (score >= 75) return "Critical";
  if (score >= 50) return "High";
  if (score >= 25) return "Medium";
  return "Low";
}

function ReportsPage() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const [query, setQuery] = useState("");
  const [applicationId, setApplicationId] = useState("");
  const [page, setPage] = useState(1);
  const [busy, setBusy] = useState("");

  const scansQuery = useQuery({
    queryKey: "scans:list:all",
    queryFn: listAllScans,
    staleTime: 30_000,
  });
  const applicationsQuery = useQuery({
    queryKey: "applications:list:all",
    queryFn: listAllApplications,
  });
  const scanItems = Array.isArray(scansQuery.data?.items)
    ? scansQuery.data.items
    : EMPTY_ITEMS;
  const scans = scanItems.filter((scan) => scan.status === "completed");
  const applications = Array.isArray(applicationsQuery.data?.items)
    ? applicationsQuery.data.items
    : EMPTY_ITEMS;
  const loading = scansQuery.isLoading || applicationsQuery.isLoading;
  const error = scansQuery.error || applicationsQuery.error;
  const hasData = scansQuery.hasData && applicationsQuery.hasData;
  const contentEntered =
    scansQuery.contentEntered || applicationsQuery.contentEntered;

  function refetch() {
    return Promise.allSettled([
      scansQuery.refetch(),
      applicationsQuery.refetch(),
    ]);
  }

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
      .map((s) => {
        const completedAt = s.completed_at || s.started_at || s.created_at;
        return {
          id: s.id,
          target: s.target_url,
          host: s.application_name || s.site_title || hostnameOf(s.target_url),
          // Only surface the crawl mode when it deviates from the default. It
          // read "Full site" on every row before, which cost a line of every
          // row's height to say nothing.
          singlePage: s.crawl_mode === "single",
          completedAt,
          date: formatRelative(completedAt),
          exact: formatAbsolute(completedAt),
          score: Math.round(s.risk_score ?? 0),
          band: severityBand(s.risk_level, Math.round(s.risk_score ?? 0)),
          count: s.total_findings ?? 0,
          analysisStatus: s.analysis?.status || "not_requested",
        };
      })
      .filter((r) => (r.host + r.target).toLowerCase().includes(q));
  }, [scans, applications, query, applicationId]);

  const totalPages = Math.ceil(rows.length / PAGE_SIZE);
  const pageRows = rows.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  async function handleDownload(id) {
    setBusy(id);
    toast("Building PDF", { type: "info" });
    try {
      const blob = await downloadReportPdf(id);
      saveBlob(blob, `sentrystrike-${id}.pdf`);
    } catch (err) {
      toast(err, { type: "error", fallback: "Could not build the PDF." });
    } finally {
      setBusy("");
    }
  }

  return (
    <div className='view'>
      <div className='head'>
        <div>
          <h1>Reports</h1>
          <p>Finished scans with a risk score and a downloadable PDF.</p>
        </div>
      </div>

      <div className='reports-controls'>
        <label className='search'>
          <Search className='ico' />
          <input
            placeholder='Search by name or URL'
            value={query}
            onChange={(e) => { setQuery(e.target.value); setPage(1); }}
          />
        </label>
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
        {!loading && rows.length > 0 && (
          <span className='result-count'>
            {rows.length} {rows.length === 1 ? "report" : "reports"}
          </span>
        )}
      </div>

      {error && hasData && (
        <ErrorNotice
          error={error}
          fallback='Reports may be out of date.'
          onRetry={refetch}
        />
      )}
      <QuerySwap>
      {loading ? (
        <QuerySkeleton
          className='reports-table query-skeleton'
          aria-label='Loading reports'
        >
          <div className='reports-head' aria-hidden='true'>
            <span>Target</span><span>Completed</span><span>Risk</span><span className='num-cell'>Findings</span><span>PDF</span>
          </div>
          {[0, 1, 2, 3].map((item) => (
            <div className='reports-row skeleton-table-row' key={item} aria-hidden='true'>
              <span className='skeleton-target'>
                <span className='skeleton-block skeleton-heading' />
                <span className='skeleton-block skeleton-copy' />
              </span>
              <span className='skeleton-block skeleton-copy' />
              <span className='skeleton-score'>
                <span className='skeleton-block skeleton-copy' />
                <span className='skeleton-block skeleton-pill' />
              </span>
              <span className='skeleton-block skeleton-copy' />
              <span className='skeleton-block skeleton-rowaction' />
            </div>
          ))}
        </QuerySkeleton>
      ) : error && !hasData ? (
        <ErrorNotice key='error' error={error} fallback='Could not load reports.' onRetry={refetch} />
      ) : rows.length === 0 ? (
        <div className='empty-state' key='empty'>
          <FileBarChart size={30} />
          <h2>
            {query
              ? "No reports match that search"
              : applicationId
                ? "No reports for this application"
                : "No reports yet"}
          </h2>
          <p>
            {query
              ? "Try a different name or URL."
              : applicationId
                ? "Completed scans of this app will appear here."
                : "Reports appear here after a scan and its analysis finish."}
          </p>
          {query ? (
            <button className='btn' onClick={() => setQuery("")}>
              Clear search
            </button>
          ) : (
            user?.role !== "viewer" && (
              <button
                className='btn primary'
                onClick={() =>
                  navigate(applicationId ? `/scan?app=${applicationId}` : "/scan")
                }
              >
                New scan
              </button>
            )
          )}
        </div>
      ) : (
        <QueryContent settled={contentEntered} className='reports-table' role='table' aria-label='Reports'>
          <div className='reports-head' role='row'>
            <span role='columnheader'>Target</span>
            <span role='columnheader'>Completed</span>
            <span role='columnheader'>Risk</span>
            <span role='columnheader' className='num-cell'>Findings</span>
            <span role='columnheader'>PDF</span>
          </div>
          {pageRows.map((r) => {
            const analysisReady = r.analysisStatus === "completed";
            return (
            <article
              key={r.id}
              className='reports-row'
              {...navigableRowProps(() =>
                navigate(`/report/${r.id}`, { state: { target: r.target } }),
              )}
            >
              <div className='rep-target' role='cell'>
                <Link
                  className='rowtitle row-link'
                  to={`/report/${r.id}`}
                  state={{ target: r.target }}
                >
                  {r.host}
                </Link>
                <div className='small mono' title={r.target}>{r.target}</div>
                {r.singlePage && <span className='row-tag'>Single page</span>}
              </div>
              <span className='small' role='cell' data-label='Completed'>
                <time dateTime={toISOString(r.completedAt)} title={r.exact}>
                  {r.date}
                </time>
              </span>
              <span className='rep-score' role='cell' data-label='Risk'>
                <b>
                  {r.score}
                  <span>/100</span>
                </b>
                <span className={`sev-tag ${severityClass(r.band)}`}>
                  {r.band}
                </span>
              </span>
              <span className='num-cell' role='cell' data-label='Findings'>{r.count}</span>
              <span className='rowactions' role='cell'>
                <Tooltip
                  label={
                    analysisReady
                      ? "Download PDF"
                      : `PDF ready once AI analysis finishes (${r.analysisStatus.replaceAll("_", " ")})`
                  }
                >
                  <button
                    type='button'
                    aria-label={
                      analysisReady
                        ? `Download PDF for ${r.host}`
                        : `PDF unavailable for ${r.host}: analysis ${r.analysisStatus.replaceAll("_", " ")}`
                    }
                    onClick={() => handleDownload(r.id)}
                    disabled={!analysisReady || busy === r.id}
                  >
                    <Download className='ico' />
                  </button>
                </Tooltip>
              </span>
            </article>
            );
          })}
          <Pagination
            page={page}
            totalPages={totalPages}
            onChange={setPage}
            label='Reports pagination'
          />
        </QueryContent>
      )}
      </QuerySwap>
    </div>
  );
}

export default ReportsPage;
