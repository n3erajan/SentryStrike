import { useCallback, useEffect, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import { ChevronDown, Download, FileText } from "lucide-react";
import { downloadReportPdf, getReport } from "../services/reports.js";
import { downloadFile, saveBlob } from "../utils/helpers.js";
import { SEVERITIES, SEVERITY_META } from "../data/constants.js";
import { useToast } from "../components/Toast.jsx";

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function sevKey(v) {
  return (v || "").toString().toLowerCase();
}

function riskLine(score) {
  if (score >= 75) return "Critical risk. Fix immediately before release.";
  if (score >= 50) return "High risk. Fix critical issues before release.";
  if (score >= 25) return "Medium risk. Plan remediation next sprint.";
  return "Low risk. Monitor for regressions.";
}

function formatDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? "—"
    : d.toLocaleDateString(undefined, {
        month: "short",
        day: "numeric",
        year: "numeric",
      });
}

// Full date + time for the report header (the scan timestamp).
function formatDateTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? "—"
    : d.toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
}

function crawlLabel(mode) {
  return mode === "single" ? "Single page" : "Full site";
}

function severityBand(score) {
  if (score >= 75) return "Critical";
  if (score >= 50) return "High";
  if (score >= 25) return "Medium";
  return "Low";
}

function sevTagClass(severity) {
  const s = sevKey(severity);
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "high";
}

function titleCase(value) {
  const s = (value || "").toString().replace(/[_-]+/g, " ").trim();
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : "—";
}

function hostnameOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url || "Report";
  }
}

// A single finding row that expands to reveal the full backend detail:
// location, CVSS vector, evidence snippets, and the AI analysis block.
function Finding({ v }) {
  const [open, setOpen] = useState(false);
  const loc = v.location || {};
  const ev = v.evidence || {};
  const ai = v.ai_analysis || {};
  const cvss = Number.isFinite(v.cvss_score) ? v.cvss_score.toFixed(1) : "—";
  const url = loc.url || "";
  const params =
    loc.parameters && loc.parameters.length
      ? loc.parameters.join(", ")
      : loc.parameter || "";

  return (
    <article className={`finding${open ? " open" : ""}`}>
      <button
        type='button'
        className='finding-head'
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
      >
        <span className={`sev-dot ${sevTagClass(v.severity)}`} />
        <div className='finding-title'>
          <div className='rowtitle'>{titleCase(v.vuln_type)}</div>
          <div className='small mono'>{url}</div>
        </div>
        <span className='finding-cat small'>{v.category}</span>
        <span className={`sev-tag ${sevTagClass(v.severity)}`}>
          {SEVERITY_META[sevKey(v.severity)]?.label || v.severity}
        </span>
        <span className='finding-cvss mono'>{cvss}</span>
        <ChevronDown className='ico chev' />
      </button>
      {open && (
        <div className='finding-body'>
          <div className='kv-grid'>
            <div className='kv-cell'>
              <span>HTTP method</span>
              <b>{loc.http_method || "GET"}</b>
            </div>
            {params && (
              <div className='kv-cell'>
                <span>Parameter(s)</span>
                <b className='mono'>{params}</b>
              </div>
            )}
            <div className='kv-cell'>
              <span>Evidence strength</span>
              <b>{titleCase(v.evidence_strength || ev.evidence_strength)}</b>
            </div>
            <div className='kv-cell'>
              <span>Review status</span>
              <b>{titleCase(v.review_status)}</b>
            </div>
            <div className='kv-cell'>
              <span>Auth context</span>
              <b>{titleCase(v.auth_context || ev.auth_context)}</b>
            </div>
            {ev.confidence_score > 0 && (
              <div className='kv-cell'>
                <span>Confidence</span>
                <b>{Math.round(ev.confidence_score)}%</b>
              </div>
            )}
            {ai.exploitability && (
              <div className='kv-cell'>
                <span>Exploitability</span>
                <b>{ai.exploitability}</b>
              </div>
            )}
          </div>

          {v.cvss_vector && (
            <p className='small mono' style={{ marginTop: 12 }}>
              {v.cvss_vector}
            </p>
          )}

          {ev.payload && (
            <div className='finding-block'>
              <h4>Payload</h4>
              <pre>{ev.payload}</pre>
            </div>
          )}
          {ev.request_snippet && (
            <div className='finding-block'>
              <h4>Request</h4>
              <pre>{ev.request_snippet}</pre>
            </div>
          )}
          {ev.response_snippet && (
            <div className='finding-block'>
              <h4>Response</h4>
              <pre>{ev.response_snippet}</pre>
            </div>
          )}

          {ai.business_impact && (
            <div className='finding-block'>
              <h4>Business impact</h4>
              <p>{ai.business_impact}</p>
            </div>
          )}
          {ai.remediation && (
            <div className='finding-block'>
              <h4>Remediation</h4>
              <p>{ai.remediation}</p>
            </div>
          )}
        </div>
      )}
    </article>
  );
}

function ReportPage() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const target = location.state?.target || "";
  const toast = useToast();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("all");
  const [busy, setBusy] = useState("");

  const load = useCallback(
    async (signal) => {
      setLoading(true);
      setError("");
      try {
        setReport(await getReport(scanId, signal));
      } catch (err) {
        if (err.name !== "AbortError")
          setError(err.message || "Could not load the report.");
      } finally {
        if (!signal || !signal.aborted) setLoading(false);
      }
    },
    [scanId],
  );

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const handleJson = useCallback(() => {
    if (report)
      downloadFile(
        JSON.stringify(report, null, 2),
        `sentrystrike-${scanId}.json`,
        "application/json",
      );
  }, [report, scanId]);

  const handlePdf = useCallback(async () => {
    setBusy("pdf");
    toast("PDF generation started");
    try {
      saveBlob(await downloadReportPdf(scanId), `sentrystrike-${scanId}.pdf`);
    } catch (err) {
      toast(err.message || "Could not download the PDF.");
    } finally {
      setBusy("");
    }
  }, [scanId, toast]);

  if (loading)
    return (
      <div className='view'>
        <div className='empty-state'>Loading report…</div>
      </div>
    );
  if (error)
    return (
      <div className='view'>
        <button className='back' onClick={() => navigate("/reports")}>
          ← All reports
        </button>
        <div className='auth-error'>{error}</div>
      </div>
    );
  if (!report) return null;

  const stats = report.statistics || {};
  const breakdown = stats.severity_breakdown || {};
  const vulns = (report.vulnerabilities || [])
    .slice()
    .sort(
      (a, b) =>
        (SEV_ORDER[sevKey(a.severity)] ?? 9) -
          (SEV_ORDER[sevKey(b.severity)] ?? 9) ||
        (b.cvss_score || 0) - (a.cvss_score || 0),
    );
  const filtered =
    filter === "all"
      ? vulns
      : vulns.filter((v) => sevKey(v.severity) === filter);
  const score = Math.round(report.risk_score || 0);
  const targetUrl = report.target_url || target || "";
  const targetHost = hostnameOf(targetUrl);
  const scanTime =
    report.started_at || report.completed_at || report.generated_at;
  const tech = report.technology_stack || [];
  const authCov = report.auth_coverage || {};
  const spaCov = report.spa_api_coverage || {};
  const evidence = report.evidence_strength_breakdown || {};
  const chains = report.attack_chains || [];
  const limitations = report.scanner_limitations || [];
  const coverage =
    report.coverage_summary?.overall_coverage_pct ??
    report.report_metadata?.coverage_percent;
  const coverageStr = Number.isFinite(coverage)
    ? `${Math.round(coverage)}%`
    : "—";

  return (
    <div className='view'>
      <button className='back' onClick={() => navigate("/reports")}>
        ← All reports
      </button>
      <div className='head'>
        <div>
          <h2>{targetHost}</h2>
          <p className='mono' style={{ wordBreak: "break-all" }}>
            {targetUrl}
          </p>
          <p> {crawlLabel(report.crawl_mode)}</p>
          <p>{formatDateTime(scanTime)} </p>
        </div>
        <div className='app-actions'>
          <button className='btn' onClick={handleJson}>
            <FileText className='ico' />
            JSON
          </button>
          <button
            className='btn primary'
            onClick={handlePdf}
            disabled={busy === "pdf"}
          >
            <Download className='ico' />
            {busy === "pdf" ? "Building PDF…" : "PDF"}
          </button>
        </div>
      </div>

      <div className='reportgrid'>
        <aside className='scorebox'>
          <strong>{score}</strong>
          <p>{riskLine(score)}</p>
          <div className='kv'>
            <span>Risk level</span>
            <b>{report.risk_level || severityBand(score)}</b>
          </div>
          <div className='kv'>
            <span>Verified findings</span>
            <b>{stats.total_vulnerabilities ?? vulns.length}</b>
          </div>
          <div className='kv'>
            <span>URLs crawled</span>
            <b>{stats.total_urls_crawled ?? "—"}</b>
          </div>
          <div className='kv'>
            <span>Crawl scope</span>
            <b>{crawlLabel(report.crawl_mode)}</b>
          </div>
          <div className='kv'>
            <span>Coverage</span>
            <b>{coverageStr}</b>
          </div>
          {authCov.state && (
            <div className='kv'>
              <span>Auth state</span>
              <b>{titleCase(authCov.state)}</b>
            </div>
          )}
        </aside>
        <div className='reportbody'>
          <h2>
            {report.executive_summary?.split("\n")[0] || "Assessment complete."}
          </h2>
          <p>
            {report.executive_summary?.split("\n").slice(1).join(" ") ||
              "Verified findings and coverage details are shown below."}
          </p>
          <div className='severity'>
            <div>
              <strong className='high'>{breakdown.critical ?? 0}</strong>
              <span>Critical</span>
            </div>
            <div>
              <strong className='high'>{breakdown.high ?? 0}</strong>
              <span>High</span>
            </div>
            <div>
              <strong className='medium'>{breakdown.medium ?? 0}</strong>
              <span>Medium</span>
            </div>
            <div>
              <strong className='low'>{breakdown.low ?? 0}</strong>
              <span>Low</span>
            </div>
            <div>
              <strong>{breakdown.info ?? 0}</strong>
              <span>Info</span>
            </div>
          </div>
        </div>
      </div>

      <div className='panel'>
        <div className='panel-h'>Scan coverage</div>
        <div className='panel-b'>
          <div className='kv-grid'>
            <div className='kv-cell'>
              <span>Crawl scope</span>
              <b>{crawlLabel(report.crawl_mode)}</b>
            </div>
            <div className='kv-cell'>
              <span>URLs crawled</span>
              <b>{stats.total_urls_crawled ?? "—"}</b>
            </div>
            <div className='kv-cell'>
              <span>Auth state</span>
              <b>{titleCase(authCov.state) || "Unauthenticated"}</b>
            </div>
            <div className='kv-cell'>
              <span>Authed URLs</span>
              <b>{authCov.authenticated_url_count ?? 0}</b>
            </div>
            <div className='kv-cell'>
              <span>Protected targets verified</span>
              <b>{authCov.protected_targets_verified ?? 0}</b>
            </div>
            <div className='kv-cell'>
              <span>SPA detected</span>
              <b>{spaCov.spa_detected ? "Yes" : "No"}</b>
            </div>
            <div className='kv-cell'>
              <span>API endpoints found</span>
              <b>{spaCov.api_endpoints_extracted ?? 0}</b>
            </div>
            <div className='kv-cell'>
              <span>Routes extracted</span>
              <b>{spaCov.routes_extracted ?? 0}</b>
            </div>
          </div>
        </div>
      </div>

      {(evidence.confirmed_exploit ||
        evidence.confirmed_observation ||
        evidence.probable ||
        evidence.possible ||
        evidence.informational) > 0 && (
        <div className='panel'>
          <div className='panel-h'>Evidence strength</div>
          <div className='panel-b'>
            <div className='kv-grid'>
              <div className='kv-cell'>
                <span>Confirmed exploit</span>
                <b>{evidence.confirmed_exploit ?? 0}</b>
              </div>
              <div className='kv-cell'>
                <span>Confirmed observation</span>
                <b>{evidence.confirmed_observation ?? 0}</b>
              </div>
              <div className='kv-cell'>
                <span>Probable</span>
                <b>{evidence.probable ?? 0}</b>
              </div>
              <div className='kv-cell'>
                <span>Possible</span>
                <b>{evidence.possible ?? 0}</b>
              </div>
              <div className='kv-cell'>
                <span>Informational</span>
                <b>{evidence.informational ?? 0}</b>
              </div>
            </div>
          </div>
        </div>
      )}

      {tech.length > 0 && (
        <div className='panel'>
          <div className='panel-h'>Technology stack</div>
          <div className='panel-b'>
            <div className='tech-list'>
              {tech.map((t, i) => (
                <div key={`${t.name}-${i}`} className='tech-item'>
                  <div>
                    <b>{t.name}</b>
                    {t.version && (
                      <span className='mono small'> {t.version}</span>
                    )}
                    <div className='small'>{titleCase(t.category)}</div>
                  </div>
                  {Array.isArray(t.cves) && t.cves.length > 0 && (
                    <span className='sev-tag high'>
                      {t.cves.length} CVE{t.cves.length > 1 ? "s" : ""}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {chains.length > 0 && (
        <div className='panel'>
          <div className='panel-h'>Attack chains</div>
          <div className='panel-b'>
            {chains.map((c) => (
              <div key={c.id} className='chain-item'>
                <span
                  className={`sev-tag ${
                    sevKey(c.severity) === "medium"
                      ? "medium"
                      : sevKey(c.severity) === "low"
                        ? "low"
                        : "high"
                  }`}
                >
                  {c.severity}
                </span>
                <p>{c.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className='filter-tabs'>
        <button
          className={`filter-tab${filter === "all" ? " active" : ""}`}
          onClick={() => setFilter("all")}
        >
          All ({vulns.length})
        </button>
        {SEVERITIES.map((s) => (
          <button
            key={s}
            className={`filter-tab${filter === s ? " active" : ""}`}
            onClick={() => setFilter(s)}
          >
            {SEVERITY_META[s].label} ({breakdown[s] ?? 0})
          </button>
        ))}
      </div>

      <div className='panel'>
        <div className='panel-h'>Detailed findings</div>
        <div className='panel-b'>
          {filtered.length === 0 ? (
            <p className='muted-text'>
              No findings for this severity.
            </p>
          ) : (
            <div className='findings'>
              {filtered.map((v) => (
                <Finding key={v.id} v={v} />
              ))}
            </div>
          )}
        </div>
      </div>

      {limitations.length > 0 && (
        <div className='panel'>
          <div className='panel-h'>Scanner limitations</div>
          <div className='panel-b'>
            <ul className='limitations'>
              {limitations.map((l, i) => (
                <li key={i}>{l}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}

export default ReportPage;
