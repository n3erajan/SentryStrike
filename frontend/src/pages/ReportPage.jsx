import { useCallback, useEffect, useRef, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import {
  ChevronDown,
  CircleOff,
  Copy,
  Download,
  FileText,
  RefreshCw,
  RotateCcw,
  Send,
} from "lucide-react";
import { downloadReportPdf, getReport } from "../services/reports.js";
import { copyToClipboard, downloadFile, saveBlob } from "../utils/helpers.js";
import { SEVERITIES, SEVERITY_META, severityClass } from "../data/constants.js";
import { useToast } from "../components/Toast.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import Select from "../components/Select.jsx";
import { getScanDetails } from "../services/scan.js";
import { listMembers } from "../services/workspace.js";
import {
  addFindingComment,
  assignFinding,
  listReverifications,
  retryAnalysis,
  reverifyFinding,
  reviewFinding,
  updateRemediation,
} from "../services/analysis.js";
import ReasonDialog from "../components/ReasonDialog.jsx";
import ReverifyCredentialsDialog from "../components/ReverifyCredentialsDialog.jsx";
import Tooltip from "../components/Tooltip.jsx";
import { reverifyAffordance } from "../utils/reverifyPolicy.js";
import { httpSnippetToCurl } from "../utils/httpToCurl.js";
import ErrorNotice from "../components/ErrorNotice.jsx";

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

// Full date + time for the report header (the scan timestamp).
function formatDateTime(iso) {
  if (!iso) return "N/A";
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? "N/A"
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

function titleCase(value) {
  const s = (value || "").toString().replace(/[_-]+/g, " ").trim();
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : "N/A";
}

// The AI verdict (confirmed | uncertain | likely_false_positive) is the model's
// calibrated judgement, reconciled against evidence grade so weak proof can't be
// over-confirmed. Map it to a label + color class for the finding badge.
const VERDICT_META = {
  confirmed: { label: "AI: Confirmed", cls: "verdict-confirmed" },
  uncertain: { label: "AI: Uncertain", cls: "verdict-uncertain" },
  likely_false_positive: {
    label: "AI: Likely false positive",
    cls: "verdict-fp",
  },
};

function hostnameOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url || "Report";
  }
}



// A borderless label/value table (same visual language as the reports and
// active-scans tables): a bold header rule with thin horizontal row rules.
function MetricTable({ title, rows }) {
  return (
    <div className='metric-table'>
      <div className='metric-head'>
        <span>{title}</span>
        <span></span>
      </div>
      {rows.map(([label, value]) => (
        <div key={label} className='metric-row'>
          <span>{label}</span>
          <b>{value}</b>
        </div>
      ))}
    </div>
  );
}

// A single finding row that expands to reveal the full backend detail:
// location, CVSS vector, evidence snippets, and the AI analysis block.
function FindingCollaboration({ scanId, finding, user, members, onChanged }) {
  const toast = useToast();
  const triager = ["owner", "admin", "analyst"].includes(user?.role);
  const contributor = triager || user?.role === "developer";
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState("");
  const [jobs, setJobs] = useState([]);
  const [showReason, setShowReason] = useState(false);
  const [showCredentials, setShowCredentials] = useState(false);
  const reverify = reverifyAffordance(finding);

  useEffect(() => {
    if (!finding.reverification_job_ids?.length) return;
    const controller = new AbortController();
    listReverifications(scanId, finding.id, controller.signal)
      .then((d) => setJobs(d.items || []))
      .catch(() => {});
    return () => controller.abort();
  }, [scanId, finding.id, finding.reverification_job_ids?.length]);

  async function mutate(key, action, message) {
    setBusy(key);
    try {
      await action();
      toast(message);
      await onChanged();
    } catch (err) {
      toast(err, { type: "error", fallback: "Could not update the finding." });
    } finally {
      setBusy("");
    }
  }
  async function submitComment(e) {
    e.preventDefault();
    const body = comment.trim();
    if (!body) return;
    await mutate(
      "comment",
      () => addFindingComment(scanId, finding.id, body),
      "Comment added",
    );
    setComment("");
  }
  function changeDisposition() {
    setShowReason(true);
  }
  function handleReasonConfirm(reason) {
    setShowReason(false);
    const disposition = finding.is_false_positive ? "active" : "false_positive";
    mutate(
      "review",
      () => reviewFinding(scanId, finding.id, disposition, reason),
      disposition === "active" ? "Finding restored" : "Finding suppressed",
    );
  }
  function queueReverification(credentials) {
    setShowCredentials(false);
    mutate(
      "reverify",
      () => reverifyFinding(scanId, finding.id, credentials),
      "Re-verification queued",
    );
  }
  function startReverification() {
    if (reverify.needsCredentials) setShowCredentials(true);
    else queueReverification(undefined);
  }

  return (
    <>
      <ReasonDialog
        open={showReason}
        title={
          finding.is_false_positive
            ? "Restore active finding"
            : "Mark false positive"
        }
        label='Reason'
        placeholder={
          finding.is_false_positive
            ? "Why is this finding being restored?"
            : "Why is this a false positive?"
        }
        confirmLabel={
          finding.is_false_positive ? "Restore finding" : "Suppress finding"
        }
        onConfirm={handleReasonConfirm}
        onCancel={() => setShowReason(false)}
      />
      <ReverifyCredentialsDialog
        open={showCredentials}
        reason={reverify.reason}
        onConfirm={queueReverification}
        onCancel={() => setShowCredentials(false)}
      />
      <div className='collab-panel'>
      <h4>Fix and review</h4>
      <div className='collab-controls'>
        <div className='field'>
          <label>Assignee</label>
          <div className='control'>
            <Select
              value={finding.assignee_user_id || ""}
              disabled={!triager || busy === "assign"}
              onChange={(v) =>
                mutate(
                  "assign",
                  () => assignFinding(scanId, finding.id, v),
                  "Assignment updated",
                )
              }
              options={[
                {value: "", label: "Unassigned"},
                ...members.map((m) => ({value: m.id, label: `${m.full_name} (${m.email})`})),
              ]}
            />
          </div>
        </div>
        <div className='field'>
          <label>Status</label>
          <div className='control'>
            <Select
              value={finding.remediation_status || "open"}
              disabled={!contributor || busy === "status"}
              onChange={(v) =>
                mutate(
                  "status",
                  () => updateRemediation(scanId, finding.id, v),
                  "Remediation status updated",
                )
              }
              options={[
                {value: "open", label: "Open"},
                {value: "in_progress", label: "In progress"},
                {value: "fixed_pending_verification", label: "Fixed, pending verification"},
                ...(triager ? [{value: "verified_fixed", label: "Verified fixed"}] : []),
                ...(triager ? [{value: "wont_fix", label: "Won't fix / risk accepted"}] : []),
              ]}
            />
          </div>
        </div>
      </div>
      {triager && (
        <div className='collab-actions' aria-label='Finding review actions'>
          {finding.verification_target &&
            (reverify.allowed ? (
              <Tooltip
                label={
                  reverify.needsCredentials
                    ? reverify.reason
                    : "Replay this finding's captured request"
                }
              >
                <button
                  type='button'
                  className='finding-action finding-action-reverify'
                  disabled={busy === "reverify"}
                  onClick={startReverification}
                >
                  <RefreshCw className={`ico${busy === "reverify" ? " spin" : ""}`} />
                  {busy === "reverify" ? "Queuing…" : "Re-verify"}
                  {busy !== "reverify" && reverify.needsCredentials && "…"}
                </button>
              </Tooltip>
            ) : (
              <Tooltip label={reverify.reason}>
                <button
                  type='button'
                  className='finding-action finding-action-reverify'
                  disabled
                >
                  <RefreshCw className='ico' />
                  Re-verify
                </button>
              </Tooltip>
            ))}
          <Tooltip
            label={
              finding.is_false_positive
                ? "Return this finding to the active workflow"
                : "Suppress this finding after recording a reason"
            }
          >
            <button
              type='button'
              className={`finding-action${finding.is_false_positive ? "" : " finding-action-danger"}`}
              onClick={changeDisposition}
              disabled={busy === "review"}
            >
              {finding.is_false_positive ? (
                <RotateCcw className='ico' />
              ) : (
                <CircleOff className='ico' />
              )}
              {busy === "review"
                ? "Updating…"
                : finding.is_false_positive
                  ? "Restore finding"
                  : "Mark false positive"}
            </button>
          </Tooltip>
        </div>
      )}
      {finding.is_false_positive && (
        <div className='review-note'>
          <b>Suppressed as false positive</b>
          <span>{finding.false_positive_reason}</span>
        </div>
      )}
      {jobs.length > 0 && (
        <section className='reverification-history'>
          <div className='reverification-history-head'>
            <h4>Reverification history</h4>
            <span className='mono'>
              {jobs.length} {jobs.length === 1 ? "attempt" : "attempts"}
            </span>
          </div>
          <ol className='reverification-list'>
            {jobs.map((j) => (
              <li key={j.id}>
                <span
                  className='reverification-marker'
                  data-status={sevKey(j.status)}
                  data-outcome={sevKey(j.outcome)}
                  aria-hidden='true'
                />
                <div className='reverification-result'>
                  <strong>
                    {j.outcome ? titleCase(j.outcome) : "Waiting for scanner"}
                  </strong>
                  <span>{titleCase(j.status)}</span>
                </div>
                <time dateTime={j.created_at}>{formatDateTime(j.created_at)}</time>
              </li>
            ))}
          </ol>
        </section>
      )}
      <div className='comment-thread'>
        {(finding.comments || []).map((c) => (
          <div className='comment' key={c.id}>
            <div>
              <div className='comment-author'>
                <span className='comment-name'>{c.author_full_name || c.author_email}</span>
                {c.author_full_name && <span className='comment-email'>{c.author_email}</span>}
              </div>
              <small>{formatDateTime(c.created_at)}</small>
            </div>
            <p>{c.body}</p>
          </div>
        ))}
      </div>
      {contributor && (
        <form className='comment-form' onSubmit={submitComment}>
          <div className='control'>
            <input
              value={comment}
              maxLength={5000}
              onChange={(e) => setComment(e.target.value)}
              placeholder='Add a remediation comment…'
            />
          </div>
          <button
            className='btn'
            disabled={!comment.trim() || busy === "comment"}
          >
            <Send className='ico' />
            Comment
          </button>
        </form>
      )}
    </div></>
  );
}

function Finding({ v, scanId, user, members, onChanged }) {
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const loc = v.location || {};
  const ev = v.evidence || {};
  const ai = v.ai_analysis || {};
  const cvss = Number.isFinite(v.cvss_score) ? v.cvss_score.toFixed(1) : "N/A";
  const url = loc.url || "";
  const params =
    loc.parameters && loc.parameters.length
      ? loc.parameters.join(", ")
      : loc.parameter || "";
  const verdict = VERDICT_META[sevKey(ai.verdict)];
  const fpPercent =
    typeof ai.false_positive_probability === "number"
      ? Math.round(ai.false_positive_probability * 100)
      : null;
  const isLikelyFp =
    sevKey(ai.verdict) === "likely_false_positive" || v.is_false_positive;
  return (
    <article
      className={`finding${open ? " open" : ""}${isLikelyFp ? " dimmed" : ""}`}
    >
      <button
        type='button'
        className='finding-head'
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
      >
        <span className={`sev-dot ${severityClass(v.severity)}`} />
        <div className='finding-title'>
          <div className='rowtitle'>{titleCase(v.vuln_type)}</div>
          <div className='small mono'>{url}</div>
        </div>
        {verdict ? (
          <span className={`verdict-tag ${verdict.cls}`}>{verdict.label}</span>
        ) : (
          <span />
        )}
        <span className='finding-cat small'>{v.category}</span>
        <span className={`sev-tag ${severityClass(v.severity)}`}>
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
                <b>{params}</b>
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
            {ai.evidence_grade && (
              <div className='kv-cell'>
                <span>Evidence grade</span>
                <b>{titleCase(ai.evidence_grade)}</b>
              </div>
            )}
            {fpPercent !== null && (
              <div className='kv-cell'>
                <span>AI false-positive estimate</span>
                <b>{fpPercent}%</b>
              </div>
            )}
            {ai.ai_analysis_status && ai.ai_analysis_status !== "success" && (
              <div className='kv-cell'>
                <span>AI analysis</span>
                <b>{titleCase(ai.ai_analysis_status)}</b>
              </div>
            )}
          </div>

          {v.cvss_vector && (
            <p className='small mono' style={{ marginTop: 12 }}>
              {v.cvss_vector}
            </p>
          )}

          {ai.description && (
            <div className='finding-block'>
              <h4>Finding</h4>
              <p>{ai.description}</p>
            </div>
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
              <div className='finding-request-code'>
                <pre>{ev.request_snippet}</pre>
                <Tooltip label='Copy as cURL' side='left'>
                  <button
                    type='button'
                    className='finding-copy-button'
                    aria-label='Copy request as cURL'
                    onClick={async (e) => {
                      e.stopPropagation()
                      const curl = httpSnippetToCurl(ev.request_snippet, {
                        baseUrl: url || undefined,
                        curlExe: navigator.userAgent.includes('Windows') ? 'curl.exe' : 'curl',
                      })
                      if (!curl) {
                        toast('Could not build cURL from this request.', { type: 'error' })
                        return
                      }
                      try {
                        await copyToClipboard(curl)
                        toast(
                          curl.includes('<YOUR_')
                            ? 'cURL copied. Replace <YOUR_…> placeholders with your own session.'
                            : 'cURL copied',
                        )
                      } catch {
                        toast('Could not copy cURL', { type: 'error' })
                      }
                    }}
                  >
                    <Copy className='ico' />
                  </button>
                </Tooltip>
              </div>
              <p className='finding-curl-hint'>
                Auth values are placeholders. Paste your own session; expired or
                one-time tokens may not reproduce.
              </p>
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
          {ai.exploitability_reasoning && (
            <div className='finding-block'>
              <h4>Why this may be exploitable</h4>
              <p>{ai.exploitability_reasoning}</p>
            </div>
          )}
          {ai.false_positive_reasoning && (
            <div className='finding-block'>
              <h4>AI false-positive review</h4>
              <p>{ai.false_positive_reasoning}</p>
            </div>
          )}
          {ai.remediation && (
            <div className='finding-block'>
              <h4>Remediation</h4>
              <p>{ai.remediation}</p>
            </div>
          )}
          {ai.evidence_grade_reason && (
            <div className='finding-block'>
              <h4>Why this evidence grade</h4>
              <p>{ai.evidence_grade_reason}</p>
            </div>
          )}

          <FindingCollaboration
            scanId={scanId}
            finding={v}
            user={user}
            members={members}
            onChanged={onChanged}
          />
        </div>
      )}
    </article>
  );
}

function ReportPage() {
  const { user } = useAuth();
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
  const [members, setMembers] = useState([]);

  const load = useCallback(
    async (signal, { silent = false } = {}) => {
      if (!silent) {
        setLoading(true);
        setError("");
      }
      try {
        const [reportData, scanData, memberData] = await Promise.all([
          getReport(scanId, signal),
          getScanDetails(scanId, signal),
          listMembers(signal),
        ]);
        setReport({ ...scanData, ...reportData });
        setMembers(memberData.items || []);
      } catch (err) {
        if (err.name === "AbortError") return;
        if (silent) toast(err, { type: "error", fallback: "Could not refresh the report." });
        else setError(err);
      } finally {
        if (!signal || !signal.aborted) {
          if (!silent) setLoading(false);
        }
      }
    },
    [scanId, toast],
  );

  useEffect(() => {
    const controller = new AbortController();
    // eslint-disable-next-line react-hooks/set-state-in-effect
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  // Poll for AI analysis progress when it isn't terminal yet.
  const pollTimer = useRef(null);
  const status = report?.analysis?.status;
  useEffect(() => {
    if (!status || status === "completed" || status === "failed") return;
    pollTimer.current = setInterval(() => {
      load(undefined, { silent: true });
    }, 5000);
    return () => {
      if (pollTimer.current) {
        clearInterval(pollTimer.current);
        pollTimer.current = null;
      }
    };
  }, [status, load]);

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
      toast(err, { type: "error", fallback: "Could not download the PDF." });
    } finally {
      setBusy("");
    }
  }, [scanId, toast]);

  const handleRetryAnalysis = useCallback(async () => {
    setBusy("analysis");
    try {
      await retryAnalysis(scanId);
      toast("Analysis retry queued");
      await load(undefined, { silent: true });
    } catch (err) {
      toast(err, { type: "error", fallback: "Could not retry analysis." });
    } finally {
      setBusy("");
    }
  }, [scanId, toast, load]);

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
        <div style={{ maxWidth: 760 }}><ErrorNotice error={error} fallback='Could not load the report.' onRetry={() => load()} /></div>
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
  // Prefer the crawled site's <title> when the scanner captured one; fall back
  // to the URL hostname otherwise.
  const siteTitle = (report.site_title || "").trim() || targetHost;
  const scanTime =
    report.started_at || report.completed_at || report.generated_at;
  const tech = report.technology_stack || [];
  const authCov = report.auth_coverage || {};
  const spaCov = report.spa_api_coverage || {};
  const evidence = report.evidence_strength_breakdown || {};
  const chains = report.attack_chains || [];
  const limitations = report.scanner_limitations || [];
  const authorization = report.authorization || {};
  const coverage =
    report.coverage_summary?.overall_coverage_pct ??
    report.report_metadata?.coverage_percent;
  const coverageStr = Number.isFinite(coverage)
    ? `${Math.round(coverage)}%`
    : "N/A";
  const analysis = report.analysis || {};
  const analysisStatus = analysis.status || "not_requested";
  const analysisComplete = analysisStatus === "completed";
  const canRetryAnalysis =
    analysisStatus === "failed" &&
    ["owner", "admin", "analyst"].includes(user?.role);

  return (
    <div className='view'>
      <button className='back' onClick={() => navigate(-1)}>
        ← Back
      </button>
      <div className='head'>
        <div>
          <h2>{siteTitle}</h2>
          <p className='mono' style={{ wordBreak: "break-all" }}>
            {targetUrl}
          </p>
          <p>{formatDateTime(scanTime)} </p>
        </div>
        <div className='app-actions'>
          <button className='btn' onClick={handleJson}>
            <FileText className='ico' />
            JSON
          </button>
          <Tooltip label={!analysisComplete ? "PDF is available after AI analysis completes" : ""}>
            <button
              className='btn primary'
              onClick={handlePdf}
              disabled={busy === "pdf" || !analysisComplete}
            >
              <Download className='ico' />
              {busy === "pdf" ? "Building PDF…" : "PDF"}
            </button>
          </Tooltip>
          </div>
      </div>

      {!analysisComplete && (
        <div className={`analysis-banner ${analysisStatus}`}>
          <div>
            <b>AI analysis: {titleCase(analysisStatus)}</b>
            <span>
              {analysis.message ||
                analysis.error_message ||
                "Analyzing findings and preparing the final report."}
            </span>
            {Number.isFinite(analysis.progress) && (
              <small>
                {analysis.progress}% complete · revision{" "}
                {analysis.revision || 1}
              </small>
            )}
          </div>
          {canRetryAnalysis && (
            <button
              className='btn'
              onClick={handleRetryAnalysis}
              disabled={busy === "analysis"}
            >
              <RefreshCw className='ico' />
              Retry analysis
            </button>
          )}
        </div>
      )}

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
            <b>{stats.total_urls_crawled ?? "N/A"}</b>
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
          <div className='kv'>
            <span>Authorization</span>
            <b>{authorization.confirmed ? "Confirmed" : "Not confirmed"}</b>
          </div>
          {authorization.confirmed_at && (
            <div className='kv'>
              <span>Confirmed at</span>
              <b>{formatDateTime(authorization.confirmed_at)}</b>
            </div>
          )}
        </aside>
        <div className='reportbody'>
          <p style={{ fontWeight: 400, fontSize: "0.88rem", lineHeight: 1.3, maxWidth: "none", color: "var(--ink)" }}>
            {report.executive_summary?.split("\n")[0] || "Scan complete."}
          </p>
          <p>
            {report.executive_summary?.split("\n").slice(1).join(" ") ||
              "Verified findings and coverage details are shown below."}
          </p>
          <div className='severity'>
            <div>
              <strong className='critical'>{breakdown.critical ?? 0}</strong>
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
              <strong className='info'>{breakdown.info ?? 0}</strong>
              <span>Info</span>
            </div>
          </div>
        </div>
      </div>

      <div className='metric-cols'>
        <MetricTable
          title='Scan coverage'
          rows={[
            ["Crawl scope", crawlLabel(report.crawl_mode)],
            ["URLs crawled", stats.total_urls_crawled ?? "N/A"],
            ["Auth state", titleCase(authCov.state) || "Unauthenticated"],
            ["Authed URLs", authCov.authenticated_url_count ?? 0],
            [
              "Protected targets verified",
              authCov.protected_targets_verified ?? 0,
            ],
            ["SPA detected", spaCov.spa_detected ? "Yes" : "No"],
            ["API endpoints found", spaCov.api_endpoints_extracted ?? 0],
            ["Routes extracted", spaCov.routes_extracted ?? 0],
          ]}
        />

        {(evidence.confirmed_exploit ||
          evidence.confirmed_observation ||
          evidence.probable ||
          evidence.possible ||
          evidence.informational) > 0 && (
          <MetricTable
            title='Evidence strength'
            rows={[
              ["Confirmed exploit", evidence.confirmed_exploit ?? 0],
              ["Confirmed observation", evidence.confirmed_observation ?? 0],
              ["Probable", evidence.probable ?? 0],
              ["Possible", evidence.possible ?? 0],
              ["Informational", evidence.informational ?? 0],
            ]}
          />
        )}
      </div>

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
                <span className={`sev-tag ${severityClass(c.severity)}`}>
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
            <p className='muted-text'>No findings for this severity.</p>
          ) : (
            <div className='findings'>
              {filtered.map((v) => (
                <Finding
                  key={v.id}
                  v={v}
                  scanId={scanId}
                  user={user}
                  members={members}
                  onChanged={() => load(undefined, { silent: true })}
                />
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
