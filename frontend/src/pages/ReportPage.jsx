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
import { copyToClipboard, downloadFile, parseUTCDate, saveBlob } from "../utils/helpers.js";
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
import useQuery from "../hooks/useQuery.js";
import { invalidateQueries } from "../services/queryCache.js";
import QuerySwap, { QuerySkeleton, QueryContent } from "../components/QuerySwap.jsx";

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
  const d = parseUTCDate(iso);
  if (!d) return "N/A";
  return d.toLocaleString(undefined, {
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

// Detector ids are snake_case module names; title-casing alone yields "Xss" and
// "Injection sql command". Spell the known ones properly, fall back otherwise.
const DETECTOR_LABELS = {
  access_control: "Access control",
  authentication_failures: "Authentication",
  crypto_failures: "Cryptographic failures",
  csrf: "CSRF",
  exception_handling: "Error handling",
  file_inclusion: "File inclusion (LFI/RFI)",
  file_upload: "File upload",
  injection_sql_command: "SQL / command injection",
  nosql_injection: "NoSQL injection",
  open_redirect: "Open redirect",
  security_headers: "Security headers",
  sensitive_paths: "Sensitive paths",
  ssrf: "SSRF",
  supply_chain: "Supply chain",
  xss: "XSS",
  crawler: "Crawler (discovery only)",
};

function detectorLabel(name) {
  const key = (name || "").toString().trim();
  return DETECTOR_LABELS[key] || titleCase(key);
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

// The tested-surface inventory: which paths and parameters the scan actually
// sent requests to, plus the gaps the scanner recorded. Paginated because a
// broad scan reaches hundreds of paths and dumping them all buries the report.
const TESTED_PATH_PAGE = 20;

function CoveragePanel({ surface, warnings }) {
  const [visible, setVisible] = useState(TESTED_PATH_PAGE);
  const paths = surface?.tested_paths || [];
  const recorded = Boolean(surface && Object.keys(surface).length > 0);
  if (!recorded && warnings.length === 0) return null;

  const pathsTested = surface?.paths_tested ?? 0;
  const probed = surface?.paths_probed_by_detector ?? 0;
  const absent = surface?.paths_absent ?? 0;
  const unconfirmed = surface?.paths_existence_unconfirmed ?? 0;
  const reachedNotProbed = Math.max(0, pathsTested - probed);
  const shown = paths.slice(0, visible);

  return (
    <div className='panel'>
      <div className='panel-h'>What was tested</div>
      <div className='panel-b'>
        {recorded ? (
          <>
            <p className='small'>
              Measured from the requests this scan actually sent - not from the
              surface found while crawling. Probes the request budget refused are
              excluded, and a path the target answered only with 404 is recorded
              as absent rather than as tested surface.
            </p>
            <MetricTable
              title='Tested surface'
              rows={[
                ["Existing paths reached", pathsTested],
                ["Paths probed by a detector", probed],
                ["Parameters tested", surface.parameters_tested ?? 0],
                ["Requests sent", surface.requests_sent ?? 0],
                [
                  "Requests proving a path absent (404)",
                  surface.requests_to_absent_paths ?? 0,
                ],
                ["Candidate paths found absent", absent],
                ["Requests with no response", surface.requests_without_response ?? 0],
                ["Requests denied by budget", surface.requests_denied_by_budget ?? 0],
              ]}
            />
            {absent > 0 && (
              <p className='small'>
                Path-guessing checks probed <b>{absent}</b> candidate path
                {absent === 1 ? "" : "s"} the target answered only with 404/410.
                Those probes prove a resource is absent, so they are counted above
                but excluded from the tested surface and from the list below -
                counting them would inflate coverage with paths that do not exist.
              </p>
            )}
            {unconfirmed > 0 && (
              <p className='small'>
                <b>{unconfirmed}</b> path{unconfirmed === 1 ? "" : "s"} never
                returned a response at all, so whether they exist was not
                established either way. They are excluded from the tested surface.
              </p>
            )}
            {reachedNotProbed > 0 && (
              <p className='small'>
                <b>{reachedNotProbed}</b> of the {pathsTested} existing paths
                reached were fetched while crawling but never probed by a
                detector. Treat them as untested.
              </p>
            )}
            {(surface.detectors_exercised || []).length > 0 && (
              <p className='small'>
                Detectors that sent traffic:{" "}
                {surface.detectors_exercised
                  .map((name) => detectorLabel(name))
                  .join(", ")}
                .
              </p>
            )}
            {surface.browser_probes_itemised === false && (
              <p className='small'>
                Browser-driven probes (DOM XSS verification, browser crawling) are
                not itemised below - this inventory covers HTTP-layer traffic only,
                so browser coverage is understated here rather than absent.
              </p>
            )}
            {shown.length > 0 && (
              <>
                <table className='coverage-table'>
                  <thead>
                    <tr>
                      <th>Path</th>
                      <th>Methods</th>
                      <th>Parameters tested</th>
                      <th>Detectors</th>
                      <th>Requests</th>
                    </tr>
                  </thead>
                  <tbody>
                    {shown.map((p) => (
                      <tr key={`${p.path}-${(p.methods || []).join(",")}`}>
                        <td className='mono' style={{ wordBreak: "break-all" }}>
                          {p.path}
                        </td>
                        <td>{(p.methods || []).join(", ")}</td>
                        <td>
                          {(p.parameters || []).length === 0 ? (
                            <span className='muted-text'>
                              none - path-level only
                            </span>
                          ) : (
                            <>
                              {(p.parameters || [])
                                .map((param) => param.name)
                                .join(", ")}
                              {p.parameters_omitted > 0 &&
                                ` +${p.parameters_omitted} more`}
                            </>
                          )}
                        </td>
                        <td>
                          {(p.detectors || [])
                            .map((name) => detectorLabel(name))
                            .join(", ")}
                        </td>
                        <td>
                          {p.requests ?? 0}
                          {p.no_response > 0 && ` (${p.no_response} unanswered)`}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <div className='coverage-more'>
                  <span className='small'>
                    Showing {shown.length} of {paths.length} existing path
                    {paths.length === 1 ? "" : "s"}
                    {surface.tested_paths_omitted > 0 &&
                      ` - ${surface.tested_paths_omitted} further tested path${
                        surface.tested_paths_omitted === 1 ? "" : "s"
                      } exceeded the storage limit and are counted above but not listed`}
                    .
                  </span>
                  {visible < paths.length && (
                    <button
                      className='btn'
                      onClick={() =>
                        setVisible((count) => count + TESTED_PATH_PAGE)
                      }
                    >
                      Show more
                    </button>
                  )}
                </div>
              </>
            )}
          </>
        ) : (
          <p className='small'>
            No tested-surface inventory was recorded for this scan, so the paths
            and parameters exercised cannot be listed. This does not mean nothing
            was tested.
          </p>
        )}

        <div className='coverage-gaps'>
          <b>Coverage gaps - what was not tested</b>
          {warnings.length > 0 ? (
            <>
              <p className='small'>
                Where a class was not exercised, the absence of findings in that
                class is not evidence the target is unaffected.
              </p>
              <ul className='limitations'>
                {warnings.map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            </>
          ) : (
            <p className='small'>
              The scanner recorded no coverage gaps for this run - every detector
              it ran sent traffic and its prerequisites were met. That is not the
              same as having tested the whole application.
            </p>
          )}
        </div>
      </div>
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
                            ? 'cURL copied. Replace the auth placeholders with your session values.'
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
  const [filter, setFilter] = useState("all");
  const [busy, setBusy] = useState("");
  const reportQuery = useQuery({
    queryKey: `reports:detail:${scanId}`,
    queryFn: async () => {
      const [reportData, scanData] = await Promise.all([
        getReport(scanId),
        getScanDetails(scanId),
      ]);
      return { ...scanData, ...reportData };
    },
    staleTime: 30_000,
  });
  const membersQuery = useQuery({
    queryKey: "team:members",
    queryFn: listMembers,
  });
  const { refetch: refetchReport } = reportQuery;
  const { refetch: refetchMembers } = membersQuery;
  const report = reportQuery.data;
  const members = membersQuery.data?.items || [];
  const loading = reportQuery.isLoading || membersQuery.isLoading;
  const error = reportQuery.error || membersQuery.error;
  const hasData = reportQuery.hasData && membersQuery.hasData;
  const contentEntered =
    reportQuery.contentEntered || membersQuery.contentEntered;

  const load = useCallback(
    async (_signal, { silent = false } = {}) => {
      try {
        await refetchReport();
      } catch (err) {
        if (silent) toast(err, { type: "error", fallback: "Could not refresh the report." });
      }
    },
    [refetchReport, toast],
  );

  const refetchAll = useCallback(
    () => Promise.allSettled([refetchReport(), refetchMembers()]),
    [refetchReport, refetchMembers],
  );

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

  useEffect(() => {
    if (status !== "completed" && status !== "failed") return;
    invalidateQueries("scans", { refetchActive: false });
  }, [status]);

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
      invalidateQueries("scans", { refetchActive: false });
      toast("Analysis retry queued");
      await load(undefined, { silent: true });
    } catch (err) {
      toast(err, { type: "error", fallback: "Could not retry analysis." });
    } finally {
      setBusy("");
    }
  }, [scanId, toast, load]);

  const reportSkeleton = (
    <>
          <div className='skeleton-back'>
            <span className='skeleton-block skeleton-copy' style={{ width: 80 }} />
          </div>
          <div className='head' aria-hidden='true'>
            <div>
              <span className='skeleton-block skeleton-heading' style={{ width: "min(60%, 280px)", height: 22, marginBottom: 8 }} />
              <span className='skeleton-block skeleton-copy' style={{ width: "min(80%, 380px)", marginBottom: 6 }} />
              <span className='skeleton-block skeleton-copy' style={{ width: "min(35%, 160px)" }} />
            </div>
            <div className='app-actions'>
              <span className='skeleton-block' style={{ width: 72, height: 34, borderRadius: 6 }} />
              <span className='skeleton-block' style={{ width: 72, height: 34, borderRadius: 6 }} />
            </div>
          </div>
          <div className='reportgrid' aria-hidden='true'>
            <div className='scorebox skeleton-scorebox'>
              <span className='skeleton-block skeleton-value' style={{ width: "4rem", height: "2.6rem", marginBottom: 8 }} />
              <span className='skeleton-block skeleton-copy' style={{ width: "85%", marginBottom: 14 }} />
              {[0, 1, 2, 3, 4, 5].map((i) => (
                <div className='skeleton-kv' key={i}>
                  <span className='skeleton-block skeleton-copy' style={{ width: "55%" }} />
                  <span className='skeleton-block skeleton-copy' style={{ width: "30%" }} />
                </div>
              ))}
            </div>
            <div className='reportbody'>
              <span className='skeleton-block skeleton-copy' style={{ width: "90%", marginBottom: 6 }} />
              <span className='skeleton-block skeleton-copy' style={{ width: "70%", marginBottom: 18 }} />
              <div className='severity' aria-hidden='true'>
                {[0, 1, 2, 3, 4].map((i) => (
                  <div key={i}>
                    <span className='skeleton-block skeleton-value' style={{ width: "1.2rem", height: "1.3rem", margin: "0 auto 4px" }} />
                    <span className='skeleton-block skeleton-copy' style={{ width: "70%", margin: "0 auto" }} />
                  </div>
                ))}
              </div>
            </div>
          </div>
          <div className='metric-cols' aria-hidden='true'>
            {[0, 1].map((t) => (
              <div className='metric-table' key={t}>
                <div className='metric-head'>
                  <span className='skeleton-block skeleton-heading' style={{ width: "min(65%, 140px)" }} />
                  <span />
                </div>
                {[0, 1, 2, 3, 4, 5, 6, 7].map((r) => (
                  <div className='metric-row' key={r}>
                    <span className='skeleton-block skeleton-copy' style={{ width: "min(70%, 160px)" }} />
                    <b><span className='skeleton-block skeleton-copy' style={{ width: "min(45%, 80px)" }} /></b>
                  </div>
                ))}
              </div>
            ))}
          </div>
    </>
  );

  if (error && !hasData)
    return (
      <div className='view'>
        <button className='back' onClick={() => navigate("/reports")}>
          ← All reports
        </button>
        <div style={{ maxWidth: 760 }}><ErrorNotice error={error} fallback='Could not load the report.' onRetry={refetchAll} /></div>
      </div>
    );

  // Everything below dereferences `report`, so it lives in a closure that only
  // runs on the loaded branch - the skeleton branch never evaluates it.
  function renderReport() {
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
  // Prefer the user-set application name, then the crawled site's <title>,
  // then the URL hostname as the last resort.
  const siteTitle =
    (report.application_name || "").trim() ||
    (report.site_title || "").trim() ||
    targetHost;
  const scanTime =
    report.started_at || report.completed_at || report.generated_at;
  const tech = report.technology_stack || [];
  const authCov = report.auth_coverage || {};
  const spaCov = report.spa_api_coverage || {};
  const evidence = report.evidence_strength_breakdown || {};
  const chains = report.attack_chains || [];
  const limitations = report.scanner_limitations || [];
  const authorization = report.authorization || {};
  const testedSurface = report.tested_surface || report.report_metadata?.tested_surface || {};
  const coverageWarnings =
    report.coverage_warnings || report.report_metadata?.coverage_warnings || [];
  const analysis = report.analysis || {};
  const analysisStatus = analysis.status || "not_requested";
  const analysisComplete = analysisStatus === "completed";
  const canRetryAnalysis =
    analysisStatus === "failed" &&
    ["owner", "admin", "analyst"].includes(user?.role);

  return (
    <>
      <button className='back' onClick={() => navigate(-1)}>
        ← Back
      </button>
      {error && (
        <div style={{ maxWidth: 760 }}>
          <ErrorNotice
            error={error}
            fallback='Report data may be out of date.'
            onRetry={refetchAll}
          />
        </div>
      )}
      <div className='head'>
        <div>
          <h2>{siteTitle}</h2>
          <p className='mono' style={{ wordBreak: "break-all" }}>
            {targetUrl}
          </p>
          <p>{formatDateTime(scanTime)} </p>
        </div>
        <div className='app-actions'>
          <Tooltip label="Download detailed JSON report">
            <button className='btn' onClick={handleJson}>
              <FileText className='ico' />
              JSON
            </button>
          </Tooltip>
          <Tooltip label={!analysisComplete ? "PDF is available after AI analysis completes" : "Download PDF report"}>
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
            <b>{stats.active_vulnerabilities ?? stats.total_vulnerabilities ?? vulns.length}</b>
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
            <span>Paths tested</span>
            <b>
              {Number.isFinite(testedSurface.paths_probed_by_detector)
                ? testedSurface.paths_probed_by_detector
                : "Not recorded"}
            </b>
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
          title='Crawl &amp; auth coverage'
          rows={[
            ["Crawl scope", crawlLabel(report.crawl_mode)],
            ["URLs discovered", stats.total_urls_crawled ?? "N/A"],
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

      <CoveragePanel surface={testedSurface} warnings={coverageWarnings} />

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
    </>
  );
  }

  return (
    <div className='view'>
      <QuerySwap>
        {loading ? (
          <QuerySkeleton
            className='report-skeleton query-skeleton'
            aria-label='Loading report'
          >
            {reportSkeleton}
          </QuerySkeleton>
        ) : !report ? null : (
          <QueryContent settled={contentEntered}>{renderReport()}</QueryContent>
        )}
      </QuerySwap>
    </div>
  );
}

export default ReportPage;
