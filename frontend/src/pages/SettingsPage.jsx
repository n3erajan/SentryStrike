import { useState } from "react";
import { ArrowUpRight } from "lucide-react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";
import { useToast } from "../components/Toast.jsx";
import {
  getRetention,
  getWorkspace,
  listAuditLog,
  setRetention,
  updateWorkspace,
} from "../services/workspace.js";
import ErrorNotice from "../components/ErrorNotice.jsx";
import { parseUTCDate } from "../utils/helpers.js";
import useQuery from "../hooks/useQuery.js";
import {
  invalidateQueries,
  setQueryData,
} from "../services/queryCache.js";
import QuerySwap, { QuerySkeleton, QueryContent } from "../components/QuerySwap.jsx";

const title = (v) =>
  (v || "").replaceAll("_", " ").replace(/^./, (c) => c.toUpperCase());

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

function siteLabel(url) {
  if (!url) return "the scan target";
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function auditDetail(entry) {
  const metadata = entry.metadata || {};
  const site = siteLabel(metadata.target_url);
  switch (entry.action) {
    case "scan_created":
      return `Started ${metadata.crawl_mode === "single" ? "a single-page scan" : "a full-site scan"} of ${site}`;
    case "scan_cancelled":
      return `Cancelled the scan of ${site}`;
    case "scan_purged":
      return `Removed the scan of ${site} after ${metadata.retention_days || "the configured"} retention days`;
    case "analysis_retry_created":
      return `Retried analysis for ${site}${metadata.new_revision ? ` · revision ${metadata.new_revision}` : ""}`;
    case "finding_review_changed":
      return `${title(metadata.finding_type) || "Finding"} on ${site} · ${title(metadata.previous_disposition)} → ${title(metadata.new_disposition)}`;
    case "finding_reverification_created":
      return `Queued re-verification of ${title(metadata.finding_type) || "a finding"} on ${site}`;
    case "member_removed":
      return `Removed ${metadata.email || "a member"}${metadata.role ? ` · ${title(metadata.role)}` : ""}`;
    case "member_role_changed":
      return `${metadata.email || "Member"} · ${title(metadata.from)} → ${title(metadata.to)}`;
    case "invite_created":
      return `Invited ${metadata.email || "a new member"}${metadata.role ? ` as ${title(metadata.role)}` : ""}`;
    case "invite_cancelled":
      return `Cancelled the invitation for ${metadata.email || "a member"}`;
    default:
      return entry.target_type && entry.target_id
        ? `${title(entry.target_type)} · ${entry.target_id}`
        : "Workspace activity";
  }
}

function SettingsPage() {
  const { user } = useAuth();
  const toast = useToast();
  const admin = ["owner", "admin"].includes(user?.role);
  const isOwner = user?.role === "owner";
  const [workspaceNameDraft, setWorkspaceNameDraft] = useState(null);
  const [retentionDraft, setRetentionDraft] = useState(null);
  const PAGE_SIZE = 15;
  const [auditPage, setAuditPage] = useState(1);
  const [saving, setSaving] = useState(false);
  const workspaceQuery = useQuery({
    queryKey: "workspace",
    queryFn: getWorkspace,
    staleTime: 5 * 60_000,
  });
  const retentionQuery = useQuery({
    queryKey: "retention",
    queryFn: getRetention,
    staleTime: 5 * 60_000,
  });
  const auditQuery = useQuery({
    queryKey: `audit:page:${auditPage}`,
    queryFn: () =>
      listAuditLog((auditPage - 1) * PAGE_SIZE, PAGE_SIZE),
    staleTime: 30_000,
    enabled: admin,
  });
  const workspaceName = workspaceNameDraft ?? workspaceQuery.data?.name ?? "";
  const retention = retentionDraft ?? retentionQuery.data?.retention_days ?? 90;
  const audit = auditQuery.data?.items || [];
  const auditTotal = auditQuery.data?.total || 0;
  const loading =
    workspaceQuery.isLoading ||
    retentionQuery.isLoading ||
    (admin && auditQuery.isLoading);
  const error =
    workspaceQuery.error || retentionQuery.error || (admin && auditQuery.error);
  const hasData =
    workspaceQuery.hasData &&
    retentionQuery.hasData &&
    (!admin || auditQuery.hasData);
  const contentEntered =
    workspaceQuery.contentEntered ||
    retentionQuery.contentEntered ||
    auditQuery.contentEntered;

  function refetch() {
    const requests = [workspaceQuery.refetch(), retentionQuery.refetch()];
    if (admin) requests.push(auditQuery.refetch());
    return Promise.allSettled(requests);
  }

  async function save() {
    setSaving(true);
    try {
      const [retentionResult, workspaceResult] = await Promise.all([
        setRetention(Number(retention)),
        isOwner
          ? updateWorkspace({ name: workspaceName })
          : Promise.resolve(workspaceQuery.data),
      ]);
      setQueryData("retention", retentionResult);
      if (workspaceResult) setQueryData("workspace", workspaceResult);
      setRetentionDraft(null);
      setWorkspaceNameDraft(null);
      invalidateQueries("audit", { refetchActive: false });
      toast("Workspace settings saved");
    } catch (err) {
      toast(err, { type: "error", fallback: "Could not save settings." });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className='view'>
      <div className='head'>
        <div>
          <h1>Settings</h1>
          <p>Manage your workspace and review recent activity.</p>
        </div>
        {admin && (
          <button
            className='btn primary'
            onClick={save}
            disabled={saving || loading}
          >
            {saving ? "Saving…" : "Save settings"}
          </button>
        )}
      </div>
      <ErrorNotice error={error} fallback='Could not load workspace settings.' onRetry={refetch} />
      <QuerySwap>
        {loading ? (
          <QuerySkeleton key='skeleton' aria-label='Loading settings'>
            <div className='settings-stack query-skeleton'>
              {[0, 1, 2].map((item) => (
                <section className='formsection skeleton-formsection' key={item} aria-hidden='true'>
                  <span className='skeleton-block skeleton-heading' />
                  <span className='skeleton-block skeleton-input' />
                </section>
              ))}
            </div>
          </QuerySkeleton>
        ) : error && !hasData ? null : (
          <QueryContent settled={contentEntered}>
            <div className='settings-stack'>
          <section className='formsection'>
            <h2>Account</h2>
            <div className='grid2'>
              <div className='field'>
                <label>Work email</label>
                <div className='control'>
                  <input value={user?.email || ""} readOnly />
                </div>
              </div>
              <div className='field'>
                <label>Workspace role</label>
                <div className='control'>
                  <input value={title(user?.role)} readOnly />
                </div>
              </div>
            </div>
          </section>
          <section className='formsection'>
            <h2>Workspace</h2>
            <div className='field settings-short'>
              <label>Workspace name</label>
              <div className='control'>
                <input
                  value={workspaceName}
                  onChange={(e) => setWorkspaceNameDraft(e.target.value)}
                  readOnly={!isOwner}
                />
              </div>
            </div>
          </section>
          <section className='formsection'>
            <h2>Data retention</h2>
            <p className='muted-text'>
              Completed scan data can be deleted after this period. The minimum
              is 30 days.
            </p>
            <div className='field settings-short'>
              <label>Retention days</label>
              <div className='control'>
                <input
                  type='number'
                  min='30'
                  value={retention}
                  onChange={(e) => setRetentionDraft(e.target.value)}
                  readOnly={!admin}
                />
              </div>
            </div>
          </section>
          {admin && (
            <section className='formsection'>
              <h2>Audit log</h2>
              <div className='audit-list'>
                {audit.length ? (
                  audit.map((a) => (
                    <article className='audit-row' key={a.id}>
                      <div className='audit-copy'>
                        <b>{title(a.action)}</b>
                        <span className='audit-detail'>{auditDetail(a)}</span>
                        <span className='small'>
                          {a.actor_email ? `By ${a.actor_email}` : "System action"}
                        </span>
                      </div>
                      <div className='audit-meta'>
                        <time className='small' dateTime={a.created_at}>
                          {(() => {
                            const dd = parseUTCDate(a.created_at);
                            return dd ? dd.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "N/A";
                          })()}
                        </time>
                        {a.resource_path && (
                          <Link className='audit-resource' to={a.resource_path}>
                            View report
                            <ArrowUpRight className='ico' />
                          </Link>
                        )}
                      </div>
                    </article>
                  ))
                ) : (
                  <p className='muted-text'>
                    No workspace activity yet.
                  </p>
                )}
              </div>
              {auditTotal > PAGE_SIZE && (
                <div className='pagination'>
                  <button
                    className='btn page-btn'
                    disabled={auditPage <= 1}
                    onClick={() => {
                      setAuditPage((page) => page - 1);
                    }}
                  >
                    ‹ Prev
                  </button>
                  {pages(auditPage, Math.ceil(auditTotal / PAGE_SIZE)).map(
                    (p, i) =>
                      p === "…" ? (
                        <span key={`ellipsis-${i}`} className='page-ellipsis'>…</span>
                      ) : (
                        <button
                          key={p}
                          className={`btn page-btn${p === auditPage ? " active" : ""}`}
                          onClick={() => {
                            setAuditPage(p);
                          }}
                        >
                          {p}
                        </button>
                      ),
                  )}
                  <button
                    className='btn page-btn'
                    disabled={auditPage >= Math.ceil(auditTotal / PAGE_SIZE)}
                    onClick={() => {
                      setAuditPage((page) => page + 1);
                    }}
                  >
                    Next ›
                  </button>
                </div>
              )}
            </section>
          )}
            </div>
          </QueryContent>
        )}
      </QuerySwap>
    </div>
  );
}

export default SettingsPage;
