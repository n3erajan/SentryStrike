import { useCallback, useEffect, useState } from "react";
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
  const [workspaceName, setWorkspaceName] = useState("");
  const [retention, setRetentionDays] = useState(90);
  const PAGE_SIZE = 15;
  const [audit, setAudit] = useState([]);
  const [auditTotal, setAuditTotal] = useState(0);
  const [auditPage, setAuditPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const loadAudit = useCallback(async (page) => {
    const skip = (page - 1) * PAGE_SIZE;
    const data = await listAuditLog(skip, PAGE_SIZE);
    setAudit(data.items || []);
    setAuditTotal(data.total || 0);
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [ws, ret] = await Promise.all([
        getWorkspace(),
        getRetention(),
      ]);
      setWorkspaceName(ws.name);
      setRetentionDays(ret.retention_days);
      if (admin) await loadAudit(1);
    } catch (err) {
      setError(err.message || "Could not load workspace settings.");
    } finally {
      setLoading(false);
    }
  }, [admin, loadAudit]);
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    load();
  }, [load]);

  async function save() {
    setSaving(true);
    try {
      const requests = [];
      requests.push(
        setRetention(Number(retention)).then((r) => setRetentionDays(r.retention_days)),
      );
      if (isOwner) {
        requests.push(
          updateWorkspace({ name: workspaceName }).then((r) =>
            setWorkspaceName(r.name),
          ),
        );
      }
      await Promise.all(requests);
      toast("Workspace settings saved");
    } catch (err) {
      toast(err.message || "Could not save settings.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className='view'>
      <div className='head'>
        <div>
          <h1>Settings</h1>
          <p>Workspace settings and audit history.</p>
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
      {error && <div className='auth-error'>{error}</div>}
      {loading ? (
        <div className='empty-state'>Loading settings…</div>
      ) : (
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
                  onChange={(e) => setWorkspaceName(e.target.value)}
                  readOnly={!isOwner}
                />
              </div>
            </div>
          </section>
          <section className='formsection'>
            <h2>Data retention</h2>
            <p className='muted-text'>
              Completed scan data is eligible for deletion after this period.
              The compliance minimum is 30 days.
            </p>
            <div className='field settings-short'>
              <label>Retention days</label>
              <div className='control'>
                <input
                  type='number'
                  min='30'
                  value={retention}
                  onChange={(e) => setRetentionDays(e.target.value)}
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
                          {new Date(a.created_at).toLocaleString(undefined, {
                            dateStyle: "medium",
                            timeStyle: "short",
                          })}
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
                    No audited workspace activity yet.
                  </p>
                )}
              </div>
              {auditTotal > PAGE_SIZE && (
                <div className='pagination'>
                  <button
                    className='btn page-btn'
                    disabled={auditPage <= 1}
                    onClick={() => {
                      const p = auditPage - 1;
                      setAuditPage(p);
                      loadAudit(p);
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
                            loadAudit(p);
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
                      const p = auditPage + 1;
                      setAuditPage(p);
                      loadAudit(p);
                    }}
                  >
                    Next ›
                  </button>
                </div>
              )}
            </section>
          )}
        </div>
      )}
    </div>
  );
}

export default SettingsPage;
