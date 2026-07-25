import { useCallback, useEffect, useState } from "react";
import { ArrowUpRight } from "lucide-react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";
import { useToast } from "../components/Toast.jsx";
import {
  getRetention,
  listAuditLog,
  setRetention,
} from "../services/workspace.js";

const title = (v) =>
  (v || "").replaceAll("_", " ").replace(/^./, (c) => c.toUpperCase());

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
  const [retention, setRetentionDays] = useState(90);
  const [audit, setAudit] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setRetentionDays((await getRetention()).retention_days);
      if (admin) setAudit((await listAuditLog()).items || []);
    } catch (err) {
      setError(err.message || "Could not load workspace settings.");
    } finally {
      setLoading(false);
    }
  }, [admin]);
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    load();
  }, [load]);

  async function save() {
    setSaving(true);
    try {
      setRetentionDays((await setRetention(Number(retention))).retention_days);
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
          <p>Workspace retention and audit history.</p>
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
            </section>
          )}
        </div>
      )}
    </div>
  );
}

export default SettingsPage;
