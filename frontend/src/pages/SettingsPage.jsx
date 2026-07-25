import { useCallback, useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext.jsx";
import { useToast } from "../components/Toast.jsx";
import { getRetention, listAuditLog, setRetention } from "../services/workspace.js";

const title = (v) => (v || "").replaceAll("_", " ").replace(/^./, (c) => c.toUpperCase());

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
    setLoading(true); setError("");
    try {
      setRetentionDays((await getRetention()).retention_days);
      if (admin) setAudit((await listAuditLog()).items || []);
    } catch (err) { setError(err.message || "Could not load workspace settings."); }
    finally { setLoading(false); }
  }, [admin]);
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    load();
  }, [load]);

  async function save() {
    setSaving(true);
    try { setRetentionDays((await setRetention(Number(retention))).retention_days); toast("Workspace settings saved"); }
    catch (err) { toast(err.message || "Could not save settings."); }
    finally { setSaving(false); }
  }

  return <div className='view'><div className='head'><div><h1>Settings</h1><p>Workspace retention and audit history.</p></div>{admin && <button className='btn primary' onClick={save} disabled={saving || loading}>{saving ? "Saving…" : "Save settings"}</button>}</div>
    {error && <div className='auth-error'>{error}</div>}
    {loading ? <div className='empty-state'>Loading settings…</div> : <div className='settings-stack'>
      <section className='formsection'><h2>Account</h2><div className='grid2'><div className='field'><label>Work email</label><div className='control'><input value={user?.email || ""} readOnly /></div></div><div className='field'><label>Workspace role</label><div className='control'><input value={title(user?.role)} readOnly /></div></div></div></section>
      <section className='formsection'><h2>Data retention</h2><p className='muted-text'>Completed scan data is eligible for deletion after this period. The compliance minimum is 30 days.</p><div className='field settings-short'><label>Retention days</label><div className='control'><input type='number' min='30' value={retention} onChange={(e) => setRetentionDays(e.target.value)} readOnly={!admin} /></div></div></section>
      <section className='formsection'><h2>Default scan configuration</h2><p className='muted-text'>Scan defaults now live on each web application, so different targets can be tuned independently. Open an application to edit its defaults.</p></section>
      {admin && <section className='formsection'><h2>Audit log</h2><div className='audit-list'>{audit.length ? audit.map((a) => <div className='audit-row' key={a.id}><div><b>{title(a.action)}</b><span className='small'>{a.actor_email}</span></div><span className='small'>{new Date(a.created_at).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}</span></div>) : <p className='muted-text'>No audited workspace activity yet.</p>}</div></section>}
    </div>}
  </div>;
}

export default SettingsPage;
