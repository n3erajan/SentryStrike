import { useCallback, useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext.jsx";
import { useToast } from "../components/Toast.jsx";
import { CONFIG_GROUPS } from "../data/constants.js";
import { getDefaultConfig, getRetention, listAuditLog, setDefaultConfig, setRetention } from "../services/workspace.js";

const title = (v) => (v || "").replaceAll("_", " ").replace(/^./, (c) => c.toUpperCase());

function SettingsPage() {
  const { user } = useAuth();
  const toast = useToast();
  const admin = ["owner", "admin"].includes(user?.role);
  const [config, setConfig] = useState({});
  const [retention, setRetentionDays] = useState(90);
  const [audit, setAudit] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [defaults, retentionData] = await Promise.all([getDefaultConfig(), getRetention()]);
      setConfig(defaults.config || {}); setRetentionDays(retentionData.retention_days);
      if (admin) setAudit((await listAuditLog()).items || []);
    } catch (err) { setError(err.message || "Could not load workspace settings."); }
    finally { setLoading(false); }
  }, [admin]);
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    load();
  }, [load]);

  function setField(field, raw) {
    setConfig((old) => {
      const next = { ...old };
      if (raw === "") delete next[field.key];
      else if (field.type === "int") next[field.key] = Number.parseInt(raw, 10);
      else if (field.type === "float") next[field.key] = Number.parseFloat(raw);
      else next[field.key] = raw;
      return next;
    });
  }
  async function save() {
    setSaving(true);
    try { const [defaults, retained] = await Promise.all([setDefaultConfig(config), setRetention(Number(retention))]); setConfig(defaults.config || {}); setRetentionDays(retained.retention_days); toast("Workspace settings saved"); }
    catch (err) { toast(err.message || "Could not save settings."); }
    finally { setSaving(false); }
  }

  return <div className='view'><div className='head'><div><h1>Settings</h1><p>Workspace scan defaults, retention, and audit history.</p></div>{admin && <button className='btn primary' onClick={save} disabled={saving || loading}>{saving ? "Saving…" : "Save settings"}</button>}</div>
    {error && <div className='auth-error'>{error}</div>}
    {loading ? <div className='empty-state'>Loading settings…</div> : <div className='settings-stack'>
      <section className='formsection'><h2>Account</h2><div className='grid2'><div className='field'><label>Work email</label><div className='control'><input value={user?.email || ""} readOnly /></div></div><div className='field'><label>Workspace role</label><div className='control'><input value={title(user?.role)} readOnly /></div></div></div></section>
      <section className='formsection'><h2>Data retention</h2><p className='muted-text'>Completed scan data is eligible for deletion after this period. The compliance minimum is 30 days.</p><div className='field settings-short'><label>Retention days</label><div className='control'><input type='number' min='30' value={retention} onChange={(e) => setRetentionDays(e.target.value)} readOnly={!admin} /></div></div></section>
      <section className='formsection'><h2>Default scan configuration</h2><p className='muted-text'>These values prefill every new assessment. Blank fields use scanner defaults.</p>{CONFIG_GROUPS.map((g) => <div key={g.title} className='settings-group'><h3>{g.title}</h3><div className='grid2'>{g.fields.map((f) => <div className='field' key={f.key}><label>{f.label}</label><div className='control'>{f.type === "select" ? <select value={config[f.key] ?? ""} onChange={(e) => setField(f, e.target.value)} disabled={!admin}><option value=''>Scanner default</option>{f.options.map(([v,l]) => <option key={v} value={v}>{l}</option>)}</select> : <input type='number' min={f.min} max={f.max} step={f.step || (f.type === "int" ? 1 : "any")} value={config[f.key] ?? ""} placeholder={String(f.defaultValue ?? "")} onChange={(e) => setField(f, e.target.value)} readOnly={!admin} />}</div><p className='field-description'>{f.description}</p></div>)}</div></div>)}</section>
      {admin && <section className='formsection'><h2>Audit log</h2><div className='audit-list'>{audit.length ? audit.map((a) => <div className='audit-row' key={a.id}><div><b>{title(a.action)}</b><span className='small'>{a.actor_email}</span></div><span className='small'>{new Date(a.created_at).toLocaleString()}</span></div>) : <p className='muted-text'>No audited workspace activity yet.</p>}</div></section>}
    </div>}
  </div>;
}

export default SettingsPage;
