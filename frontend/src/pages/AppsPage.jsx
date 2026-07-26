import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Boxes, ChevronDown, Pencil, Plus, Trash2, X } from "lucide-react";
import {
  createApplication,
  deleteApplication,
  listApplications,
  updateApplication,
} from "../services/applications.js";
import { CONFIG_GROUPS } from "../data/constants.js";
import ConfigField, { configValid } from "../components/ConfigField.jsx";
import Tooltip from "../components/Tooltip.jsx";
import { useToast } from "../components/Toast.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { isValidUrl } from "../utils/helpers.js";

function hostnameOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url || "unknown";
  }
}

// Create/edit dialog. `app` is null when creating. Mirrors the invite modal on
// TeamPage; the scan-config half reuses the same field renderer as ScanPage.
function ApplicationDialog({ app, onSave, onClose }) {
  const [name, setName] = useState(app?.name || "");
  const [targetUrl, setTargetUrl] = useState(app?.target_url || "");
  const [config, setConfig] = useState(app?.default_scan_config || {});
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [saving, setSaving] = useState(false);

  const urlValid = isValidUrl(targetUrl);
  const canSave =
    name.trim() && urlValid && configValid(CONFIG_GROUPS, config) && !saving;

  function setConfigField(key, value) {
    setConfig((prev) => {
      if (value === "" || value === undefined || value === null) {
        const next = { ...prev };
        delete next[key];
        return next;
      }
      return { ...prev, [key]: value };
    });
  }

  async function submit(e) {
    e.preventDefault();
    if (!canSave) return;
    setSaving(true);
    try {
      await onSave({ name: name.trim(), targetUrl: targetUrl.trim(), config });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className='modal-backdrop' onMouseDown={onClose}>
      <div
        className='modal-card modal-wide'
        role='dialog'
        aria-modal='true'
        aria-labelledby='application-dialog-title'
        onMouseDown={(e) => e.stopPropagation()}
      >
        <Tooltip label='Close'>
          <button
            type='button'
            className='modal-close'
            aria-label='Close application dialog'
            onClick={onClose}
          >
            <X className='ico' />
          </button>
        </Tooltip>
        <h2 id='application-dialog-title'>
          {app ? "Edit application" : "Add a web application"}
        </h2>
        <p className='muted-text'>
          Save the target URL and defaults you want to reuse for future scans.
        </p>
        <form onSubmit={submit}>
          <div className='field'>
            <label htmlFor='app-name'>Name</label>
            <div className='control'>
              <input
                id='app-name'
                value={name}
                maxLength={200}
                onChange={(e) => setName(e.target.value)}
                placeholder='Customer portal (staging)'
                autoFocus
              />
            </div>
          </div>
          <div className='field'>
            <label htmlFor='app-url'>Target URL</label>
            <div className={`control${targetUrl && !urlValid ? " error" : ""}`}>
              <input
                id='app-url'
                type='url'
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder='https://staging.example.com'
              />
            </div>
            {targetUrl && !urlValid && (
              <span className='field-error'>
                Enter a valid URL including http:// or https://
              </span>
            )}
          </div>

          <button
            type='button'
            className={`advanced-toggle${advancedOpen ? " open" : ""}`}
            onClick={() => setAdvancedOpen((v) => !v)}
            aria-expanded={advancedOpen}
          >
            Default scan configuration{" "}
            <span className='muted-text'>(optional)</span>
            <span className='advanced-toggle-hint'>
              Used to prefill new scans of this app
            </span>
            <ChevronDown className='ico chev' />
          </button>
          {advancedOpen && (
            <div className='advanced-panel'>
              {CONFIG_GROUPS.map((group) => (
                <div key={group.title}>
                  <h3>{group.title}</h3>
                  <p className='muted-text'>{group.blurb}</p>
                  <div className='grid2'>
                    {group.fields.map((field) => (
                      <ConfigField
                        key={field.key}
                        field={field}
                        value={config[field.key]}
                        onChange={setConfigField}
                        disabled={saving}
                        idPrefix='app-cfg'
                      />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}

          <button className='btn primary' disabled={!canSave}>
            {saving
              ? "Saving…"
              : app
                ? "Save changes"
                : "Create application"}
          </button>
        </form>
      </div>
    </div>
  );
}

function AppsPage() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const canManage = user?.role !== "viewer";
  const [apps, setApps] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [dialog, setDialog] = useState(null); // { app } | null
  const [busy, setBusy] = useState("");

  const load = useCallback(async (signal) => {
    setLoading(true);
    setError("");
    try {
      const data = await listApplications({ signal });
      setApps(Array.isArray(data?.items) ? data.items : []);
    } catch (err) {
      if (err.name !== "AbortError")
        setError(err.message || "Could not load applications.");
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

  async function save(payload) {
    const editing = dialog?.app;
    try {
      if (editing) await updateApplication(editing.id, payload);
      else await createApplication(payload);
      setDialog(null);
      toast(editing ? "Application updated" : "Application created");
      await load();
    } catch (err) {
      toast(err.message || "Could not save the application.");
    }
  }

  async function remove(app) {
    if (
      !window.confirm(
        `Delete ${app.name}? Its scan reports are kept, but the saved target and defaults are removed.`,
      )
    )
      return;
    setBusy(app.id);
    try {
      await deleteApplication(app.id);
      toast("Application deleted");
      await load();
    } catch (err) {
      toast(err.message || "Could not delete the application.");
    } finally {
      setBusy("");
    }
  }

  return (
    <div className='view'>
      <div className='head'>
        <div>
          <h1>Web applications</h1>
          <p>Save targets and keep their scan history together.</p>
        </div>
        {canManage && (
          <button className='btn primary' onClick={() => setDialog({ app: null })}>
            <Plus className='ico' />
            Add application
          </button>
        )}
      </div>

      {loading ? (
        <div className='empty-state'>Loading applications…</div>
      ) : error ? (
        <div className='auth-error'>{error}</div>
      ) : apps.length === 0 ? (
        <div className='empty-state'>
          <Boxes size={30} />
          <h2>No applications yet</h2>
          <p>
            Add an app to save its target URL, defaults, and scan history.
          </p>
          {canManage && (
            <button
              className='btn primary'
              onClick={() => setDialog({ app: null })}
            >
              <Plus className='ico' />
              Add application
            </button>
          )}
        </div>
      ) : (
        <div className='app-grid'>
          {apps.map((a) => (
            <article key={a.id} className='card'>
              <h2>{a.name}</h2>
              <p className='mono' style={{ wordBreak: "break-all" }}>{a.target_url}</p>
              <div className='cardfoot'>
                <Link className='text-btn' to={`/apps/${a.id}`}>
                  Scan history
                </Link>
                {canManage && (
                  <span className='rowactions'>
                    <Tooltip label={`Start a scan of ${a.name}`}>
                      <button
                        type='button'
                        className='scan-action'
                        aria-label={`Start a scan of ${a.name}`}
                        onClick={() => navigate(`/scan?app=${a.id}`)}
                      >
                        Scan
                      </button>
                    </Tooltip>
                    <Tooltip label={`Edit ${a.name}`}>
                      <button
                        type='button'
                        aria-label={`Edit ${a.name}`}
                        onClick={() => setDialog({ app: a })}
                      >
                        <Pencil className='ico' />
                      </button>
                    </Tooltip>
                    <Tooltip label={`Delete ${a.name}`}>
                      <button
                        type='button'
                        className='danger'
                        aria-label={`Delete ${a.name}`}
                        disabled={busy === a.id}
                        onClick={() => remove(a)}
                      >
                        <Trash2 className='ico' />
                      </button>
                    </Tooltip>
                  </span>
                )}
              </div>
            </article>
          ))}
        </div>
      )}

      {dialog && (
        <ApplicationDialog
          app={dialog.app}
          onSave={save}
          onClose={() => setDialog(null)}
        />
      )}
    </div>
  );
}

export default AppsPage;
