import { useState, useEffect, useCallback } from "react";
import {
  ArrowLeft,
  Globe,
  Clock,
  CheckCircle,
  ShieldCheck,
  Lightning,
  CircleNotch,
  WarningCircle,
  Warning,
  DownloadSimple,
  FileText,
} from "@phosphor-icons/react";
import SeverityBadge from "../components/SeverityBadge.jsx";
import ScoreRing from "../components/ScoringRing.jsx";
import VulnerabilityCard from "../components/VulnerabilityCard.jsx";
import { SEVERITIES, SEVERITY_META } from "../data/constants.js";
import { getReport, downloadReportPdf } from "../services/reports.js";
import { downloadFile, saveBlob } from "../utils/helpers.js";

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function sevKey(value) {
  return (value || "").toString().toLowerCase();
}

function prettify(value) {
  if (value === null || value === undefined || value === "") return "-";
  return value
    .toString()
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function boolText(v) {
  return v ? "Yes" : "No";
}

function riskRating(score) {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  if (score > 0) return "low";
  return "safe";
}

function formatDate(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "-" : d.toLocaleString();
}

function KV({ k, v }) {
  return (
    <div className='kv-row'>
      <span className='kv-key'>{k}</span>
      <span className='kv-val'>{v}</span>
    </div>
  );
}

function ReportPage({ scanId, target, onBack }) {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("all");
  const [busy, setBusy] = useState(""); // "" | "pdf"
  const [notice, setNotice] = useState("");

  const load = useCallback(
    async (signal) => {
      setLoading(true);
      setError("");
      try {
        const data = await getReport(scanId, signal);
        setReport(data);
      } catch (err) {
        if (err.name === "AbortError") return;
        setError(err.message || "Could not load the report.");
      } finally {
        if (!signal || !signal.aborted) setLoading(false);
      }
    },
    [scanId],
  );

  useEffect(() => {
    const controller = new AbortController();
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch-on-mount
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const handleDownloadJson = useCallback(() => {
    if (!report) return;
    downloadFile(
      JSON.stringify(report, null, 2),
      `sentrystrike-${scanId}.json`,
      "application/json",
    );
  }, [report, scanId]);

  const handleDownloadPdf = useCallback(async () => {
    setBusy("pdf");
    setNotice("");
    try {
      const blob = await downloadReportPdf(scanId);
      saveBlob(blob, `sentrystrike-${scanId}.pdf`);
    } catch (err) {
      setNotice(err.message || "Could not download the PDF.");
    } finally {
      setBusy("");
    }
  }, [scanId]);

  if (loading) {
    return (
      <div className='page-wide'>
        <div className='card report-state'>
          <CircleNotch className='spin' size={26} weight='bold' />
          <p>Loading report</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className='page-wide'>
        <button className='report-back' onClick={onBack}>
          <ArrowLeft size={15} weight='bold' /> Back
        </button>
        <div className='card report-state'>
          <div className='auth-error' style={{ marginBottom: 8 }}>
            <WarningCircle size={16} weight='fill' /> {error}
          </div>
          <button
            className='btn-ghost'
            style={{ maxWidth: 200 }}
            onClick={() => load()}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!report) return null;

  const stats = report.statistics || {};
  const breakdown = stats.severity_breakdown || {};
  const vulns = (report.vulnerabilities || [])
    .slice()
    .sort((a, b) => {
      const s =
        (SEV_ORDER[sevKey(a.severity)] ?? 9) -
        (SEV_ORDER[sevKey(b.severity)] ?? 9);
      return s !== 0 ? s : (b.cvss_score || 0) - (a.cvss_score || 0);
    });
  const filtered =
    filter === "all"
      ? vulns
      : vulns.filter((v) => sevKey(v.severity) === filter);

  const riskScore = Math.round(report.risk_score || 0);
  const rating = riskRating(riskScore);
  const techs = report.technology_stack || [];
  const chains = report.attack_chains || [];
  const limitations = report.scanner_limitations || [];
  const auth = report.authorization || {};

  // Coverage data the backend returns but the UI previously ignored.
  const evidence = report.evidence_strength_breakdown || {};
  const spa = report.spa_api_coverage || {};
  const authCov = report.auth_coverage || {};
  const warnings = report.report_metadata?.coverage_warnings || [];

  const stat = [
    {
      label: "Vulnerabilities",
      value: stats.total_vulnerabilities ?? vulns.length,
    },
    { label: "URLs crawled", value: stats.total_urls_crawled ?? "-" },
    { label: "Info findings", value: breakdown.info ?? 0 },
    { label: "Technologies", value: techs.length },
  ];

  const evidenceTiles = [
    { label: "Confirmed exploit", value: evidence.confirmed_exploit ?? 0 },
    {
      label: "Confirmed observation",
      value: evidence.confirmed_observation ?? 0,
    },
    { label: "Probable", value: evidence.probable ?? 0 },
    { label: "Possible", value: evidence.possible ?? 0 },
    { label: "Informational", value: evidence.informational ?? 0 },
  ];

  return (
    <div className='page-wide'>
      <button className='report-back' onClick={onBack}>
        <ArrowLeft size={15} weight='bold' /> Back
      </button>
      <h1 className='report-title'>
        Security Assessment <span>Report</span>
      </h1>

      {notice && <div className='auth-notice'>{notice}</div>}

      <div className='card target-card'>
        <div className='report-header-grid'>
          <div>
            <div className='target-label'>Target</div>
            <div className='target-url'>
              <Globe size={17} weight='bold' />
              <code>{target || report.scan_id}</code>
            </div>
            <div className='target-meta'>
              <span>
                <Clock size={13} /> {formatDate(report.generated_at)}
              </span>
              <span>
                Overall Risk: <SeverityBadge severity={rating} />
              </span>
              {auth.confirmed && (
                <span>
                  <CheckCircle size={13} weight='fill' /> Authorized
                </span>
              )}
            </div>
          </div>
          <ScoreRing score={riskScore} caption='Risk / 100' higherIsWorse />
        </div>
      </div>

      {/* Export controls sit at the top, before the report body. */}
      <div className='dl-section' style={{ marginTop: "1.5rem" }}>
        <div>
          <div className='dl-title'>Export this report</div>
          <div className='dl-sub'>
            Download the full findings as a formatted PDF or raw JSON.
          </div>
        </div>
        <div className='dl-buttons'>
          <button
            className='btn-dl btn-dl-primary'
            onClick={handleDownloadPdf}
            disabled={busy === "pdf"}
          >
            {busy === "pdf" ? (
              <>
                <CircleNotch className='spin' size={16} weight='bold' /> Building
                PDF
              </>
            ) : (
              <>
                <DownloadSimple size={16} weight='bold' /> Download PDF
              </>
            )}
          </button>
          <button
            className='btn-dl btn-dl-secondary'
            onClick={handleDownloadJson}
          >
            <FileText size={16} weight='bold' /> Download JSON
          </button>
        </div>
      </div>

      {report.executive_summary && (
        <div style={{ marginTop: "2rem" }}>
          <div className='section-head'>Executive Summary</div>
          <div className='card'>
            <p className='vuln-text' style={{ whiteSpace: "pre-line" }}>
              {report.executive_summary}
            </p>
          </div>
        </div>
      )}

      <div className='stat-row' style={{ marginTop: "1.5rem" }}>
        {stat.map((s) => (
          <div key={s.label} className='stat-tile'>
            <div className='stat-value'>{s.value}</div>
            <div className='stat-label'>{s.label}</div>
          </div>
        ))}
      </div>

      <div style={{ marginTop: "2rem" }}>
        <div className='section-head'>Severity Breakdown</div>
        <div className='summary-grid'>
          {[
            { sev: "critical", label: "Critical" },
            { sev: "high", label: "High Risk" },
            { sev: "medium", label: "Medium Risk" },
            { sev: "low", label: "Low Risk" },
          ].map(({ sev, label }) => {
            const m = SEVERITY_META[sev];
            const Icon = m.Icon;
            return (
              <div
                key={sev}
                className='summary-card'
                style={{ background: m.bg, borderColor: m.border }}
              >
                <div className='summary-card-icon' style={{ color: m.color }}>
                  <Icon size={22} weight='bold' />
                </div>
                <div className='summary-card-value' style={{ color: m.color }}>
                  {breakdown[sev] ?? 0}
                </div>
                <div className='summary-card-label' style={{ color: m.color }}>
                  {label}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div style={{ marginTop: "2rem" }}>
        <div className='section-head'>Evidence Strength</div>
        <div className='stat-row'>
          {evidenceTiles.map((t) => (
            <div key={t.label} className='stat-tile'>
              <div className='stat-value'>{t.value}</div>
              <div className='stat-label'>{t.label}</div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ marginTop: "2rem" }}>
        <div className='section-head'>
          Detailed Findings ({vulns.length}{" "}
          {vulns.length === 1 ? "vulnerability" : "vulnerabilities"})
        </div>
        <div className='filter-tabs'>
          {[
            ["all", "All", "var(--blue-solid)"],
            ...SEVERITIES.map((s) => [
              s,
              SEVERITY_META[s].label,
              SEVERITY_META[s].color,
            ]),
          ].map(([val, lbl, col]) => (
            <button
              key={val}
              className={`filter-tab ${filter === val ? "active" : ""}`}
              style={filter === val ? { background: col, color: "#06120c" } : {}}
              onClick={() => setFilter(val)}
            >
              {lbl}
            </button>
          ))}
        </div>
        {filtered.length === 0 ? (
          <div className='empty-state'>
            <ShieldCheck size={30} weight='bold' />
            {vulns.length === 0
              ? "No vulnerabilities were found for this target."
              : "No findings for this severity."}
          </div>
        ) : (
          filtered.map((v, i) => (
            <VulnerabilityCard key={v.id} vuln={v} defaultOpen={i === 0} />
          ))
        )}
      </div>

      <div className='two-col' style={{ marginTop: "2rem" }}>
        <div>
          <div className='section-head'>AI Analysis · Attack Chains</div>
          {chains.length === 0 ? (
            <div
              className='card card-sm'
              style={{ color: "var(--text-2)", fontSize: 13 }}
            >
              No attack chains were identified.
            </div>
          ) : (
            chains.map((c, i) => (
              <div key={c.id || i} className='chain-card'>
                <div className='chain-icon'>
                  <Lightning size={18} weight='bold' />
                </div>
                <div>
                  <div className='chain-title'>
                    Attack chain {i + 1}
                    {c.severity && (
                      <SeverityBadge severity={sevKey(c.severity)} />
                    )}
                  </div>
                  <div className='chain-desc'>{c.description}</div>
                </div>
              </div>
            ))
          )}
        </div>
        <div>
          <div className='section-head'>Technology Stack</div>
          <div className='card card-sm'>
            {techs.length === 0 ? (
              <div style={{ color: "var(--text-2)", fontSize: 13 }}>
                No technologies fingerprinted.
              </div>
            ) : (
              <div className='tech-list'>
                {techs.map((t, i) => (
                  <div key={`${t.name}-${i}`} className='tech-chip'>
                    <span className='tech-name'>
                      {t.name}
                      {t.version ? ` ${t.version}` : ""}
                    </span>
                    {(t.cves || []).length > 0 && (
                      <span className='cve-chip'>{t.cves.length} CVE</span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      <div className='two-col' style={{ marginTop: "2rem" }}>
        <div>
          <div className='section-head'>Authenticated Coverage</div>
          <div className='card card-sm'>
            <div className='kv-list'>
              <KV k='Session state' v={prettify(authCov.state)} />
              <KV
                k='Authenticated URLs'
                v={authCov.authenticated_url_count ?? 0}
              />
              <KV
                k='Unauthenticated URLs'
                v={authCov.unauthenticated_url_count ?? 0}
              />
              <KV
                k='Protected targets verified'
                v={authCov.protected_targets_verified ?? 0}
              />
              <KV
                k='Auth headers present'
                v={boolText(authCov.auth_headers_present)}
              />
              <KV
                k='Session cookies present'
                v={boolText(authCov.session_cookies_present)}
              />
            </div>
          </div>
        </div>
        <div>
          <div className='section-head'>SPA / API Coverage</div>
          <div className='card card-sm'>
            <div className='kv-list'>
              <KV k='SPA detected' v={boolText(spa.spa_detected)} />
              <KV k='Routes extracted' v={spa.routes_extracted ?? 0} />
              <KV k='API endpoints' v={spa.api_endpoints_extracted ?? 0} />
              <KV k='Parameters extracted' v={spa.parameters_extracted ?? 0} />
              <KV
                k='Browser requests observed'
                v={spa.browser_requests_observed ?? 0}
              />
              <KV k='Dynamic status' v={prettify(spa.dynamic_status)} />
            </div>
          </div>
        </div>
      </div>

      {warnings.length > 0 && (
        <div style={{ marginTop: "2rem" }}>
          <div className='section-head'>
            <Warning size={13} weight='bold' /> Coverage Warnings
          </div>
          <div className='card card-sm coverage-warn'>
            <ul className='note-list'>
              {warnings.map((line, i) => (
                <li key={i}>{line}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {limitations.length > 0 && (
        <div style={{ marginTop: "2rem" }}>
          <div className='section-head'>Scanner Coverage Notes</div>
          <div className='card card-sm'>
            <ul className='note-list'>
              {limitations.map((line, i) => (
                <li key={i}>{line}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}

export default ReportPage;
