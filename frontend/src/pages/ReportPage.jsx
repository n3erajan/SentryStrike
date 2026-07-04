import { useState, useEffect, useCallback } from "react";
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

function riskRating(score) {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  if (score > 0) return "low";
  return "safe";
}

function formatDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
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
        <div className='card card-elevated report-state'>
          <span className='spin' style={{ color: "var(--accent)", fontSize: 22 }}>
            ⟳
          </span>
          <p>Loading report…</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className='page-wide'>
        <button className='report-back' onClick={onBack}>
          ← New scan
        </button>
        <div className='card card-elevated report-state'>
          <div className='auth-error' style={{ marginBottom: 16 }}>{error}</div>
          <button className='btn-ghost' style={{ maxWidth: 200 }} onClick={() => load()}>
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
      const s = (SEV_ORDER[sevKey(a.severity)] ?? 9) - (SEV_ORDER[sevKey(b.severity)] ?? 9);
      return s !== 0 ? s : (b.cvss_score || 0) - (a.cvss_score || 0);
    });
  const filtered =
    filter === "all" ? vulns : vulns.filter((v) => sevKey(v.severity) === filter);

  const riskScore = Math.round(report.risk_score || 0);
  const rating = riskRating(riskScore);
  const techs = report.technology_stack || [];
  const chains = report.attack_chains || [];
  const limitations = report.scanner_limitations || [];
  const auth = report.authorization || {};

  const stat = [
    { label: "Vulnerabilities", value: stats.total_vulnerabilities ?? vulns.length },
    { label: "URLs crawled", value: stats.total_urls_crawled ?? "—" },
    { label: "Info findings", value: breakdown.info ?? 0 },
    { label: "Technologies", value: techs.length },
  ];

  return (
    <div className='page-wide'>
      <button className='report-back' onClick={onBack}>
        ← New scan
      </button>
      <h1 className='report-title'>
        Security Assessment <span className='gtext'>Report</span>
      </h1>

      {notice && <div className='auth-notice'>{notice}</div>}

      <div className='card card-elevated target-card'>
        <div className='report-header-grid'>
          <div>
            <div className='target-label'>Target</div>
            <div className='target-url'>
              <span>🌐</span>
              <code style={{ fontFamily: "var(--mono)", fontSize: 15 }}>
                {target || report.scan_id}
              </code>
            </div>
            <div className='target-meta'>
              <span>🕐 {formatDate(report.generated_at)}</span>
              <span>
                Overall Risk: <SeverityBadge severity={rating} />
              </span>
              {auth.confirmed && <span>✅ Authorized</span>}
            </div>
          </div>
          <ScoreRing score={riskScore} caption='Risk / 100' higherIsWorse />
        </div>
      </div>

      {report.executive_summary && (
        <div style={{ marginTop: "2rem" }}>
          <div className='section-head'>Executive Summary</div>
          <div className='card card-elevated'>
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
            return (
              <div
                key={sev}
                className='summary-card'
                style={{ background: m.bg, borderColor: m.border }}
              >
                <div className='summary-card-icon'>{m.icon}</div>
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
        <div className='section-head'>
          Detailed Findings ({vulns.length}{" "}
          {vulns.length === 1 ? "vulnerability" : "vulnerabilities"})
        </div>
        <div className='filter-tabs'>
          {[
            ["all", "All", "var(--accent)"],
            ...SEVERITIES.map((s) => [s, SEVERITY_META[s].label, SEVERITY_META[s].color]),
          ].map(([val, lbl, col]) => (
            <button
              key={val}
              className={`filter-tab ${filter === val ? "active" : ""}`}
              style={
                filter === val
                  ? { background: col, color: val === "all" ? "#060d12" : "#fff" }
                  : {}
              }
              onClick={() => setFilter(val)}
            >
              {lbl}
            </button>
          ))}
        </div>
        {filtered.length === 0 ? (
          <div
            className='card'
            style={{ textAlign: "center", color: "var(--text2)", padding: "2rem" }}
          >
            {vulns.length === 0
              ? "No vulnerabilities were found for this target. 🎉"
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
          <div className='section-head'>🤖 AI Analysis · Attack Chains</div>
          {chains.length === 0 ? (
            <div className='card card-sm' style={{ color: "var(--text2)", fontSize: 13 }}>
              No attack chains were identified.
            </div>
          ) : (
            chains.map((c, i) => (
              <div key={c.id || i} className='chain-card'>
                <div className='chain-icon'>⚡</div>
                <div>
                  <div className='chain-title'>
                    Attack chain {i + 1}
                    {c.severity && (
                      <span style={{ marginLeft: 8 }}>
                        <SeverityBadge severity={sevKey(c.severity)} />
                      </span>
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
              <div style={{ color: "var(--text2)", fontSize: 13 }}>
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

      <div className='dl-section' style={{ marginTop: "2rem" }}>
        <div className='dl-title'>Export this report</div>
        <div className='dl-sub'>
          Share findings with your security team or auditors in a standard format.
        </div>
        <div className='dl-buttons'>
          <button
            className='btn-dl btn-dl-primary'
            onClick={handleDownloadPdf}
            disabled={busy === "pdf"}
          >
            {busy === "pdf" ? "Building PDF…" : "📥 Download PDF"}
          </button>
          <button className='btn-dl btn-dl-secondary' onClick={handleDownloadJson}>
            📄 Download JSON Data
          </button>
        </div>
      </div>
    </div>
  );
}

export default ReportPage;
