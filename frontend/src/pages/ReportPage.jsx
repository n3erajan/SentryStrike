import React, { useState, useEffect } from "react";
import { buildReport } from "../utils/reportBuilder";
import SeverityBadge from "../components/SeverityBadge";
import ScoreRing from "../components/ScoringRing";
import VulnerabilityCard from "../components/VulnerabilityCard";
import { SEVERITIES, SEVERITY_META } from "../data/constants.js";

function ReportPage({ target, onBack }) {
  const report = buildReport(target);
  const [filter, setFilter] = useState("all");
  const dateStr = new Date(report.timestamp).toLocaleString();
  const filteredFindings =
    filter === "all"
      ? report.findings
      : report.findings.filter((f) => f.severity === filter);

  function handleDownload(kind) {
    if (kind === "html")
      downloadFile(
        buildHtmlReport(report, dateStr),
        "sentrystrike-report.html",
        "text/html",
      );
    else
      downloadFile(
        JSON.stringify(report, null, 2),
        "sentrystrike-report.json",
        "application/json",
      );
  }

  return (
    <div className='page-wide'>
      <button className='report-back' onClick={onBack}>
        ← New scan
      </button>
      <h1 className='report-title'>
        Security Assessment <span className='gtext'>Report</span>
      </h1>

      <div className='card card-elevated target-card'>
        <div className='report-header-grid'>
          <div>
            <div className='target-label'>Target</div>
            <div className='target-url'>
              <span>🌐</span>
              <code style={{ fontFamily: "var(--mono)", fontSize: 15 }}>
                {report.target}
              </code>
            </div>
            <div className='target-meta'>
              <span>🕐 {dateStr}</span>
              <span>
                ⏱ Duration:{" "}
                <strong style={{ color: "var(--text0)" }}>
                  {report.durationSec}s
                </strong>
              </span>
              <span>
                Overall Risk: <SeverityBadge severity={report.rating} />
              </span>
            </div>
          </div>
          <ScoreRing score={report.score} />
        </div>
      </div>

      <div style={{ marginTop: "2rem" }}>
        <div className='section-head'>Executive Summary</div>
        <div className='summary-grid'>
          {[
            { sev: "critical", label: "Critical", icon: "⬡" },
            { sev: "high", label: "High Risk", icon: "▲" },
            { sev: "medium", label: "Medium Risk", icon: "◆" },
            { sev: "low", label: "Low Risk", icon: "●" },
          ].map(({ sev, label, icon }) => {
            const m = SEVERITY_META[sev];
            return (
              <div
                key={sev}
                className='summary-card'
                style={{ background: m.bg, borderColor: m.border }}
              >
                <div className='summary-card-icon'>{icon}</div>
                <div className='summary-card-value' style={{ color: m.color }}>
                  {report.counts[sev]}
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
          Detailed Findings ({report.findings.length} vulnerabilities)
        </div>
        <div className='filter-tabs'>
          {[
            ["all", "All", "var(--accent)"],
            ...SEVERITIES.map((s) => [
              s,
              SEVERITY_META[s].label,
              SEVERITY_META[s].color,
            ]),
          ].map(([val, lbl, col]) => (
            <button
              key={val}
              className={`filter-tab ${filter === val ? "active" : ""}`}
              style={
                filter === val
                  ? {
                      background: col,
                      color: val === "all" ? "#060d12" : "#fff",
                    }
                  : {}
              }
              onClick={() => setFilter(val)}
            >
              {lbl}
            </button>
          ))}
        </div>
        {filteredFindings.length === 0 ? (
          <div
            className='card'
            style={{
              textAlign: "center",
              color: "var(--text2)",
              padding: "2rem",
            }}
          >
            No findings for this severity.
          </div>
        ) : (
          filteredFindings.map((f, i) => (
            <VulnerabilityCard key={f.id} finding={f} defaultOpen={i === 0} />
          ))
        )}
      </div>

      <div className='two-col' style={{ marginTop: "2rem" }}>
        <div>
          <div className='section-head'>🤖 AI Analysis · Attack Chains</div>
          {report.attackChains.map((c) => (
            <div key={c.title} className='chain-card'>
              <div className='chain-icon'>⚡</div>
              <div>
                <div className='chain-title'>{c.title}</div>
                <div className='chain-desc'>{c.description}</div>
              </div>
            </div>
          ))}
        </div>
        <div>
          <div className='section-head'>Scan Timeline</div>
          <div className='card card-sm'>
            <div className='timeline'>
              {report.timeline.map((item) => (
                <div key={item.label} className='tl-item'>
                  <div className='tl-track'>
                    <div className='tl-dot' />
                  </div>
                  <div className='tl-content'>
                    <div className='tl-label'>{item.label}</div>
                    <div className='tl-time'>{item.time}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className='dl-section' style={{ marginTop: "2rem" }}>
        <div className='dl-title'>Export this report</div>
        <div className='dl-sub'>
          Share findings with your security team or auditors in a standard
          format.
        </div>
        <div className='dl-buttons'>
          <button
            className='btn-dl btn-dl-primary'
            onClick={() => handleDownload("html")}
          >
            📥 Download HTML Report
          </button>
          <button
            className='btn-dl btn-dl-secondary'
            onClick={() => handleDownload("json")}
          >
            📄 Download JSON Data
          </button>
        </div>
      </div>
    </div>
  );
}

export default ReportPage;
