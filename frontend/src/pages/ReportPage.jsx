import { useCallback, useEffect, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, CheckCircle, CircleNotch, Clock, DownloadSimple, FileText, Globe, Lightning, Warning, WarningCircle } from "@phosphor-icons/react";
import ScoreRing from "../components/ScoringRing.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import VulnerabilityCard from "../components/VulnerabilityCard.jsx";
import { SEVERITIES, SEVERITY_META } from "../data/constants.js";
import { downloadReportPdf, getReport } from "../services/reports.js";
import { downloadFile, saveBlob } from "../utils/helpers.js";

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_STYLE = { critical: "border-[#efbbb7] bg-[#fff0ef] text-[#de3d34]", high: "border-[#f4c7a1] bg-[#fff5eb] text-[#b54708]", medium: "border-[#ead49a] bg-[#fff8e6] text-[#8a6108]", low: "border-[#a9ddc6] bg-[#edf9f3] text-[#1c8742]" };
const outlineButton = "inline-flex min-h-9 items-center justify-center gap-2 rounded-md border border-[#cfd7e3] bg-white px-3.5 text-[10px] font-semibold text-[#3f4b60] transition hover:bg-[#e8eff8] active:translate-y-px disabled:cursor-not-allowed disabled:opacity-50";
function sevKey(value) { return (value || "").toString().toLowerCase(); }
function prettify(value) { return value === null || value === undefined || value === "" ? "-" : value.toString().replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()); }
function boolText(value) { return value ? "Yes" : "No"; }
function riskRating(score) { return score >= 75 ? "critical" : score >= 50 ? "high" : score >= 25 ? "medium" : score > 0 ? "low" : "safe"; }
function formatDate(iso) { if (!iso) return "-"; const date = new Date(iso); return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString(); }
function KV({ label, value }) { return <div className='grid grid-cols-[minmax(0,1fr)_auto] gap-4 border-b border-[#edf0f4] py-2.5 last:border-0'><dt className='text-[9px] text-[#6f7c8c]'>{label}</dt><dd className='m-0 max-w-[16rem] truncate text-right font-mono text-[9px] font-semibold text-[#415166]' title={String(value)}>{value}</dd></div>; }
function Panel({ title, children, className = "" }) { return <section className={`border border-[#cbd5e3] bg-white ${className}`}><h2 className='border-b border-[#cbd5e3] px-4 py-3 text-[9px] font-semibold uppercase tracking-[0.12em] text-[#6f7c8c]'>{title}</h2><div className='p-4'>{children}</div></section>; }

function ReportPage() {
  const { scanId } = useParams(); const navigate = useNavigate(); const location = useLocation();
  const target = location.state?.target || "";
  const [report, setReport] = useState(null); const [loading, setLoading] = useState(true); const [error, setError] = useState(""); const [filter, setFilter] = useState("all"); const [busy, setBusy] = useState(""); const [notice, setNotice] = useState("");
  const load = useCallback(async (signal) => { setLoading(true); setError(""); try { setReport(await getReport(scanId, signal)); } catch (err) { if (err.name !== "AbortError") setError(err.message || "Could not load the report."); } finally { if (!signal || !signal.aborted) setLoading(false); } }, [scanId]);
  useEffect(() => {
    const controller = new AbortController();
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch-on-mount
    load(controller.signal);
    return () => controller.abort();
  }, [load]);
  const handleDownloadJson = useCallback(() => { if (report) downloadFile(JSON.stringify(report, null, 2), `sentrystrike-${scanId}.json`, "application/json"); }, [report, scanId]);
  const handleDownloadPdf = useCallback(async () => { setBusy("pdf"); setNotice(""); try { saveBlob(await downloadReportPdf(scanId), `sentrystrike-${scanId}.pdf`); } catch (err) { setNotice(err.message || "Could not download the PDF."); } finally { setBusy(""); } }, [scanId]);

  if (loading) return <div className='flex min-h-[calc(100dvh-64px)] items-center justify-center gap-3 text-[12px] text-[#6f7c8c]'><CircleNotch className='animate-spin text-[#006de2]' size={25} weight='bold' />Loading report</div>;
  if (error) return <div className='mx-auto max-w-3xl px-4 py-10'><button className='inline-flex items-center gap-2 text-[10px] font-semibold text-[#415166]' onClick={() => navigate("/history")}><ArrowLeft size={14} weight='bold' />Back</button><div className='mt-6 flex flex-col items-start gap-4 border border-[#efbbb7] bg-[#fff0ef] p-5 text-[12px] text-[#de3d34]'><span className='flex gap-2'><WarningCircle size={16} weight='fill' />{error}</span><button className={outlineButton} onClick={() => load()}>Retry</button></div></div>;
  if (!report) return null;

  const stats = report.statistics || {}; const breakdown = stats.severity_breakdown || {};
  const vulns = (report.vulnerabilities || []).slice().sort((a, b) => ((SEV_ORDER[sevKey(a.severity)] ?? 9) - (SEV_ORDER[sevKey(b.severity)] ?? 9)) || ((b.cvss_score || 0) - (a.cvss_score || 0)));
  const filtered = filter === "all" ? vulns : vulns.filter((vuln) => sevKey(vuln.severity) === filter);
  const riskScore = Math.round(report.risk_score || 0); const rating = riskRating(riskScore);
  const techs = report.technology_stack || []; const chains = report.attack_chains || []; const limitations = report.scanner_limitations || []; const auth = report.authorization || {};
  const evidence = report.evidence_strength_breakdown || {}; const spa = report.spa_api_coverage || {}; const authCov = report.auth_coverage || {}; const warnings = report.report_metadata?.coverage_warnings || [];
  const summaryStats = [["Vulnerabilities", stats.total_vulnerabilities ?? vulns.length], ["URLs crawled", stats.total_urls_crawled ?? "-"], ["Info findings", breakdown.info ?? 0], ["Technologies", techs.length]];

  return (
    <div className='mx-auto w-full max-w-[1440px] px-4 py-8 sm:px-6 lg:px-8 lg:py-10'>
      <button className='inline-flex items-center gap-2 border-0 bg-transparent p-0 text-[10px] font-semibold text-[#415166] hover:text-[#006de2]' onClick={() => navigate("/history")}><ArrowLeft size={14} weight='bold' />Scan history</button>
      <header className='mt-6 flex flex-col gap-5 border-b border-[#cbd5e3] pb-7 lg:flex-row lg:items-end lg:justify-between'>
        <div><span className='text-[10px] font-semibold uppercase tracking-[0.16em] text-[#006de2]'>Security scan</span><h1 className='mt-2 text-3xl font-semibold leading-tight'>Report</h1><div className='mt-3 flex min-w-0 flex-wrap items-center gap-x-5 gap-y-2 text-[9px] text-[#6f7c8c]'><span className='flex min-w-0 items-center gap-1.5'><Globe size={13} weight='bold' /><code className='max-w-[36rem] truncate font-mono'>{target || report.scan_id}</code></span><span className='flex items-center gap-1.5'><Clock size={13} />{formatDate(report.generated_at)}</span>{auth.confirmed && <span className='flex items-center gap-1.5 text-[#1c8742]'><CheckCircle size={13} weight='fill' />Authorized</span>}</div></div>
        <div className='flex flex-wrap gap-2'><button className={outlineButton} onClick={handleDownloadJson}><FileText size={14} weight='bold' />JSON</button><button className={`${outlineButton} border-[#006de2] bg-[#006de2] text-white hover:bg-[#004bb7]`} onClick={handleDownloadPdf} disabled={busy === "pdf"}>{busy === "pdf" ? <CircleNotch className='animate-spin' size={14} weight='bold' /> : <DownloadSimple size={14} weight='bold' />}{busy === "pdf" ? "Building PDF" : "Download PDF"}</button></div>
      </header>
      {notice && <div className='mt-5 border-l-2 border-[#de3d34] bg-[#fff0ef] px-4 py-3 text-[10px] text-[#de3d34]'>{notice}</div>}

      <div className='mt-7 grid gap-6 lg:grid-cols-[220px_minmax(0,1fr)]'>
        <aside className='grid gap-5 lg:sticky lg:top-24 lg:self-start'>
          <Panel title='Risk score'><div className='flex flex-col items-center'><ScoreRing score={riskScore} caption='Risk / 100' higherIsWorse /><div className='mt-3 flex items-center gap-2 text-[9px] text-[#6f7c8c]'>Overall risk <SeverityBadge severity={rating} /></div></div></Panel>
          <Panel title='Severity totals'><div className='grid gap-2'>{["critical", "high", "medium", "low", "info"].map((severity) => <div key={severity} className='flex items-center justify-between text-[9px]'><span className='capitalize text-[#415166]'>{severity}</span><strong className='font-mono text-[#0a1421]'>{breakdown[severity] ?? 0}</strong></div>)}</div></Panel>
        </aside>
        <main className='min-w-0 space-y-6'>
          {report.executive_summary && <Panel title='Executive summary'><p className='whitespace-pre-line text-[11px] leading-6 text-[#415166]'>{report.executive_summary}</p></Panel>}
          <section className='grid grid-cols-2 border border-[#cbd5e3] bg-white md:grid-cols-4'>{summaryStats.map(([label, value]) => <div key={label} className='border-b border-r border-[#cbd5e3] p-4 even:border-r-0 md:border-b-0 md:even:border-r md:last:border-r-0'><strong className='block font-mono text-xl font-semibold tabular-nums text-[#172033]'>{value}</strong><span className='mt-1 block text-[8px] uppercase tracking-[0.1em] text-[#6f7c8c]'>{label}</span></div>)}</section>
          <section><div className='mb-3 flex items-end justify-between gap-4'><div><span className='text-[9px] font-semibold uppercase tracking-[0.12em] text-[#6f7c8c]'>Detailed findings</span><h2 className='mt-1 text-[16px] font-semibold'>{vulns.length} {vulns.length === 1 ? "vulnerability" : "vulnerabilities"}</h2></div><div className='flex max-w-full gap-1 overflow-x-auto'>{[["all", "All"], ...SEVERITIES.map((severity) => [severity, SEVERITY_META[severity].label])].map(([value, label]) => <button key={value} className={`min-h-8 shrink-0 rounded px-2.5 text-[9px] font-semibold transition ${filter === value ? "bg-[#172033] text-white" : "border border-[#cbd5e3] bg-white text-[#415166] hover:bg-[#e8eff8]"}`} onClick={() => setFilter(value)}>{label}</button>)}</div></div><div className='grid gap-2'>{filtered.length ? filtered.map((vuln, index) => <VulnerabilityCard key={vuln.id} vuln={vuln} defaultOpen={index === 0} />) : <div className='border border-[#cbd5e3] bg-white px-5 py-12 text-center text-[11px] text-[#6f7c8c]'>No findings for this severity.</div>}</div></section>
          <div className='grid gap-6 xl:grid-cols-2'>
            <Panel title='Evidence strength'><dl>{[["Confirmed exploit", evidence.confirmed_exploit ?? 0], ["Confirmed observation", evidence.confirmed_observation ?? 0], ["Probable", evidence.probable ?? 0], ["Possible", evidence.possible ?? 0], ["Informational", evidence.informational ?? 0]].map(([label, value]) => <KV key={label} label={label} value={value} />)}</dl></Panel>
            <Panel title='Technology stack'>{techs.length ? <div className='grid gap-2'>{techs.map((tech, index) => <div key={`${tech.name}-${index}`} className='flex items-center justify-between border-b border-[#edf0f4] py-2 last:border-0'><span className='font-mono text-[9px] font-semibold text-[#415166]'>{tech.name}{tech.version ? ` ${tech.version}` : ""}</span>{(tech.cves || []).length > 0 && <span className='rounded bg-[#fff0ef] px-2 py-1 text-[8px] text-[#de3d34]'>{tech.cves.length} CVE</span>}</div>)}</div> : <p className='text-[10px] text-[#6f7c8c]'>No technologies fingerprinted.</p>}</Panel>
          </div>
          <div className='grid gap-6 xl:grid-cols-2'>
            <Panel title='Authenticated coverage'><dl><KV label='Session state' value={prettify(authCov.state)} /><KV label='Authenticated URLs' value={authCov.authenticated_url_count ?? 0} /><KV label='Unauthenticated URLs' value={authCov.unauthenticated_url_count ?? 0} /><KV label='Protected targets verified' value={authCov.protected_targets_verified ?? 0} /><KV label='Auth headers present' value={boolText(authCov.auth_headers_present)} /><KV label='Session cookies present' value={boolText(authCov.session_cookies_present)} /></dl></Panel>
            <Panel title='SPA and API coverage'><dl><KV label='SPA detected' value={boolText(spa.spa_detected)} /><KV label='Routes extracted' value={spa.routes_extracted ?? 0} /><KV label='API endpoints' value={spa.api_endpoints_extracted ?? 0} /><KV label='Parameters extracted' value={spa.parameters_extracted ?? 0} /><KV label='Browser requests' value={spa.browser_requests_observed ?? 0} /><KV label='Dynamic status' value={prettify(spa.dynamic_status)} /></dl></Panel>
          </div>
          <Panel title='Attack chains'>{chains.length ? <div className='grid gap-3'>{chains.map((chain, index) => <div key={chain.id || index} className='grid grid-cols-[28px_minmax(0,1fr)] gap-3 border-b border-[#edf0f4] pb-3 last:border-0 last:pb-0'><span className='grid size-7 place-items-center rounded-md bg-[#fff4dc] text-[#925f05]'><Lightning size={14} weight='bold' /></span><div><div className='flex items-center gap-2 text-[10px] font-semibold'>Attack chain {index + 1}{chain.severity && <SeverityBadge severity={sevKey(chain.severity)} />}</div><p className='mt-1 text-[9px] leading-5 text-[#415166]'>{chain.description}</p></div></div>)}</div> : <p className='text-[10px] text-[#6f7c8c]'>No attack chains were identified.</p>}</Panel>
          {(warnings.length > 0 || limitations.length > 0) && <Panel title='Coverage notes'><div className='grid gap-4'>{warnings.length > 0 && <div className={`border p-3 ${SEV_STYLE.medium}`}><h3 className='flex items-center gap-2 text-[9px] font-semibold'><Warning size={13} weight='bold' />Coverage warnings</h3><ul className='mt-2 grid gap-1 pl-4 text-[9px] leading-5'>{warnings.map((line, index) => <li key={index}>{line}</li>)}</ul></div>}{limitations.length > 0 && <ul className='grid gap-2 pl-4 text-[9px] leading-5 text-[#415166]'>{limitations.map((line, index) => <li key={index}>{line}</li>)}</ul>}</div></Panel>}
        </main>
      </div>
    </div>
  );
}

export default ReportPage;
