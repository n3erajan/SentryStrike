import { useNavigate } from "react-router-dom";
import { ArrowRight, CircleNotch, File as FileIcon, Plus, Pulse, ShieldCheck, TreeStructure, WarningCircle } from "@phosphor-icons/react";
import { useActiveScans } from "../hooks/useActiveScans.js";
import { useBackendHealth } from "../hooks/useBackendHealth.js";

const STATUS_LABEL = { queued: "Queued", running: "Running" };
const button = "inline-flex min-h-9 items-center justify-center gap-2 rounded-md bg-[#006de2] px-3.5 text-[11px] font-semibold text-white transition hover:bg-[#004bb7] active:translate-y-px focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#006de2]";

function formatDate(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "-" : d.toLocaleString();
}

function ActiveScansPage() {
  const navigate = useNavigate();
  const { scans, loading, error } = useActiveScans();
  const { health } = useBackendHealth();
  const workerCount = health?.active_scanners;

  return (
    <div className='mx-auto w-full max-w-[1440px] px-4 py-8 sm:px-6 lg:px-8 lg:py-10'>
      <header className='flex flex-col gap-5 border-b border-[#cbd5e3] pb-7 sm:flex-row sm:items-end sm:justify-between'>
        <div>
          <span className='text-[10px] font-semibold uppercase tracking-[0.16em] text-[#006de2]'>Scanner queue</span>
          <h1 className='mt-2 text-3xl font-semibold leading-tight text-[#172033]'>Active scans</h1>
          <p className='mt-2 max-w-[60ch] text-[12px] leading-6 text-[#415166]'>Queued and running scans remain visible here while scanner workers process them.</p>
        </div>
        <div className='flex flex-wrap items-center gap-3'>
          {Number.isInteger(workerCount) && <div className={`flex min-h-9 items-center gap-2 border-l-2 px-3 text-[10px] font-semibold ${workerCount === 0 ? "border-[#de3d34] text-[#de3d34]" : "border-[#1c8742] text-[#1c8742]"}`}>{workerCount === 0 ? <WarningCircle size={15} weight='fill' /> : <Pulse size={15} weight='bold' />}{workerCount === 0 ? "No scanner workers online" : `${workerCount} scanner ${workerCount === 1 ? "worker" : "workers"} online`}</div>}
          <button className={button} onClick={() => navigate("/scan")}><Plus size={15} weight='bold' />New scan</button>
        </div>
      </header>

      <section className='mt-7 overflow-hidden border border-[#cbd5e3] bg-white' aria-label='Active scans'>
        <div className='hidden grid-cols-[112px_minmax(0,1fr)_160px_88px_32px] gap-4 border-b border-[#cbd5e3] bg-[#f8f9fb] px-5 py-3 text-[9px] font-semibold uppercase tracking-[0.12em] text-[#6f7c8c] md:grid'>
          <span>Status</span><span>Target</span><span>Started</span><span>Progress</span><span />
        </div>
        {loading && scans.length === 0 ? (
          <div className='flex min-h-48 flex-col items-center justify-center gap-3 text-[12px] text-[#6f7c8c]'><CircleNotch className='animate-spin text-[#006de2]' size={25} weight='bold' />Loading active scans</div>
        ) : error ? (
          <div className='m-5 flex items-start gap-2 rounded-md border border-[#efbbb7] bg-[#fff0ef] px-3 py-2.5 text-[12px] text-[#de3d34]'><WarningCircle size={16} weight='fill' />{error}</div>
        ) : scans.length === 0 ? (
          <div className='flex min-h-64 flex-col items-center justify-center px-6 text-center'><span className='grid size-12 place-items-center rounded-md bg-[#d4eaff] text-[#006de2]'><ShieldCheck size={24} weight='bold' /></span><h2 className='mt-4 text-[14px] font-semibold'>No scans are running</h2><p className='mt-1 max-w-sm text-[11px] leading-5 text-[#6f7c8c]'>Create a new scan and its live phase, progress, and worker state will appear here.</p><button className={`${button} mt-5`} onClick={() => navigate("/scan")}>New scan</button></div>
        ) : scans.map((scan) => {
          const CrawlIcon = scan.crawl_mode === "single" ? FileIcon : TreeStructure;
          return <button key={scan.id} className='grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-4 border-0 border-b border-[#e7ebf0] bg-white px-4 py-4 text-left transition last:border-b-0 hover:bg-[#f8faff] focus-visible:outline-2 focus-visible:outline-inset focus-visible:outline-[#006de2] md:grid-cols-[112px_minmax(0,1fr)_160px_88px_32px] md:px-5' onClick={() => navigate(`/active/${scan.id}`, { state: { target: scan.target_url } })}>
            <span className={`row-start-1 w-fit rounded px-2 py-1 text-[9px] font-bold ${scan.status === "running" ? "bg-[#e7f7ef] text-[#1c8742]" : "bg-[#fff4dc] text-[#925f05]"}`}>{STATUS_LABEL[scan.status] || scan.status}</span>
            <span className='col-span-2 min-w-0 md:col-span-1'><span className='block truncate font-mono text-[11px] font-semibold text-[#0a1421]'>{scan.target_url}</span><span className='mt-1 flex items-center gap-1.5 text-[9px] text-[#6f7c8c]'><CrawlIcon size={11} weight='bold' />{scan.crawl_mode === "single" ? "Single page" : "Full site"}<span className='md:hidden'>Ãƒâ€šÃ‚Â· {formatDate(scan.created_at)}</span></span></span>
            <span className='hidden text-[10px] text-[#415166] md:block'>{formatDate(scan.created_at)}</span>
            <span className='col-span-2 flex items-center gap-2 md:col-span-1'><span className='h-1.5 flex-1 overflow-hidden bg-[#e8ecf2] md:w-14'><span className='block h-full bg-[#006de2]' style={{ width: `${scan.progress || 0}%` }} /></span><span className='w-8 text-right font-mono text-[9px] text-[#415166]'>{scan.progress || 0}%</span></span>
            <ArrowRight className='hidden text-[#6f7c8c] md:block' size={15} weight='bold' />
          </button>;
        })}
      </section>
    </div>
  );
}

export default ActiveScansPage;
