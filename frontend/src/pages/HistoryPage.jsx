import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowRight, CircleNotch, ClockCounterClockwise, File as FileIcon, Plus, TreeStructure, WarningCircle } from "@phosphor-icons/react";
import { listScans } from "../services/scan.js";

const STATUS_LABEL = { queued: "Queued", running: "Running", completed: "Completed", failed: "Failed", cancelled: "Cancelled" };
const statusClass = { queued: "bg-[#fff4dc] text-[#925f05]", running: "bg-[#e7f7ef] text-[#1c8742]", completed: "bg-[#d4eaff] text-[#004bb7]", failed: "bg-[#fff0ef] text-[#de3d34]", cancelled: "bg-[#eef1f5] text-[#415166]" };
const button = "inline-flex min-h-9 items-center justify-center gap-2 rounded-md bg-[#006de2] px-3.5 text-[11px] font-semibold text-white transition hover:bg-[#004bb7] active:translate-y-px focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#006de2]";

function formatDate(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "-" : d.toLocaleString();
}

function HistoryPage() {
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const load = useCallback(async (signal) => {
    setLoading(true); setError("");
    try { const data = await listScans({ signal }); setScans(Array.isArray(data?.items) ? data.items : []); }
    catch (err) { if (err.name !== "AbortError") setError(err.message || "Could not load your scans."); }
    finally { if (!signal || !signal.aborted) setLoading(false); }
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch-on-mount
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  return (
    <div className='mx-auto w-full max-w-[1440px] px-4 py-8 sm:px-6 lg:px-8 lg:py-10'>
      <header className='flex flex-col gap-5 border-b border-[#cbd5e3] pb-7 sm:flex-row sm:items-end sm:justify-between'>
        <div><span className='text-[10px] font-semibold uppercase tracking-[0.16em] text-[#006de2]'>Scan ledger</span><h1 className='mt-2 text-3xl font-semibold leading-tight'>Scan history</h1><p className='mt-2 max-w-[60ch] text-[12px] leading-6 text-[#415166]'>Review completed reports or return to a scan that is still in progress.</p></div>
        <button className={button} onClick={() => navigate("/scan")}><Plus size={15} weight='bold' />New scan</button>
      </header>
      <section className='mt-7 overflow-hidden border border-[#cbd5e3] bg-white'>
        <div className='hidden grid-cols-[112px_minmax(0,1fr)_170px_160px_32px] gap-4 border-b border-[#cbd5e3] bg-[#f8f9fb] px-5 py-3 text-[9px] font-semibold uppercase tracking-[0.12em] text-[#6f7c8c] md:grid'><span>Status</span><span>Target</span><span>Started</span><span>Last activity</span><span /></div>
        {loading ? <div className='flex min-h-48 flex-col items-center justify-center gap-3 text-[12px] text-[#6f7c8c]'><CircleNotch className='animate-spin text-[#006de2]' size={25} weight='bold' />Loading your scans</div>
        : error ? <div className='flex min-h-48 flex-col items-center justify-center gap-4 p-5'><div className='flex items-start gap-2 rounded-md border border-[#efbbb7] bg-[#fff0ef] px-3 py-2.5 text-[12px] text-[#de3d34]'><WarningCircle size={16} weight='fill' />{error}</div><button className='text-[11px] font-semibold text-[#006de2]' onClick={() => load()}>Retry</button></div>
        : scans.length === 0 ? <div className='flex min-h-64 flex-col items-center justify-center px-6 text-center'><ClockCounterClockwise className='text-[#006de2]' size={30} weight='bold' /><h2 className='mt-4 text-[14px] font-semibold'>No scan history yet</h2><p className='mt-1 text-[11px] text-[#6f7c8c]'>Your first scan will be recorded here.</p><button className={`${button} mt-5`} onClick={() => navigate("/scan")}>New scan</button></div>
        : scans.map((scan) => {
          const completed = scan.status === "completed";
          const active = scan.status === "queued" || scan.status === "running";
          const openable = completed || active;
          const CrawlIcon = scan.crawl_mode === "single" ? FileIcon : TreeStructure;
          const open = () => completed ? navigate(`/report/${scan.id}`, { state: { target: scan.target_url } }) : active && navigate(`/active/${scan.id}`, { state: { target: scan.target_url } });
          return <button key={scan.id} disabled={!openable} className='grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-4 border-0 border-b border-[#e7ebf0] bg-white px-4 py-4 text-left transition last:border-b-0 enabled:hover:bg-[#f8faff] disabled:cursor-default focus-visible:outline-2 focus-visible:outline-inset focus-visible:outline-[#006de2] md:grid-cols-[112px_minmax(0,1fr)_170px_160px_32px] md:px-5' onClick={open}>
            <span className={`w-fit rounded px-2 py-1 text-[9px] font-bold ${statusClass[scan.status] || statusClass.cancelled}`}>{STATUS_LABEL[scan.status] || scan.status}</span>
            <span className='col-span-2 min-w-0 md:col-span-1'><span className='block truncate font-mono text-[11px] font-semibold text-[#0a1421]'>{scan.target_url}</span><span className='mt-1 flex items-center gap-1.5 text-[9px] text-[#6f7c8c]'><CrawlIcon size={11} weight='bold' />{scan.crawl_mode === "single" ? "Single page" : "Full site"}</span></span>
            <span className='hidden text-[10px] text-[#415166] md:block'>{formatDate(scan.created_at)}</span>
            <span className='col-span-2 truncate text-[10px] text-[#415166] md:col-span-1'>{scan.status === "running" ? `${scan.progress}% Ãƒâ€šÃ‚Â· ${scan.phase_message || "Scanning"}` : scan.phase_message || STATUS_LABEL[scan.status]}</span>
            {openable && <ArrowRight className='hidden text-[#6f7c8c] md:block' size={15} weight='bold' />}
          </button>;
        })}
      </section>
    </div>
  );
}

export default HistoryPage;
