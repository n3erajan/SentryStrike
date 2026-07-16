import { useEffect } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import {
  ArrowLeft,
  ArrowRight,
  Check,
  CircleNotch,
  Globe,
  ShieldCheck,
  WarningCircle,
} from "@phosphor-icons/react";
import { useScanStatus } from "../hooks/useScanStatus.js";
import { SCAN_PHASES } from "../data/constants.js";

const STATUS_LABEL = {
  queued: "Queued",
  running: "Scanning",
  completed: "Complete",
  failed: "Failed",
  cancelled: "Cancelled",
};
function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) return "";
  if (seconds < 60) return `${Math.ceil(seconds)}s`;
  const minutes = Math.ceil(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const remainder = minutes % 60;
  return remainder ? `${hours}h ${remainder}m` : `${hours}h`;
}

function ActiveScanPage() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const target = location.state?.target || "";
  const {
    status,
    progress,
    phaseMessage,
    stageIdx,
    eta,
    logs,
    logRef,
    error,
    active,
    cancelling,
    cancel,
  } = useScanStatus(scanId);
  useEffect(() => {
    if (status !== "completed") return undefined;
    const id = setTimeout(() => navigate(`/report/${scanId}`), 1200);
    return () => clearTimeout(id);
  }, [status, scanId, navigate]);

  return (
    <div className='mx-auto w-full max-w-[1240px] px-4 py-8 sm:px-6 lg:px-8 lg:py-10'>
      <button
        className='inline-flex items-center gap-2 border-0 bg-transparent p-0 text-[10px] font-semibold text-[#415166] hover:text-[#006de2] focus-visible:outline-2 focus-visible:outline-[#006de2]'
        onClick={() => navigate("/active")}
      >
        <ArrowLeft size={14} weight='bold' />
        All active scans
      </button>
      <header className='mt-6 border-b border-[#cbd5e3] pb-7'>
        <div className='flex flex-wrap items-center gap-3'>
          <span
            className={`rounded px-2 py-1 text-[9px] font-bold ${active ? "bg-[#e7f7ef] text-[#1c8742]" : status === "failed" ? "bg-[#fff0ef] text-[#de3d34]" : "bg-[#d4eaff] text-[#004bb7]"}`}
          >
            {STATUS_LABEL[status] || "Queued"}
          </span>
          <span className='font-mono text-[9px] text-[#6f7c8c]'>
            ID {scanId}
          </span>
        </div>
        <h1 className='mt-3 text-3xl font-semibold'>Live scan</h1>
        {target && (
          <div className='mt-3 flex min-w-0 items-center gap-2 text-[#415166]'>
            <Globe className='shrink-0' size={15} weight='bold' />
            <code className='truncate font-mono text-[11px]'>{target}</code>
          </div>
        )}
      </header>

      <div className='mt-7 grid gap-7 lg:grid-cols-[minmax(0,1fr)_290px]'>
        <section className='min-w-0 border border-[#cbd5e3] bg-white'>
          <div className='flex flex-col gap-4 border-b border-[#cbd5e3] p-5 sm:flex-row sm:items-start sm:justify-between'>
            <div>
              <span className='flex items-center gap-2 text-[12px] font-semibold text-[#0a1421]'>
                {active ? (
                  <CircleNotch
                    className='animate-spin text-[#006de2]'
                    size={16}
                    weight='bold'
                  />
                ) : (
                  <Check className='text-[#1c8742]' size={16} weight='bold' />
                )}
                {phaseMessage || STATUS_LABEL[status] || "Scan queued"}
              </span>
              {eta != null && eta > 0 && (
                <span className='mt-1 block text-[10px] text-[#6f7c8c]'>
                  About {formatDuration(eta)} remaining
                </span>
              )}
            </div>
            <span className='font-mono text-2xl font-semibold tabular-nums text-[#172033]'>
              {Math.round(progress)}%
            </span>
          </div>
          <div className='h-1.5 bg-[#e8ecf2]'>
            <div
              className='h-full bg-[#006de2] transition-[width] duration-500'
              style={{ width: `${progress}%` }}
            />
          </div>
          <div className='p-5'>
            {error && (
              <div className='mb-5 flex items-start gap-2 rounded-md border border-[#efbbb7] bg-[#fff0ef] px-3 py-2.5 text-[12px] text-[#de3d34]'>
                <WarningCircle size={16} weight='fill' />
                {error}
              </div>
            )}
            <div className='flex items-center justify-between'>
              <h2 className='text-[10px] font-semibold uppercase tracking-[0.13em] text-[#6f7c8c]'>
                Activity log
              </h2>
              <span className='text-[9px] text-[#a1aabb]'>Worker events</span>
            </div>
            <div
              className='mt-3 h-72 overflow-y-auto bg-[#172033] p-4 font-mono text-[10px] leading-6 text-[#b9c4d6]'
              ref={logRef}
            >
              {logs.length ? (
                logs.map((line, i) => (
                  <div
                    key={i}
                    className={
                      line.kind === "error"
                        ? "text-[#ff9b95]"
                        : line.kind === "warn"
                          ? "text-[#ffd27a]"
                          : ""
                    }
                  >
                    {line.text}
                  </div>
                ))
              ) : (
                <div className='text-[#78869e]'>
                  Waiting for scanner activity...
                </div>
              )}
            </div>
            <div className='mt-5 flex justify-end'>
              {active ? (
                <button
                  type='button'
                  className='min-h-9 rounded-md border border-[#de3d34] bg-white px-3.5 text-[10px] font-semibold text-[#de3d34] transition hover:bg-[#fff0ef] disabled:cursor-not-allowed disabled:opacity-50'
                  onClick={cancel}
                  disabled={cancelling}
                >
                  {cancelling ? "Cancellation requested" : "Cancel scan"}
                </button>
              ) : status === "completed" ? (
                <Link
                  to={`/report/${scanId}`}
                  className='inline-flex min-h-9 items-center gap-2 rounded-md bg-[#006de2] px-3.5 text-[10px] font-semibold text-white no-underline'
                >
                  <ShieldCheck size={15} weight='bold' />
                  View report
                  <ArrowRight size={14} weight='bold' />
                </Link>
              ) : (
                <Link
                  to='/scan'
                  className='inline-flex min-h-9 items-center rounded-md border border-[#cbd5e3] px-3.5 text-[10px] font-semibold text-[#415166] no-underline'
                >
                  Start a new scan
                </Link>
              )}
            </div>
          </div>
        </section>

        <aside className='border border-[#cbd5e3] bg-white p-5 lg:self-start'>
          <h2 className='text-[10px] font-semibold uppercase tracking-[0.13em] text-[#6f7c8c]'>
            Scan phases
          </h2>
          <ol className='mt-4 grid'>
            {SCAN_PHASES.slice(1).map((scanPhase, chipIndex) => {
              const phaseIndex = chipIndex + 1;
              const completed = status === "completed" || phaseIndex < stageIdx;
              const current = active && phaseIndex === stageIdx;
              return (
                <li
                  key={scanPhase.key}
                  className='grid grid-cols-[22px_minmax(0,1fr)] gap-2 border-l border-[#cbd5e3] pb-4 pl-3 last:border-transparent last:pb-0'
                >
                  <span
                    className={`-ml-[24px] grid size-[22px] place-items-center rounded-full border text-[9px] ${completed ? "border-[#1c8742] bg-[#1c8742] text-white" : current ? "border-[#006de2] bg-white text-[#006de2]" : "border-[#cbd5e3] bg-[#f8f9fb] text-[#a1aabb]"}`}
                  >
                    {completed ? <Check size={11} weight='bold' /> : phaseIndex}
                  </span>
                  <span
                    className={`pt-0.5 text-[10px] font-medium ${current ? "text-[#004bb7]" : completed ? "text-[#415166]" : "text-[#a1aabb]"}`}
                  >
                    {scanPhase.label}
                  </span>
                </li>
              );
            })}
          </ol>
        </aside>
      </div>
    </div>
  );
}

export default ActiveScanPage;
