import { useState } from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { List, Plus } from "@phosphor-icons/react";
import Sidebar from "./Sidebar.jsx";

function crumbFor(pathname) {
  if (pathname.includes("/report/")) return "History / Security report";
  if (pathname.includes("/active/")) return "Active scans / Live scan";
  if (pathname.endsWith("/active")) return "Active scans";
  if (pathname.endsWith("/history")) return "Scan history";
  return "New scan";
}

function AppLayout() {
  const location = useLocation();
  const navigate = useNavigate();
  const [menuOpen, setMenuOpen] = useState(false);
  const onScanPage = location.pathname.endsWith("/scan");

  return (
    <div className='min-h-dvh bg-[#f6f9fd] font-sans text-[#172033] lg:grid lg:grid-cols-[224px_minmax(0,1fr)]'>
      <Sidebar open={menuOpen} onClose={() => setMenuOpen(false)} />
      <div className='min-w-0'>
        <header className='sticky top-0 z-20 flex h-16 items-center justify-between border-b border-[#cbd5e3] bg-white/95 px-4 backdrop-blur-md sm:px-6 lg:px-8'>
          <div className='flex min-w-0 items-center gap-3'>
            <button className='grid size-9 shrink-0 place-items-center rounded-md border border-[#cbd5e3] bg-white text-[#415166] transition hover:bg-[#e8eff8] active:translate-y-px focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#006de2] lg:hidden' onClick={() => setMenuOpen(true)} aria-label='Open navigation'>
              <List size={19} weight='bold' />
            </button>
            <div className='truncate text-[12px] text-[#6f7c8c]'>SentryStrike <span className='px-1 text-[#cbd5e3]'>/</span> <b className='font-semibold text-[#0a1421]'>{crumbFor(location.pathname)}</b></div>
          </div>
          {!onScanPage && (
            <button className='inline-flex min-h-9 shrink-0 items-center justify-center gap-2 rounded-md bg-[#006de2] px-3.5 text-[12px] font-semibold text-white transition hover:bg-[#004bb7] active:translate-y-px focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#006de2]' onClick={() => navigate("/scan")}>
              <Plus size={15} weight='bold' /> <span className='hidden sm:inline'>New scan</span>
            </button>
          )}
        </header>
        <main id='main-content' className='min-w-0'><Outlet /></main>
      </div>
    </div>
  );
}

export default AppLayout;
