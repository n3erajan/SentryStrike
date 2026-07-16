import { NavLink, useNavigate } from "react-router-dom";
import { ShieldCheck, SignOut } from "@phosphor-icons/react";
import { NAV_ITEMS } from "../data/constants.js";
import { useAuth } from "../context/AuthContext.jsx";
import { useActiveScans } from "../hooks/useActiveScans.js";

function Sidebar({ open = false, onClose }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const { count } = useActiveScans();

  async function handleLogout() {
    await logout();
    navigate("/", { replace: true });
  }

  return (
    <>
      {open && (
        <button
          className='fixed inset-0 z-30 bg-[#172033]/35 lg:hidden'
          onClick={onClose}
          aria-label='Close navigation'
        />
      )}
      <aside
        className={`fixed inset-y-0 left-0 z-40 flex w-56 flex-col border-r border-[#cbd5e3] bg-white px-3 py-5 transition-transform duration-200 lg:sticky lg:top-0 lg:h-dvh lg:translate-x-0 ${open ? "translate-x-0" : "-translate-x-full"}`}
      >
        <NavLink
          to='/scan'
          onClick={onClose}
          className='flex items-center gap-2.5 px-2 text-[16px] font-bold text-[#172033] no-underline'
        >
          <span className='grid size-8 place-items-center rounded-md bg-[#006de2] text-white'>
            <ShieldCheck size={18} weight='bold' />
          </span>
          SentryStrike
        </NavLink>

        <nav className='mt-4 grid gap-1' aria-label='Workspace'>
          {NAV_ITEMS.map(({ to, label, Icon, badge, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              onClick={onClose}
              className={({ isActive }) =>
                `flex min-h-10 items-center gap-3 rounded-md px-3 text-[12px] font-medium no-underline transition focus-visible:outline-2 focus-visible:outline-[#006de2] ${isActive ? "bg-[#d4eaff] text-[#004bb7]" : "text-[#415166] hover:bg-[#e8eff8] hover:text-[#172033]"}`
              }
            >
              <Icon size={17} weight='bold' />
              <span className='flex-1'>{label}</span>
              {badge === "active" && count > 0 && (
                <span className='min-w-5 rounded bg-[#006de2] px-1.5 py-0.5 text-center font-mono text-[9px] font-bold text-white'>
                  {count}
                </span>
              )}
            </NavLink>
          ))}
        </nav>
        <div className='mt-auto border-t border-[#cbd5e3] px-2 pt-4'>
          <b
            className='block truncate text-[10px] font-semibold text-[#0a1421]'
            title={user?.email}
          >
            {user?.email || "Signed in"}
          </b>
          <span className='mt-0.5 block text-[9px] text-[#6f7c8c]'>
            Authorized scans
          </span>
          <button
            className='mt-3 inline-flex items-center gap-2 border-0 bg-transparent p-0 text-[11px] font-semibold text-[#415166] transition hover:text-[#de3d34] focus-visible:outline-2 focus-visible:outline-[#006de2]'
            onClick={handleLogout}
          >
            <SignOut size={14} weight='bold' />
            Sign out
          </button>
        </div>
      </aside>
    </>
  );
}

export default Sidebar;
