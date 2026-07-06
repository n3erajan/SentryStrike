import { SignOut, UserCircle } from "@phosphor-icons/react";

function Navbar({
  page,
  onGoScan,
  onGoHistory,
  onGoReport,
  hasReport,
  user,
  onLogout,
}) {
  return (
    <nav className='navbar'>
      <div
        className='logo'
        onClick={onGoScan}
        role='button'
        tabIndex={0}
        onKeyDown={(e) => e.key === "Enter" && onGoScan()}
      >
        <div className='logo-icon'>
          <img src='/shield.png' alt='SentryStrike' className='logo-img' />
        </div>
        <div className='logo-text'>
          <div className='brand'>
            Sentry<span>Strike</span>
          </div>
          <div className='tagline'>Web Vulnerability Scanner</div>
        </div>
      </div>
      <div className='nav-links'>
        <button
          className={`nav-link ${page === "scan" ? "active" : ""}`}
          onClick={onGoScan}
        >
          Scan
        </button>
        <button
          className={`nav-link ${page === "history" ? "active" : ""}`}
          onClick={onGoHistory}
        >
          History
        </button>
        <button
          className={`nav-link ${page === "report" ? "active" : ""}`}
          onClick={onGoReport}
          disabled={!hasReport}
          title={!hasReport ? "Run a scan first" : undefined}
        >
          Report
        </button>
        {user?.email && (
          <span className='nav-profile' title={user.email}>
            <UserCircle size={20} weight='fill' />
            <span className='nav-user'>{user.email}</span>
          </span>
        )}
        <button className='nav-logout' onClick={onLogout}>
          <SignOut size={15} weight='bold' /> Logout
        </button>
      </div>
    </nav>
  );
}

export default Navbar;
