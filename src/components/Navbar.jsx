function Navbar({ page, onGoScan, onGoReport, hasReport }) {
  return (
    <nav className='navbar'>
      <div
        className='logo'
        onClick={onGoScan}
        role='button'
        tabIndex={0}
        onKeyDown={(e) => e.key === "Enter" && onGoScan()}
      >
        <div className='logo-icon'>🛡</div>
        <div className='logo-text'>
          <div className='brand'>
            Sentry<span>Strike</span>
          </div>
          <div className='tagline'>AI-Powered Web Vulnerability Scanner</div>
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
          className={`nav-link ${page === "report" ? "active" : ""}`}
          onClick={onGoReport}
          disabled={!hasReport}
          title={!hasReport ? "Run a scan first" : undefined}
        >
          Report
        </button>
      </div>
    </nav>
  );
}

export default Navbar;
