// Top brand bar for the login/registration screens.
// Mirrors the Navbar look but has no navigation.
function AuthHeader() {
  return (
    <header className='auth-topbar'>
      <div className='logo'>
        <div className='logo-icon'>
          <img src='/shield.png' alt='SentryStrike' className='logo-img' />
        </div>
        <div className='logo-text'>
          <div className='brand'>
            Sentry<span>Strike</span>
          </div>
          <div className='tagline'>AI-Powered Web Vulnerability Scanner</div>
        </div>
      </div>
    </header>
  );
}

export default AuthHeader;
