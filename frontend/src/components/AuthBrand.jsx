import {
  ShieldCheck,
  SealCheck,
  Robot,
  FileArrowDown,
} from "@phosphor-icons/react";

// Shared brand panel for the auth screens.
function AuthBrand() {
  return (
    <aside className='auth-brand'>
      <div className='auth-brand-top'>
        <div className='auth-brand-mark'>
          <img src='/shield.png' alt='' />
        </div>
        <div className='auth-brand-name'>
          Sentry<span>Strike</span>
        </div>
      </div>

      <div className='auth-brand-center'>
        <div className='auth-brand-eyebrow'>
          <ShieldCheck size={14} weight='bold' /> AI-Assisted Scanner
        </div>
        <h2 className='auth-brand-headline'>
          Find what attackers find, <span>before they do.</span>
        </h2>
        <p className='auth-brand-desc'>
          SentryStrike crawls your web target, runs OWASP Top 10 detectors,
          verifies findings against real evidence, and uses AI to explain the
          impact and remediation.
        </p>

        <div className='auth-brand-list'>
          <div className='auth-brand-list-item'>
            <ShieldCheck size={20} weight='bold' /> Detectors across the OWASP
            Top 10
          </div>
          <div className='auth-brand-list-item'>
            <SealCheck size={20} weight='bold' /> Evidence-based verification
            cuts false positives
          </div>
          <div className='auth-brand-list-item'>
            <Robot size={20} weight='bold' /> AI-written impact and remediation
            analysis
          </div>
          <div className='auth-brand-list-item'>
            <FileArrowDown size={20} weight='bold' /> Export-ready PDF and JSON
          </div>
        </div>
      </div>

      <div className='auth-brand-foot'>Web Vulnerability Scanner</div>
    </aside>
  );
}

export default AuthBrand;
