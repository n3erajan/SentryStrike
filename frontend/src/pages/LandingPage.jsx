import { Link } from "react-router-dom";
import {
  ShieldCheck,
  SealCheck,
  Robot,
  FileArrowDown,
  Pulse,
  LockKey,
  ArrowRight,
  GithubLogo,
} from "@phosphor-icons/react";

// Public product-description landing page shown on startup (route "/"). Signed-in
// users are redirected to the app by PublicOnlyRoute, so this is always the
// unauthenticated entry point. Reuses the existing brand voice from AuthBrand.

const FEATURES = [
  {
    Icon: ShieldCheck,
    title: "OWASP Top 10 detectors",
    desc: "Injection, XSS, broken access control, SSRF, security misconfiguration and more — run against your target in one pass.",
  },
  {
    Icon: SealCheck,
    title: "Evidence-based verification",
    desc: "Every finding is checked against real request and response evidence, so the report is signal, not a pile of false positives.",
  },
  {
    Icon: Robot,
    title: "AI impact & remediation",
    desc: "A local model explains what each issue means for your business and exactly how to fix it for your detected tech stack.",
  },
  {
    Icon: Pulse,
    title: "Concurrent scanning",
    desc: "Kick off a scan and start the next one immediately — SentryStrike runs them in parallel and tracks each on its own page.",
  },
  {
    Icon: LockKey,
    title: "Authenticated & IDOR testing",
    desc: "Supply test accounts to reach logged-in pages and prove horizontal and vertical access-control weaknesses.",
  },
  {
    Icon: FileArrowDown,
    title: "Export-ready reports",
    desc: "Hand results to your team as a formatted PDF or raw JSON, complete with severity breakdown and attack chains.",
  },
];

const STEPS = [
  ["01", "Create an account", "Sign up in seconds — no setup, no agents to install."],
  ["02", "Point at a target", "Enter a URL you're authorized to test and choose your crawl depth."],
  ["03", "Get a verified report", "Watch progress live, then review evidence-backed findings and remediation."],
];

function LandingPage() {
  return (
    <div className='landing'>
      <header className='landing-nav'>
        <div className='landing-brand'>
          <div className='logo-icon'>
            <img src='/shield.png' alt='' className='logo-img' />
          </div>
          <div className='landing-brand-name'>
            Sentry<span>Strike</span>
          </div>
        </div>
        <div className='landing-nav-actions'>
          <Link to='/login' className='landing-link'>
            Sign in
          </Link>
          <Link to='/register' className='btn-dl btn-dl-primary landing-cta-sm'>
            Get started
          </Link>
        </div>
      </header>

      <section className='landing-hero'>
        <div className='landing-eyebrow'>
          <ShieldCheck size={14} weight='bold' /> AI-Assisted Web Vulnerability Scanner
        </div>
        <h1 className='landing-headline'>
          Find what attackers find,
          <br />
          <span>before they do.</span>
        </h1>
        <p className='landing-sub'>
          SentryStrike crawls your web target, runs OWASP Top 10 detectors,
          verifies each finding against real evidence, and uses AI to explain
          the impact and the fix. Built for authorized security testing.
        </p>
        <div className='landing-hero-actions'>
          <Link to='/register' className='btn-primary landing-cta'>
            <ShieldCheck size={18} weight='bold' /> Create an account
          </Link>
          <Link to='/login' className='btn-ghost landing-cta'>
            Sign in <ArrowRight size={16} weight='bold' />
          </Link>
        </div>
        <p className='landing-consent-note'>
          For authorized testing only. Scan targets you own or have explicit
          permission to assess.
        </p>
      </section>

      <section className='landing-section'>
        <div className='landing-section-head'>
          <h2 className='landing-h2'>Everything you need to assess a web target</h2>
          <p className='landing-section-sub'>
            One scan surfaces the vulnerabilities, verifies them, and writes them
            up — end to end.
          </p>
        </div>
        <div className='landing-features'>
          {FEATURES.map(({ Icon, title, desc }) => (
            <div key={title} className='landing-feature card'>
              <div className='landing-feature-icon'>
                <Icon size={22} weight='bold' />
              </div>
              <div className='landing-feature-title'>{title}</div>
              <p className='landing-feature-desc'>{desc}</p>
            </div>
          ))}
        </div>
      </section>

      <section className='landing-section'>
        <div className='landing-section-head'>
          <h2 className='landing-h2'>How it works</h2>
        </div>
        <div className='landing-steps'>
          {STEPS.map(([num, title, desc]) => (
            <div key={num} className='landing-step'>
              <div className='landing-step-num'>{num}</div>
              <div className='landing-step-title'>{title}</div>
              <p className='landing-step-desc'>{desc}</p>
            </div>
          ))}
        </div>
      </section>

      <section className='landing-final card'>
        <h2 className='landing-h2'>Ready to run your first scan?</h2>
        <p className='landing-section-sub'>
          Create an account and point SentryStrike at an authorized target.
        </p>
        <div className='landing-hero-actions'>
          <Link to='/register' className='btn-primary landing-cta'>
            <ShieldCheck size={18} weight='bold' /> Get started free
          </Link>
        </div>
      </section>

      <footer className='landing-foot'>
        <span>SentryStrike — Web Vulnerability Scanner</span>
        <span className='landing-foot-meta'>
          <GithubLogo size={15} weight='bold' /> Educational · authorized use only
        </span>
      </footer>
    </div>
  );
}

export default LandingPage;
