import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  BadgeCheck,
  ArrowUpRight,
  LockKeyhole,
  CheckCircle2,
  FileCheck2,
  Plus,
} from "lucide-react";
import ThemeToggle from "../components/ThemeToggle.jsx";

const WORKFLOW = [
  {
    id: "provide",
    title: "Set the target",
    desc: "Enter a URL, choose the scope, and add test accounts if needed.",
  },
  {
    id: "scan",
    title: "Run the scan",
    desc: "Map the app and test the routes, inputs, and sessions it exposes.",
  },
  {
    id: "report",
    title: "Review the results",
    desc: "Triage findings, assign fixes, and export the report.",
  },
];

const OWASP = {
  a01: {
    nav: "A01 Access Control",
    label: "A01 · BROKEN ACCESS CONTROL",
    title: "Check what each user can access.",
    p: "Compare public, standard, secondary, and admin sessions to find horizontal and vertical access failures.",
    chips: [
      "IDOR / BOLA",
      "Privilege escalation",
      "Cross-tenant access",
      "SSRF / CSRF",
    ],
  },
  a02: {
    nav: "A02 Misconfiguration",
    label: "A02 · SECURITY MISCONFIGURATION",
    title: "Find unsafe defaults and exposed files.",
    p: "Check headers, sensitive paths, directory listings, and backup files.",
    chips: ["Security headers", "Sensitive paths", "Error disclosure"],
  },
  a03: {
    nav: " A03 Supply Chain",
    label: "A03 · SOFTWARE SUPPLY CHAIN FAILURES",
    title: "Find known risks in dependencies.",
    p: "Match detected components and versions against CVEs from the NVD.",
    chips: ["Dependency CVEs", "Version exposure"],
  },
  a04: {
    nav: "A04 Cryptographic",
    label: "A04 · CRYPTOGRAPHIC FAILURES",
    title: "Check HTTPS and TLS.",
    p: "Inspect certificates, protocol support, and visible cryptographic weaknesses.",
    chips: ["TLS analysis", "Certificates", "HTTPS enforcement"],
  },
  a05: {
    nav: "A05 Injection",
    label: "A05 · INJECTION",
    title: "Test how the app handles input.",
    p: "Probe for SQL and NoSQL injection, XSS, command injection, file inclusion, and unsafe uploads.",
    chips: ["SQLi / NoSQLi", "XSS", "Command injection", "SSRF"],
  },
  a07: {
    nav: "A07 Authentication",
    label: "A07 · AUTHENTICATION FAILURES",
    title: "Test login and session controls.",
    p: "Check authentication flows, session handling, CSRF protection, and role boundaries.",
    chips: ["Session validation", "Auth bypass", "JWT validation"],
  },
  a10: {
    nav: "A10 Exceptional Conditions",
    label: "A10 · MISHANDLING OF EXCEPTIONAL CONDITIONS",
    title: "Check what errors reveal.",
    p: "Look for stack traces, verbose errors, and debug pages that expose internal details.",
    chips: ["Stack traces", "Error disclosure", "Debug pages"],
  },
};

const ROLES = {
  owner: {
    nav: "Business owner",
    title: "See what could block a release.",
    desc: "Get the risk, likely impact, and current remediation status without reading raw scanner output.",
    items: [
      "Risk score and release guidance",
      "Plain-language impact",
      "Fix status",
    ],
  },
  developer: {
    nav: "Developer",
    title: "Get enough detail to fix it.",
    desc: "See the affected endpoint, payload, evidence, and recommended fix.",
    items: [
      "Exact endpoint and parameter",
      "Request and response evidence",
      "CVSS and exploitability",
      "Suggested fix",
    ],
  },
  security: {
    nav: "Security team",
    title: "Review what the scan covered.",
    desc: "Check authentication context, evidence strength, skipped tests, and scan limits.",
    items: [
      "SPA and API coverage",
      "Authenticated coverage",
      "Reasons tests were skipped",
      "Evidence strength breakdown",
    ],
  },
};

const FAQS = [
  [
    "Can SentryStrike test behind login?",
    "Yes. Provide primary, secondary, and administrator test accounts for authenticated workflows and access-control testing. Credentials are used in memory and not stored at rest.",
  ],
  [
    "Does this replace a human penetration test?",
    "No. It automates repeatable DAST checks. Threat modeling, source review, and complex business logic still need skilled human testing.",
  ],
  [
    "Can teams compare past reports?",
    "Yes. Reports keeps every completed scan, and each application page shows its scan history and latest score.",
  ],
];

const PHASE_LABELS = [
  "Mapping application",
  "Detecting technology",
  "Testing security controls",
  "Building report",
];

function ScanPreview() {
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [state, setState] = useState("Ready");
  const [label, setLabel] = useState("Waiting for target");
  const [done, setDone] = useState(false);
  const timerRef = useRef(null);

  const start = useCallback(() => {
    if (scanning) return;
    setScanning(true);
    setDone(false);
    setProgress(0);
    setState("Scanning");
    setLabel(PHASE_LABELS[0]);
    timerRef.current = setInterval(() => {
      setProgress((prev) => {
        const next = prev + 4;
        if (next >= 100) {
          clearInterval(timerRef.current);
          setScanning(false);
          setDone(true);
          setState("Complete");
          setLabel("3 verified findings");
          return 100;
        }
        const idx = Math.min(3, Math.floor(next / 25));
        setLabel(PHASE_LABELS[idx]);
        return next;
      });
    }, 55);
  }, [scanning]);

  useEffect(
    () => () => timerRef.current && clearInterval(timerRef.current),
    [],
  );

  const idx = done ? 4 : Math.min(3, Math.floor(progress / 25));

  return (
    <div className='stage'>
      <div className='orbit'>
        <i></i>
      </div>
      <div className='scan-card'>
        <div className='scan-head'>
          <b>Scan preview</b>
          <span>
            <i className='live' />
            <span>{state}</span>
          </span>
        </div>
        <div className='target'>
          <input
            defaultValue='https://example.com'
            aria-label='Preview target'
          />
          <button onClick={start} aria-label='Start preview scan'>
            <ArrowUpRight className='ico' />
          </button>
        </div>
        <div className='scan-label'>
          <span>{label}</span>
          <b className='mono'>{progress}%</b>
        </div>
        <div className='bar'>
          <span style={{ width: `${progress}%` }} />
        </div>
        <div className='phases'>
          {["Map app", "Detect stack", "Test controls", "Build report"].map(
            (name, i) => (
              <div
                key={name}
                className={`phase ${done || i < idx ? "done" : ""} ${!done && i === idx ? "active" : ""}`}
              >
                {name}
              </div>
            ),
          )}
        </div>
        <div className={`findings${done ? " visible" : ""}`}>
          <div className='finding-mini'>
            <i className='sev' />
            <span>Broken object-level authorization</span>
            <b>9.1</b>
          </div>
          <div className='finding-mini'>
            <i className='sev' />
            <span>Stored cross-site scripting</span>
            <b>8.4</b>
          </div>
          <div className='finding-mini'>
            <i className='sev' style={{ background: "var(--warn)" }} />
            <span>Cross-site request forgery</span>
            <b>6.2</b>
          </div>
        </div>
      </div>
    </div>
  );
}

function WorkflowVisual({ id }) {
  if (id === "provide") {
    return (
      <div className='workflow-pane active'>
        <div className='mock-browser'>
          <div className='mock-top'>
            <i />
            <i />
            <i />
          </div>
          <div className='mock-body'>
            <h3>New scan</h3>
            <div className='field'>
              <label>Target URL</label>
              <div className='control'>
                <input defaultValue='https://example.com' readOnly />
              </div>
            </div>
            <div className='field'>
              <label>Crawl scope</label>
              <div className='control'>
                <input defaultValue='Full Site' readOnly />
              </div>
            </div>
            <Link
              className='btn primary'
              to='/register'
              style={{ marginTop: 15 }}
            >
              Continue
            </Link>
          </div>
        </div>
      </div>
    );
  }
  if (id === "scan") {
    return (
      <div className='workflow-pane active'>
        <h3 style={{ fontSize: "0.98rem" }}>Live scan coverage</h3>
        <div className='coverage'>
          <div className='coverage-row'>
            <span>Routes discovered</span>
            <div className='mini'>
              <span style={{ width: "92%" }} />
            </div>
            <b>164</b>
          </div>
          <div className='coverage-row'>
            <span>API endpoints</span>
            <div className='mini'>
              <span style={{ width: "74%" }} />
            </div>
            <b>14</b>
          </div>
          <div className='coverage-row'>
            <span>Forms submitted</span>
            <div className='mini'>
              <span style={{ width: "75%" }} />
            </div>
            <b>21/28</b>
          </div>
          <div className='coverage-row'>
            <span>Security tests</span>
            <div className='mini'>
              <span style={{ width: "64%" }} />
            </div>
            <b>64%</b>
          </div>
        </div>
      </div>
    );
  }
  return (
    <div className='workflow-pane active'>
      <div className='report-preview'>
        <div className='report-preview-head'>
          <b>Acme Checkout report</b>
          <span>Complete</span>
        </div>
        <div className='preview-score'>
          <strong className='high mono'>42</strong>
          <p>
            <b>High risk</b>
            <br />
            Cross-tenant exposure should block release.
          </p>
        </div>
        <div className='cardfoot'>
          <span>9 verified findings</span>
          <b>96% coverage</b>
        </div>
      </div>
    </div>
  );
}

function RolePane({ role }) {
  if (role === "developer") {
    return (
      <>
        <div className='role-copy'>
          <h3>{ROLES.developer.title}</h3>
          <p>{ROLES.developer.desc}</p>
          <ul>
            {ROLES.developer.items.map((i) => (
              <li key={i}>{i}</li>
            ))}
          </ul>
        </div>
        <div className='report-preview'>
          <div className='report-preview-head'>
            <b>Finding evidence</b>
            <span>Confirmed exploit</span>
          </div>
          <pre
            style={{
              background: "var(--dark)",
              color: "var(--light)",
              padding: 14,
              borderRadius: 7,
              font: '11px/1.7 "IBM Plex Mono", monospace',
              margin: "14px 0 0",
              overflowX: "auto",
            }}
          >{`GET /api/v1/invoices/8842
HTTP 200 OK
{"customer":"Northstar","total":4280}`}</pre>
        </div>
      </>
    );
  }
  if (role === "security") {
    return (
      <>
        <div className='role-copy'>
          <h3>{ROLES.security.title}</h3>
          <p>{ROLES.security.desc}</p>
          <ul>
            {ROLES.security.items.map((i) => (
              <li key={i}>{i}</li>
            ))}
          </ul>
        </div>
        <div className='report-preview'>
          <div className='report-preview-head'>
            <b>Coverage quality</b>
            <span>Dynamic partial</span>
          </div>
          <div className='coverage'>
            <div className='coverage-stat'>
              <span>Authenticated targets verified</span>
              <b className='mono'>12</b>
            </div>
            <div className='coverage-stat'>
              <span>API endpoints extracted</span>
              <b className='mono'>37</b>
            </div>
            <div className='coverage-stat'>
              <span>Confirmed evidence</span>
              <b className='mono'>9</b>
            </div>
            <div className='coverage-stat'>
              <span>SPA detected</span>
              <b className='mono'>Yes</b>
            </div>
          </div>
        </div>
      </>
    );
  }
  return (
    <>
      <div className='role-copy'>
        <h3>{ROLES.owner.title}</h3>
        <p>{ROLES.owner.desc}</p>
        <ul>
          {ROLES.owner.items.map((i) => (
            <li key={i}>{i}</li>
          ))}
        </ul>
      </div>
      <div className='report-preview'>
        <div className='report-preview-head'>
          <b>Executive report</b>
          <span>Jul 13</span>
        </div>
        <div className='preview-score'>
          <strong className='high mono'>42</strong>
          <p>
            <b>High risk</b>
            <br />
            Release should remain blocked.
          </p>
        </div>
      </div>
    </>
  );
}

function LandingPage() {
  const [workflow, setWorkflow] = useState("provide");
  const [owasp, setOwasp] = useState("a01");
  const [role, setRole] = useState("owner");
  const [openFaq, setOpenFaq] = useState(0);
  const d = OWASP[owasp];

  return (
    <div className='landing'>
      <nav className='public-nav'>
        <div className='brand'>
          <img src='/sentrystrike-logo.svg' className='mark-img' alt='' />
          SentryStrike
        </div>
        <div className='navlinks'>
          <a href='#platform'>Platform</a>
          <a href='#owasp'>OWASP 2025</a>
          <a href='#teams'>For teams</a>
          <a href='#faq'>FAQ</a>
        </div>
        <div className='navactions'>
          <ThemeToggle />
          <Link className='btn' to='/login'>
            Sign in
          </Link>
          <Link className='btn primary' to='/register'>
            Start a scan
          </Link>
        </div>
      </nav>
      <main>
        <section className='hero'>
          <div className='hero-copy'>
            <span className='eyebrow'>
              <BadgeCheck className='ico' />
              Evidence-driven DAST
            </span>
            <h1>Find what your web app exposes.</h1>
            <p>
              SentryStrike scans public and authenticated routes, verifies
              findings, and shows your team what to fix.
            </p>
            <div className='hero-actions'>
              <Link className='btn primary' to='/register'>
                Start a scan
              </Link>
              <a className='btn' href='#platform'>
                See how it works
              </a>
            </div>
            <div className='trust'>
              <span>
                <LockKeyhole className='ico' />
                Credentials kept in memory
              </span>
              <span>
                <CheckCircle2 className='ico' />
                Evidence-backed findings
              </span>
              <span>
                <FileCheck2 className='ico' />
                PDF reports
              </span>
            </div>
          </div>
          <ScanPreview />
        </section>

        <div className='ticker-wrap'>
          <span className='ticker-label'>Built for</span>
          <div className='ticker'>
            {[
              "Business owners",
              "Development teams",
              "Security teams",
              "Growing SaaS companies",
              "Business owners",
              "Development teams",
              "Security teams",
              "Growing SaaS companies",
            ].map((s, i) => (
              <span key={`${s}-${i}`}>{s}</span>
            ))}
          </div>
        </div>

        <section className='public-section' id='platform'>
          <div className='section-head'>
            <h2>A scan you can follow.</h2>
            <p>
              Set the target and scope. SentryStrike handles discovery,
              testing, and reporting.
            </p>
          </div>
          <div className='workflow'>
            <div className='steps'>
              {WORKFLOW.map((s, i) => (
                <button
                  key={s.id}
                  type='button'
                  className={`step${workflow === s.id ? " active" : ""}`}
                  onClick={() => setWorkflow(s.id)}
                >
                  <b>{String(i + 1).padStart(2, "0")}</b>
                  <div>
                    <h3>{s.title}</h3>
                    <p>{s.desc}</p>
                  </div>
                </button>
              ))}
            </div>
            <div className='workflow-visual'>
              <WorkflowVisual id={workflow} />
            </div>
          </div>
        </section>

        <section className='public-section dark-section' id='owasp'>
          <div className='section-head'>
            <h2>Coverage you can inspect.</h2>
            <p>
              See what ran, what was skipped, and why. Missing coverage is never
              treated as a pass.
            </p>
          </div>
          <div className='owasp'>
            <div className='owasp-nav'>
              {Object.entries(OWASP).map(([key, entry]) => (
                <button
                  key={key}
                  type='button'
                  className={owasp === key ? "active" : undefined}
                  onClick={() => setOwasp(key)}
                >
                  {entry.nav}
                </button>
              ))}
            </div>
            <div className='owasp-detail' key={owasp}>
              <span>{d.label}</span>
              <h3>{d.title}</h3>
              <p>{d.p}</p>
              <div className='chips'>
                {d.chips.map((c) => (
                  <i key={c}>{c}</i>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section className='public-section' id='teams'>
          <div className='section-head'>
            <h2>One report, useful at every level.</h2>
            <p>
              Each role gets the detail it needs without losing the underlying
              evidence.
            </p>
          </div>
          <div className='roles'>
            {Object.entries(ROLES).map(([key, entry]) => (
              <button
                key={key}
                type='button'
                className={role === key ? "active" : undefined}
                onClick={() => setRole(key)}
              >
                {entry.nav}
              </button>
            ))}
          </div>
          <div className='role-pane active' key={role}>
            <RolePane role={role} />
          </div>
        </section>

        <section className='public-section' id='faq'>
          <div className='faq'>
            <h2>Common questions</h2>
            {FAQS.map(([q, a], i) => (
              <article
                key={q}
                className={`faq-item${openFaq === i ? " open" : ""}`}
              >
                <button
                  className='faq-q'
                  type='button'
                  onClick={() => setOpenFaq(openFaq === i ? -1 : i)}
                  aria-expanded={openFaq === i}
                >
                  {q}
                  <Plus className='ico' />
                </button>
                <div className='faq-a'>
                  <div>
                    <p>{a}</p>
                  </div>
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className='cta'>
          <div>
            <h2>Scan an authorized web app.</h2>
            <p>Start with a URL. Add test accounts when you need authenticated coverage.</p>
          </div>
          <Link className='btn' to='/register'>
            Create account
          </Link>
        </section>
      </main>
      <footer className='public-footer'>
        <span>Copyright © {new Date().getFullYear()} SentryStrike</span>
        <span>Authorized security testing only</span>
      </footer>
    </div>
  );
}

export default LandingPage;
