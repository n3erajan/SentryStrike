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

const WORKFLOW = [
  {
    id: "provide",
    title: "Provide the application",
    desc: "Add URL, confirm authorization, set crawl scope, and optional test users.",
  },
  {
    id: "scan",
    title: "Perform VAPT",
    desc: "Map routes, replay workflows, and test OWASP controls.",
  },
  {
    id: "report",
    title: "Act on the report",
    desc: "Review risk, evidence, remediation, and coverage.",
  },
];

const OWASP = {
  a01: {
    nav: "A01 Access Control",
    label: "A01 · BROKEN ACCESS CONTROL",
    title: "Test what each identity can reach.",
    p: "Compare unauthenticated, normal-user, secondary-user, and administrator access to verify horizontal and vertical authorization failures.",
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
    title: "Find dangerous defaults and exposed surfaces.",
    p: "Inspect headers, sensitive paths, directory listings, and backup files.",
    chips: ["Security headers", "Sensitive paths", "Error disclosure"],
  },
  a03: {
    nav: " A03 Supply Chain",
    label: "A03 · SOFTWARE SUPPLY CHAIN FAILURES",
    title: "Identify vulnerable dependencies.",
    p: "Cross-reference detected components and versions against known CVEs via NVD.",
    chips: ["Dependency CVEs", "Version exposure"],
  },
  a04: {
    nav: "A04 Cryptographic",
    label: "A04 · CRYPTOGRAPHIC FAILURES",
    title: "Inspect transport security.",
    p: "Analyze HTTPS, TLS configuration, certificates, and visible cryptographic weaknesses.",
    chips: ["TLS analysis", "Certificates", "HTTPS enforcement"],
  },
  a05: {
    nav: "A05 Injection",
    label: "A05 · INJECTION",
    title: "Verify input-driven execution.",
    p: "Test SQL/NoSQL injection, XSS, command injection, file inclusion, and upload.",
    chips: ["SQLi / NoSQLi", "XSS", "Command injection", "SSRF"],
  },
  a07: {
    nav: "A07 Authentication",
    label: "A07 · AUTHENTICATION FAILURES",
    title: "Test sessions and login boundaries.",
    p: "Evaluate authentication workflows, sessions, CSRF protection, and role boundaries.",
    chips: ["Session validation", "Auth bypass", "JWT validation"],
  },
  a10: {
    nav: "A10 Exceptional Conditions",
    label: "A10 · MISHANDLING OF EXCEPTIONAL CONDITIONS",
    title: "Inspect error handling and failures.",
    p: "Surface stack traces, verbose errors, and debug pages that leak internals.",
    chips: ["Stack traces", "Error disclosure", "Debug pages"],
  },
};

const ROLES = {
  owner: {
    nav: "Business owner",
    title: "Make release decisions with confidence.",
    desc: "See customer impact, business risk, priorities, and progress without decoding scanner output.",
    items: [
      "Security score and release recommendation",
      "Plain-language impact",
      "Prioritized action plan",
    ],
  },
  developer: {
    nav: "Developer",
    title: "Go from finding to fix.",
    desc: "Inspect endpoints, payloads, masked evidence, reproduction details, and remediation.",
    items: [
      "Exact endpoint and parameter",
      "Request and response evidence",
      "CVSS and exploitability",
      "Focused remediation",
    ],
  },
  security: {
    nav: "Security team",
    title: "Judge coverage, not just findings.",
    desc: "Review authentication context, evidence strength, coverage quality, attack chains, and limitations.",
    items: [
      "SPA and API coverage",
      "Authenticated target verification",
      "Skipped-reason visibility",
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
    "No. It automates repeatable VAPT coverage. Threat modeling, business logic, insecure design, and monitoring review still benefit from skilled human testing.",
  ],
  [
    "Can teams compare past reports?",
    "Every completed assessment is saved and listed under Reports, and each application shows its latest security score. Side-by-side comparison of past reports is on the roadmap.",
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
          <b>Interactive scan preview</b>
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
            <h3>New Scan</h3>
            <div className='field'>
              <label>Application URL</label>
              <div className='control'>
                <input defaultValue='https://example.com' readOnly />
              </div>
            </div>
            <div className='field'>
              <label>Crawl Scope</label>
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
        <h3 style={{ fontSize: "0.98rem" }}>Live application coverage</h3>
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
            <b>Developer evidence</b>
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
          <img src='/shield.png' className='mark-img' alt='' />
          SentryStrike
        </div>
        <div className='navlinks'>
          <a href='#platform'>Platform</a>
          <a href='#owasp'>OWASP 2025</a>
          <a href='#teams'>For teams</a>
          <a href='#faq'>FAQ</a>
        </div>
        <div className='navactions'>
          <Link className='btn' to='/login'>
            Sign in
          </Link>
          <Link className='btn primary' to='/register'>
            Start assessment
          </Link>
        </div>
      </nav>
      <main>
        <section className='hero'>
          <div className='hero-copy'>
            <span className='eyebrow'>
              <BadgeCheck className='ico' />
              OWASP Top 10 2025 VAPT
            </span>
            <h1>Know what your web app exposes.</h1>
            <p>
              SentryStrike turns an application URL into verified
              vulnerabilities, clear business risk, developer evidence, and a
              report your team can act on.
            </p>
            <div className='hero-actions'>
              <Link className='btn primary' to='/register'>
                Assess your web app
              </Link>
              <a className='btn' href='#platform'>
                Explore the platform
              </a>
            </div>
            <div className='trust'>
              <span>
                <LockKeyhole className='ico' />
                Credentials never stored
              </span>
              <span>
                <CheckCircle2 className='ico' />
                Verified evidence
              </span>
              <span>
                <FileCheck2 className='ico' />
                Business-ready reports
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
            <h2>From URL to security decision.</h2>
            <p>
              A guided workflow makes VAPT approachable for businesses without
              hiding the technical depth developers need.
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
            <h2>OWASP Top 10 2025, with honest coverage.</h2>
            <p>
              Automated categories are tested actively. Human-review categories
              are disclosed as limitations, never marked secure.
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
            <h2>One report. Three useful views.</h2>
            <p>
              Everyone works from the same verified evidence, presented at the
              right level.
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
            <h2>Questions worth asking.</h2>
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
            <h2>Start with your application URL.</h2>
            <p>Get an OWASP Top 10 2025 VAPT report your whole team can use.</p>
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
