import { useCallback, useEffect, useRef, useState } from "react";
import { MotionConfig, motion } from "motion/react";
import {
  BadgeCheck,
  ArrowUpRight,
  LockKeyhole,
  CheckCircle2,
  FileCheck2,
  Plus,
} from "lucide-react";
import ThemeToggle from "../components/ThemeToggle.jsx";
import PageTransitionLink from "../components/PageTransitionLink.jsx";
import {
  AnimatedWords,
  Reveal,
  StaggerGroup,
  StaggerItem,
  SwitchPane,
} from "../components/motion/primitives.jsx";
import { SPRING, fadeUp } from "../components/motion/tokens.js";

const Link = PageTransitionLink;
const MotionLink = motion.create(PageTransitionLink);

const WORKFLOW = [
  {
    id: "provide",
    title: "Set up the assessment",
    desc: "Choose the web application and scope, then add dedicated test accounts when needed.",
  },
  {
    id: "scan",
    title: "Scan and analyze",
    desc: "Map the application, test its exposed surface, verify findings, and run local AI analysis.",
  },
  {
    id: "report",
    title: "Review and remediate",
    desc: "Assign findings, discuss fixes, track remediation, re-verify, and export the report.",
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
    nav: "A03 Supply Chain",
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
    title: "Understand the risk in plain language.",
    desc: "See the overall risk, business impact, executive summary, and remediation progress without reading raw HTTP evidence.",
    items: [
      "Overall risk and severity",
      "Plain-language business impact",
      "Executive summary",
      "Remediation progress",
    ],
  },
  developer: {
    nav: "Developer",
    title: "See exactly what needs to be fixed.",
    desc: "Work from the affected request, parameters, scanner evidence, and AI-generated remediation guidance.",
    items: [
      "Affected URL, method, and parameters",
      "Request, response, and payload snippets",
      "Exploitability and business context",
      "Remediation guidance and fix status",
    ],
  },
  security: {
    nav: "Security reviewer",
    title: "Inspect the evidence behind every result.",
    desc: "Review verification details, confidence, AI false-positive reasoning, authentication coverage, and scan limits.",
    items: [
      "Verification method and reproducibility",
      "Evidence strength and confidence",
      "AI false-positive assessment",
      "Coverage warnings and re-verification",
    ],
  },
};

const FAQS = [
  [
    "Can SentryStrike test behind login?",
    "Yes. Provide primary, secondary, and administrator test accounts for authenticated workflows and access-control testing. They travel in the temporary Redis scan job, are removed from the queue when a worker claims it, and are never saved to MongoDB.",
  ],
  [
    "Does this replace a human penetration test?",
    "No. It automates repeatable DAST checks. Threat modeling, source review, and complex business logic still need skilled human testing.",
  ],
  [
    "Where does the AI analysis run?",
    "SentryStrike uses local Ollama by default, so finding evidence stays inside the deployment. An external OpenAI-compatible provider can be configured when its data-handling policy is acceptable.",
  ],
  [
    "Can teams review earlier assessments?",
    "Yes. SentryStrike keeps completed scans and reports in the workspace, and each application shows its scan history and latest risk score.",
  ],
];

const AUDIENCES = [
  "Business owners",
  "E-commerce teams",
  "Development teams",
  "Security teams",
  "Growing SaaS companies",
  "Website operators",
  "Product teams",
  "Security consultants",
];

const PHASE_LABELS = [
  "Mapping application",
  "Testing security controls",
  "Verifying evidence",
  "Analyzing findings",
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
          {["Map app", "Test controls", "Verify evidence", "Analyze findings"].map(
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
              to='/login'
              viewTransition
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
            <span>Browser requests</span>
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
            <b>Medium risk</b>
            <br />
            Cross-tenant exposure is the highest-priority finding.
          </p>
        </div>
        <div className='cardfoot'>
          <span>9 verified findings</span>
          <b>Coverage recorded</b>
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
              <span>Browser requests observed</span>
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
            <b>Medium risk</b>
            <br />
            Prioritize the strongest verified findings.
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
    <MotionConfig reducedMotion='user'>
      <div className='landing'>
      <nav className='public-nav'>
        <div className='brand'>
          <img src='/sentrystrike-logo.svg' className='mark-img' alt='' />
          <span className='brand-name'>SentryStrike</span>
        </div>
        <div className='navlinks'>
          <a href='#platform'>Platform</a>
          <a href='#owasp'>OWASP 2025</a>
          <a href='#teams'>For teams</a>
          <a href='#faq'>FAQ</a>
        </div>
        <div className='navactions'>
          <ThemeToggle />
          <MotionLink
            className='btn'
            to='/login'
            viewTransition
            whileTap={{ scale: 0.97 }}
          >
            Sign in
          </MotionLink>
          <MotionLink
            className='btn primary'
            to='/request-access'
            viewTransition
            whileTap={{ scale: 0.97 }}
          >
            Request access
          </MotionLink>
        </div>
      </nav>
      <main>
        <section className='hero'>
          <motion.div
            className='hero-copy'
            initial='hidden'
            animate='visible'
            variants={{
              hidden: {},
              visible: { transition: { staggerChildren: 0.08 } },
            }}
          >
            <motion.span className='eyebrow' variants={fadeUp}>
              <BadgeCheck className='ico' />
              Web DAST + vulnerability management
            </motion.span>
            <AnimatedWords
              text='From web scan to verified fix.'
              delay={0.12}
            />
            <motion.p variants={fadeUp}>
              SentryStrike maps and tests traditional sites and SPAs, verifies
              the evidence, and uses local AI to analyze findings and build the
              report. Your team can review, assign, discuss, and track every fix
              in the same workspace.
            </motion.p>
            <motion.div className='hero-actions' variants={fadeUp}>
              <MotionLink
                className='btn primary'
                to='/request-access'
                viewTransition
                whileTap={{ scale: 0.97 }}
              >
                Request access
              </MotionLink>
              <motion.a
                className='btn'
                href='#platform'
                whileTap={{ scale: 0.97 }}
              >
                See how it works
              </motion.a>
            </motion.div>
            <motion.div className='trust' variants={fadeUp}>
              <span>
                <LockKeyhole className='ico' />
                Test credentials never persisted
              </span>
              <span>
                <CheckCircle2 className='ico' />
                Local AI analysis
              </span>
              <span>
                <FileCheck2 className='ico' />
                Evidence-based reports
              </span>
            </motion.div>
          </motion.div>
          <motion.div
            initial={{ opacity: 0, x: 28, filter: "blur(5px)" }}
            animate={{ opacity: 1, x: 0, filter: "blur(0px)" }}
            transition={{ ...SPRING, duration: 0.7, delay: 0.25 }}
          >
            <ScanPreview />
          </motion.div>
        </section>

        <Reveal className='ticker-wrap'>
          <span className='ticker-label'>Built for</span>
          <div className='ticker-viewport'>
            <div className='ticker'>
              {/* Two copies drive the -50% loop; each copy repeats the list so
                  one copy always exceeds the viewport width, keeping the wrap
                  seamless (no blank gap at the reset point) on any screen. */}
              {[0, 1].flatMap((copy) =>
                [...AUDIENCES, ...AUDIENCES].map((s, i) => (
                  <span
                    key={`${copy}-${s}-${i}`}
                    aria-hidden={copy === 1 ? "true" : undefined}
                  >
                    {s}
                  </span>
                ))
              )}
            </div>
          </div>
        </Reveal>

        <section className='public-section' id='platform'>
          <StaggerGroup className='section-head'>
            <StaggerItem as='h2'>From assessment to remediation.</StaggerItem>
            <StaggerItem as='p'>
              Run the scan, understand the findings, and manage the work that
              follows without moving between separate tools.
            </StaggerItem>
          </StaggerGroup>
          <div className='workflow'>
            <StaggerGroup className='steps'>
              {WORKFLOW.map((s, i) => (
                <StaggerItem
                  key={s.id}
                  as='button'
                  type='button'
                  className={`step${workflow === s.id ? " active" : ""}`}
                  onClick={() => setWorkflow(s.id)}
                  whileTap={{ scale: 0.99 }}
                >
                  <b>{String(i + 1).padStart(2, "0")}</b>
                  <div>
                    <h3>{s.title}</h3>
                    <p>{s.desc}</p>
                  </div>
                </StaggerItem>
              ))}
            </StaggerGroup>
            <Reveal className='workflow-visual' delay={0.1}>
              <SwitchPane id={workflow}>
                <WorkflowVisual id={workflow} />
              </SwitchPane>
            </Reveal>
          </div>
        </section>

        <section className='public-section dark-section' id='owasp'>
          <StaggerGroup className='section-head'>
            <StaggerItem as='h2'>Coverage you can inspect.</StaggerItem>
            <StaggerItem as='p'>
              Inspect active checks across OWASP Top 10 (2025), along with what
              ran, what was skipped, and why. A06, A08, and A09 are identified as
              outside automated DAST scope rather than treated as passes.
            </StaggerItem>
          </StaggerGroup>
          <div className='owasp'>
            <StaggerGroup className='owasp-nav'>
              {Object.entries(OWASP).map(([key, entry]) => (
                <StaggerItem
                  key={key}
                  as='button'
                  type='button'
                  className={`tab-btn${owasp === key ? " active" : ""}`}
                  onClick={() => setOwasp(key)}
                  whileTap={{ scale: 0.98 }}
                >
                  {owasp === key && (
                    <motion.span
                      layoutId='owasp-pill'
                      className='tab-pill'
                      transition={SPRING}
                    />
                  )}
                  <span className='tab-label'>{entry.nav}</span>
                </StaggerItem>
              ))}
            </StaggerGroup>
            <div className='pane-stage'>
              <div className='pane-sizer' aria-hidden='true'>
                {Object.values(OWASP).map((entry) => (
                  <div key={entry.label} className='owasp-detail'>
                    <span>{entry.label}</span>
                    <h3>{entry.title}</h3>
                    <p>{entry.p}</p>
                    <div className='chips'>
                      {entry.chips.map((c) => (
                        <i key={c}>{c}</i>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
              <SwitchPane id={owasp} className='owasp-detail'>
                <span>{d.label}</span>
                <h3>{d.title}</h3>
                <p>{d.p}</p>
                <div className='chips'>
                  {d.chips.map((c) => (
                    <i key={c}>{c}</i>
                  ))}
                </div>
              </SwitchPane>
            </div>
          </div>
        </section>

        <section className='public-section' id='teams'>
          <StaggerGroup className='section-head'>
            <StaggerItem as='h2'>One assessment, three useful views.</StaggerItem>
            <StaggerItem as='p'>
              Business owners, developers, and security reviewers each get the
              detail they need from the same findings and report.
            </StaggerItem>
          </StaggerGroup>
          <StaggerGroup className='roles'>
            {Object.entries(ROLES).map(([key, entry]) => (
              <StaggerItem
                key={key}
                as='button'
                type='button'
                className={`tab-btn${role === key ? " active" : ""}`}
                onClick={() => setRole(key)}
                whileTap={{ scale: 0.96 }}
              >
                {role === key && (
                  <motion.span
                    layoutId='role-pill'
                    className='tab-pill'
                    transition={SPRING}
                  />
                )}
                <span className='tab-label'>{entry.nav}</span>
              </StaggerItem>
            ))}
          </StaggerGroup>
          <div className='pane-stage'>
            <div className='pane-sizer' aria-hidden='true'>
              {Object.keys(ROLES).map((key) => (
                <div key={key} className='role-pane active'>
                  <RolePane role={key} />
                </div>
              ))}
            </div>
            <SwitchPane id={role} className='role-pane active'>
              <RolePane role={role} />
            </SwitchPane>
          </div>
        </section>

        <section className='public-section' id='faq'>
          <StaggerGroup className='faq'>
            <StaggerItem as='h2'>Common questions</StaggerItem>
            {FAQS.map(([q, a], i) => (
              <StaggerItem
                key={q}
                as='article'
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
              </StaggerItem>
            ))}
          </StaggerGroup>
        </section>

        <section className='cta'>
          <Reveal>
            <h2>Start with a SentryStrike workspace.</h2>
            <p>Request access for your organization. Approved owners receive a secure setup link by email.</p>
          </Reveal>
          <Reveal delay={0.12}>
            <MotionLink
              className='btn'
              to='/request-access'
              viewTransition
              whileTap={{ scale: 0.97 }}
            >
              Request access
            </MotionLink>
          </Reveal>
        </section>
      </main>
      <footer className='public-footer'>
        <span>Copyright © {new Date().getFullYear()} SentryStrike</span>
        <span className='footer-links'>
          <Link to='/privacy' viewTransition>
            Privacy policy
          </Link>
          <Link to='/terms' viewTransition>
            Terms of use
          </Link>
          Authorized security testing only
        </span>
      </footer>
      </div>
    </MotionConfig>
  );
}

export default LandingPage;
