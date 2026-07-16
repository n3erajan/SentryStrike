import { useState } from "react";
import { Link } from "react-router-dom";
import {
  ArrowUpRight,
  SealCheck,
  Check,
  CheckCircle,
  FileText,
  LockKey,
  Plus,
  ShieldCheck,
} from "@phosphor-icons/react";

const FAQS = [
  [
    "Can SentryStrike test behind login?",
    "Yes. Add primary, secondary, and administrator test accounts for authenticated workflows and access-control testing. Credentials are used for the scan and are not stored.",
  ],
  [
    "Does this replace a human penetration test?",
    "No. It automates repeatable web application assessment. Threat modeling, business logic, insecure design, and monitoring review still benefit from skilled human testing.",
  ],
  [
    "What can I export?",
    "Completed assessments can be downloaded as a formatted PDF or raw JSON, including findings, evidence, remediation, coverage, and scanner limitations.",
  ],
];

function Brand() {
  return (
    <Link to='/' className='brand public-brand' aria-label='SentryStrike home'>
      <span className='mark'>
        <ShieldCheck size={19} weight='bold' />
      </span>
      SentryStrike
    </Link>
  );
}

function LandingPage() {
  const [openFaq, setOpenFaq] = useState(0);

  return (
    <div className='landing'>
      <nav className='public-nav'>
        <Brand />
        <div className='navlinks'>
          <a href='#platform'>Platform</a>
          <a href='#owasp'>OWASP coverage</a>
          <a href='#report'>The report</a>
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
              <SealCheck size={16} weight='bold' />
              OWASP web application assessment
            </span>
            <h1>Know what your web app exposes.</h1>
            <p>
              SentryStrike turns a target URL into verified vulnerabilities,
              clear business risk, developer evidence, and a report your team
              can act on.
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
                <LockKey size={16} /> Credentials never stored
              </span>
              <span>
                <CheckCircle size={16} /> Verified evidence
              </span>
              <span>
                <FileText size={16} /> Export-ready reports
              </span>
            </div>
          </div>

          <div className='stage' aria-label='Scan preview'>
            <div className='orbit'>
              <i />
            </div>
            <div className='scan-card'>
              <div className='scan-head'>
                <b>Assessment preview</b>
                <span>
                  <i className='live' />
                  Ready
                </span>
              </div>
              <div className='target'>
                <input value='https://staging.example.com' readOnly />
                <Link to='/register' aria-label='Start an assessment'>
                  <ArrowUpRight size={18} weight='bold' />
                </Link>
              </div>
              <div className='scan-label'>
                <span>Testing application controls</span>
                <b className='mono'>64%</b>
              </div>
              <div className='bar'>
                <span style={{ width: "64%" }} />
              </div>
              <div className='phases'>
                <div className='phase done'>Map app</div>
                <div className='phase done'>Detect stack</div>
                <div className='phase active'>Test controls</div>
                <div className='phase'>Build report</div>
              </div>
              <div className='findings visible'>
                <div className='finding-mini'>
                  <i className='sev critical' />
                  <span>Broken object-level authorization</span>
                  <b>9.1</b>
                </div>
                <div className='finding-mini'>
                  <i className='sev critical' />
                  <span>Stored cross-site scripting</span>
                  <b>8.4</b>
                </div>
                <div className='finding-mini'>
                  <i className='sev medium' />
                  <span>Cross-site request forgery</span>
                  <b>6.2</b>
                </div>
              </div>
            </div>
          </div>
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
            ].map((item, index) => (
              <span key={index}>{item}</span>
            ))}
          </div>
        </div>

        <section className='public-section' id='platform'>
          <div className='section-head public-section-head'>
            <h2>From URL to security decision.</h2>
            <p>
              A guided workflow keeps assessment setup approachable without
              hiding the technical depth developers need.
            </p>
          </div>
          <div className='workflow'>
            <div className='steps'>
              <article className='step active'>
                <b>01</b>
                <div>
                  <h3>Provide the target</h3>
                  <p>Add URL, authorization, and optional test users.</p>
                </div>
              </article>
              <article className='step'>
                <b>02</b>
                <div>
                  <h3>Run the assessment</h3>
                  <p>Map routes, replay workflows, and test OWASP controls.</p>
                </div>
              </article>
              <article className='step'>
                <b>03</b>
                <div>
                  <h3>Act on the report</h3>
                  <p>Review risk, evidence, remediation, and coverage.</p>
                </div>
              </article>
            </div>
            <div className='workflow-visual'>
              <div className='mock-browser'>
                <div className='mock-top'>
                  <i />
                  <i />
                  <i />
                </div>
                <div className='mock-body'>
                  <h3>New assessment</h3>
                  <div className='field'>
                    <label>Target URL</label>
                    <div className='control'>
                      <input value='https://staging.example.com' readOnly />
                    </div>
                  </div>
                  <div className='field'>
                    <label>Crawl mode</label>
                    <div className='control'>
                      <input value='Full site' readOnly />
                    </div>
                  </div>
                  <Link className='btn primary workflow-button' to='/register'>
                    Continue
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className='public-section dark-section' id='owasp'>
          <div className='section-head public-section-head'>
            <h2>OWASP coverage, stated honestly.</h2>
            <p>
              Automated categories are tested actively. Coverage notes and
              scanner limitations remain visible in the final report.
            </p>
          </div>
          <div className='owasp'>
            <div className='owasp-nav'>
              <button className='active'>A01 Access Control</button>
              <button>A02 Misconfiguration</button>
              <button>A04 Cryptographic</button>
              <button>A05 Injection</button>
              <button>A07 Authentication</button>
            </div>
            <div className='owasp-detail'>
              <span>A01 - BROKEN ACCESS CONTROL</span>
              <h3>Test what each identity can reach.</h3>
              <p>
                Compare unauthenticated, regular-user, secondary-user, and
                administrator access to verify horizontal and vertical
                authorization failures.
              </p>
              <div className='chips'>
                <i>IDOR / BOLA</i>
                <i>Privilege escalation</i>
                <i>Cross-account access</i>
              </div>
            </div>
          </div>
        </section>

        <section className='public-section' id='report'>
          <div className='section-head public-section-head'>
            <h2>One report. Every useful layer.</h2>
            <p>
              Business context, developer evidence, and coverage stay connected
              to the same verified findings.
            </p>
          </div>
          <div className='roles'>
            <button className='active'>Business risk</button>
            <button>Developer evidence</button>
            <button>Coverage quality</button>
          </div>
          <div className='role-pane active'>
            <div className='role-copy'>
              <h3>Make release decisions with clear priorities.</h3>
              <p>
                See the overall risk score, verified findings, plain-language
                impact, and the work that should happen first.
              </p>
              <ul>
                {[
                  "Risk score and severity breakdown",
                  "Executive summary",
                  "Prioritized remediation",
                  "Export-ready PDF and JSON",
                ].map((item) => (
                  <li key={item}>
                    <Check size={15} weight='bold' />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
            <div className='report-preview report-preview-large'>
              <div className='report-preview-head'>
                <b>Executive summary</b>
                <span>Verified</span>
              </div>
              <div className='preview-score'>
                <strong className='high mono'>58</strong>
                <p>
                  <b>High risk</b>
                  <br />
                  Verified issues should be fixed before release.
                </p>
              </div>
              <div className='severity-preview'>
                <span>1 Critical</span>
                <span>2 High</span>
                <span>3 Medium</span>
              </div>
            </div>
          </div>
        </section>

        <section className='public-section' id='faq'>
          <div className='faq'>
            <h2>Questions worth asking.</h2>
            {FAQS.map(([question, answer], index) => (
              <article
                className={`faq-item ${openFaq === index ? "open" : ""}`}
                key={question}
              >
                <button
                  className='faq-q'
                  type='button'
                  onClick={() => setOpenFaq(openFaq === index ? -1 : index)}
                  aria-expanded={openFaq === index}
                >
                  {question}
                  <Plus size={18} weight='bold' />
                </button>
                <div className='faq-a'>
                  <div>
                    <p>{answer}</p>
                  </div>
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className='cta'>
          <div>
            <h2>Start with your target URL.</h2>
            <p>Run an evidence-backed assessment your team can use.</p>
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
