import { useEffect, useState } from "react";
import { MotionConfig, motion } from "motion/react";
import { ShieldCheck, Cpu, KeyRound, Timer, Cookie } from "lucide-react";
import ThemeToggle from "../components/ThemeToggle.jsx";
import PageTransitionLink from "../components/PageTransitionLink.jsx";
import { Reveal } from "../components/motion/primitives.jsx";

const Link = PageTransitionLink;
const MotionLink = motion.create(PageTransitionLink);

const LAST_UPDATED = "29 July 2026";

const SECTIONS = [
  ["scope", "Who this applies to"],
  ["collect", "What we collect"],
  ["scans", "Scan data and evidence"],
  ["credentials", "Test account credentials"],
  ["ai", "AI analysis"],
  ["cookies", "Cookies and sessions"],
  ["third-parties", "Outside services"],
  ["retention", "How long we keep things"],
  ["audit", "Audit records"],
  ["security", "How we protect this data"],
  ["rights", "Your rights"],
  ["changes", "Changes and contact"],
];

// The four answers most people open a privacy policy looking for.
const AT_A_GLANCE = [
  {
    id: "ai",
    icon: Cpu,
    title: "No third-party AI",
    body: "Findings are analyzed by a model running on our own infrastructure. Your evidence is never sent to an outside provider.",
  },
  {
    id: "credentials",
    icon: KeyRound,
    title: "Test logins are never stored",
    body: "Credentials live in worker memory for the length of a scan and are never written to the scan record.",
  },
  {
    id: "retention",
    icon: Timer,
    title: "Scans expire on a schedule",
    body: "90 days by default, adjustable per workspace, and deleted automatically once the window passes.",
  },
  {
    id: "cookies",
    icon: Cookie,
    title: "One cookie, no tracking",
    body: "A single session cookie keeps you signed in. There is no analytics or advertising script anywhere.",
  },
];

function useActiveSection() {
  const [active, setActive] = useState(SECTIONS[0][0]);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
        if (visible) setActive(visible.target.id);
      },
      { rootMargin: "-88px 0px -65% 0px", threshold: 0 },
    );

    for (const [id] of SECTIONS) {
      const node = document.getElementById(id);
      if (node) observer.observe(node);
    }
    return () => observer.disconnect();
  }, []);

  return active;
}

function PrivacyPage() {
  const active = useActiveSection();

  return (
    <MotionConfig reducedMotion='user'>
      <div className='landing'>
        <nav className='public-nav'>
          <Link to='/' className='brand' viewTransition>
            <img src='/sentrystrike-logo.svg' className='mark-img' alt='' />
            <span className='brand-name'>SentryStrike</span>
          </Link>
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

        <main className='legal'>
          <header className='legal-head'>
            <Reveal>
              <span className='eyebrow'>
                <ShieldCheck className='ico' />
                Privacy policy
              </span>
              <h1>What SentryStrike does with your data.</h1>
              <p>
                SentryStrike handles two kinds of sensitive information: the
                accounts of the people who use it, and the security evidence it
                collects from the applications you scan. This page covers both.
              </p>
              <span className='mono legal-updated'>
                Last updated {LAST_UPDATED}
              </span>
            </Reveal>
          </header>

          <div className='legal-body'>
            <aside className='legal-toc' aria-label='On this page'>
              <nav>
                <span className='legal-toc-label mono'>On this page</span>
                {SECTIONS.map(([id, label]) => (
                  <a
                    key={id}
                    href={`#${id}`}
                    className={active === id ? "active" : undefined}
                  >
                    {label}
                  </a>
                ))}
              </nav>
            </aside>

            <article className='legal-prose'>
              <section id='scope'>
                <h2>Who this applies to</h2>
                <p>
                  SentryStrike is a dynamic application security testing
                  platform. Organizations use it to scan web applications they
                  own or have written permission to test, review what the scan
                  found, and track the fixes.
                </p>
                <p>
                  We run the platform, which means we hold the accounts, the
                  scan results, and the evidence behind them. The content of a
                  workspace belongs to the organization that created it. We
                  process it to provide the service and for nothing else. We do
                  not sell it, we do not use it to advertise, and we do not use
                  one customer{"'"}s scan data to build anything for another.
                </p>
                <p>
                  This policy covers the SentryStrike web application and the
                  scanning services behind it. It does not cover the
                  applications you point a scan at, which remain yours to
                  govern. The rules for using the platform, including what you
                  are permitted to scan, are in the{" "}
                  <Link to='/terms' viewTransition>
                    terms of use
                  </Link>
                  .
                </p>
              </section>

              <section id='collect'>
                <h2>What we collect</h2>
                <p>
                  Access to a workspace is by request rather than open signup.
                  The public request form asks for your name, your work email,
                  and the name of your organization. We record the network
                  address the request came from in a short-lived counter that
                  stops the form from being flooded, and requests we do not
                  approve are deleted after 30 days.
                </p>
                <p>
                  Once an account exists, it holds your name, email address, a
                  hashed password, the workspace you belong to, and your role in
                  it. The role decides what you may do. It does not narrow what
                  you can see, since every member of a workspace can read that
                  workspace{"'"}s scans and findings.
                </p>
                <p>
                  Working on findings creates a record too. When you comment on
                  a finding, take ownership of one, or mark one as a false
                  positive, your name and email are stored alongside that
                  finding so your colleagues know who said what. Comments stay
                  with the finding until the scan itself is deleted.
                </p>
              </section>

              <section id='scans'>
                <h2>Scan data and evidence</h2>
                <p>
                  A scan records the target address, the technologies it
                  detected, the requests it sent, the portions of the responses
                  it received, and the result of a TLS handshake against the
                  host. That evidence is the point. Without the captured request
                  and response, a finding is an assertion rather than a proof.
                </p>
                <div className='legal-callout'>
                  <p>
                    Evidence from an authenticated scan can contain data
                    belonging to the target application{"'"}s own users. The
                    crawler is signed in while it works, so the pages it
                    retrieves are the pages a real user would see, and a
                    captured response may include whatever those pages
                    displayed.
                  </p>
                  <p>
                    Treat scan reports as sensitive material. Scan only what you
                    are authorized to scan, and use seeded test data instead of
                    production records wherever your environment allows it.
                  </p>
                </div>
              </section>

              <section id='credentials'>
                <h2>Test account credentials</h2>
                <p>
                  Testing authenticated behaviour, including access control
                  flaws, requires a test account. Credentials you supply when
                  submitting a scan are placed in the job payload on the queue,
                  and the queue removes that payload the moment a worker claims
                  the job. After that the credentials exist only in the memory
                  of the worker running your scan.
                </p>
                <p>
                  They are never written to the scan record. The stored scan
                  keeps only a marker naming which account slots were filled,
                  never the values themselves. Use dedicated test accounts
                  regardless, and rotate them once an assessment is finished.
                </p>
              </section>

              <section id='ai'>
                <h2>AI analysis</h2>
                <p>
                  SentryStrike uses a language model to explain findings in
                  plain language and to flag results that look like false
                  positives. Most tools in this category send that work to a
                  commercial API. We do not. The model runs on our own
                  infrastructure, so your evidence is analyzed where it already
                  sits and is never transmitted to OpenAI, Anthropic, Google, or
                  any other provider.
                </p>
                <p>
                  This matters more here than it would elsewhere, because the
                  text being analyzed is a captured response from your
                  application. Sending that to a third party would mean handing
                  over the exact material you hired a scanner to keep track of.
                  Analysis can also be switched off for a workspace, in which
                  case findings still complete using deterministic summaries.
                </p>
              </section>

              <section id='cookies'>
                <h2>Cookies and sessions</h2>
                <p>
                  Signing in creates a session on the server and sets a single
                  cookie in your browser. The cookie carries a bearer token, but
                  the database stores only a SHA-256 hash of it, so reading the
                  database does not give anyone a usable credential. Sessions
                  expire seven days after they are issued and can be revoked
                  before that. Each one records when it was last used, which is
                  what makes unusual activity traceable.
                </p>
                <p>
                  We set no advertising cookies and run no analytics or tracking
                  scripts.
                </p>
              </section>

              <section id='third-parties'>
                <h2>Outside services</h2>
                <p>
                  Two outside services touch anything at all, and neither of
                  them sees scan data.
                </p>
                <p>
                  Cloudflare Turnstile protects the public request and sign-in
                  forms against automated abuse. When the widget loads,
                  Cloudflare receives your network address and basic details
                  about your browser. It does not receive the contents of the
                  form.
                </p>
                <p>
                  Transactional email, meaning workspace invitations and
                  decisions on access requests, goes out through an email relay.
                  That relay sees the recipient address and the message. We send
                  no marketing email and we share no address with anyone for
                  marketing purposes.
                </p>
                <p>
                  There is no analytics vendor, no session recorder, no
                  advertising network, and no AI provider on that list.
                </p>
              </section>

              <section id='retention'>
                <h2>How long we keep things</h2>
                <p>
                  A background job runs twice a day and deletes scans that have
                  passed their workspace{"'"}s retention window.
                </p>
                <div className='legal-table-wrap'>
                  <table className='legal-table'>
                    <thead>
                      <tr>
                        <th>Data</th>
                        <th>Kept for</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td>Scans, findings, and evidence</td>
                        <td>
                          90 days by default, set per workspace, never below 30
                        </td>
                      </tr>
                      <tr>
                        <td>Access requests that were not approved</td>
                        <td>30 days</td>
                      </tr>
                      <tr>
                        <td>Sign-in sessions</td>
                        <td>7 days, or until revoked</td>
                      </tr>
                      <tr>
                        <td>Workspace invitations</td>
                        <td>7 days</td>
                      </tr>
                      <tr>
                        <td>Out-of-band interaction records</td>
                        <td>1 hour</td>
                      </tr>
                      <tr>
                        <td>Audit log entries</td>
                        <td>Kept indefinitely, see below</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </section>

              <section id='audit'>
                <h2>Audit records</h2>
                <p>
                  Some actions are written to an append-only log: starting or
                  cancelling a scan, changing how a finding was reviewed,
                  inviting or removing a member, changing someone{"'"}s role,
                  and the retention job deleting a scan. Each entry names who
                  did it and when.
                </p>
                <p>
                  These entries are never edited or deleted afterward, and they
                  outlive both the scans and the accounts they refer to. A
                  removed member{"'"}s identifier still appears in the log. This
                  is deliberate, because a log that can be rewritten is not
                  useful for auditing, and it is the one place where deleting
                  your account does not delete every trace of it.
                </p>
              </section>

              <section id='security'>
                <h2>How we protect this data</h2>
                <p>
                  Passwords are hashed before storage and the plaintext is never
                  written down. Session tokens are stored only as hashes and can
                  be revoked individually. Every database query is scoped to a
                  single workspace, so one organization{"'"}s scans are not
                  reachable from another{"'"}s account.
                </p>
                <p>
                  On the scanning side, we refuse targets on private network
                  ranges, which stops the scanner from being pointed at internal
                  infrastructure it has no business reaching. Public forms are
                  rate limited by address, and invitations are rate limited per
                  workspace and per sender.
                </p>
              </section>

              <section id='rights'>
                <h2>Your rights</h2>
                <p>
                  You can ask for a copy of the personal data we hold about you,
                  correct anything inaccurate, ask us to delete your account, or
                  object to how we are handling something. Email us and we will
                  respond. We may ask you to write from the address on the
                  account so we are not handing someone else{"'"}s data to a
                  stranger who asked nicely.
                </p>
                <p>
                  Some of this you can do without us. Owners and administrators
                  can export scan reports, change the retention window, and
                  remove members from workspace settings, which takes effect
                  immediately.
                </p>
                <p>
                  Removing a member deletes their account. Their entries in the
                  audit log remain for the reason described above.
                </p>
              </section>

              <section id='changes'>
                <h2>Changes and contact</h2>
                <p>
                  When this policy changes in a way that affects what we collect
                  or how long we keep it, we will update the date at the top of
                  this page and notify workspace owners by email. We will not
                  quietly broaden what we collect and leave you to notice.
                </p>
                <p>
                  For anything else about this policy or the data behind it,
                  email us and a person will read it.
                </p>
                <p>
                  One last point worth repeating, because it is the one that
                  gets people into trouble. SentryStrike sends live security
                  testing traffic at whatever you aim it at. Running it against
                  a system you do not own or have written permission to test is
                  unlawful in most jurisdictions, and that responsibility is
                  yours, not ours.
                </p>
              </section>
            </article>

            <aside className='legal-rail' aria-label='At a glance'>
              <div className='legal-rail-inner'>
                <span className='legal-toc-label mono'>At a glance</span>
                {AT_A_GLANCE.map(({ id, icon: Icon, title, body }) => (
                  <a key={id} href={`#${id}`} className='legal-fact'>
                    <Icon className='ico' />
                    <strong>{title}</strong>
                    <span>{body}</span>
                  </a>
                ))}
              </div>
            </aside>
          </div>
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

export default PrivacyPage;
