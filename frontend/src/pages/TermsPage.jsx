import { useEffect, useState } from "react";
import { MotionConfig, motion } from "motion/react";
import { Scale, ShieldAlert, Ban, Network, UserCheck } from "lucide-react";
import ThemeToggle from "../components/ThemeToggle.jsx";
import PageTransitionLink from "../components/PageTransitionLink.jsx";
import { Reveal } from "../components/motion/primitives.jsx";

const Link = PageTransitionLink;
const MotionLink = motion.create(PageTransitionLink);

const LAST_UPDATED = "29 July 2026";

const SECTIONS = [
  ["agreement", "The agreement"],
  ["accounts", "Accounts and workspaces"],
  ["authorization", "Authorization to test"],
  ["acceptable-use", "Acceptable use"],
  ["targets", "Targets we refuse"],
  ["conduct", "Running a scan responsibly"],
  ["findings", "What a scan does not prove"],
  ["availability", "Availability"],
  ["ip", "Ownership"],
  ["liability", "Liability"],
  ["termination", "Suspension and termination"],
  ["changes", "Changes and contact"],
];

// The obligations people most often get wrong, linked to the clause that covers them.
const AT_A_GLANCE = [
  {
    id: "authorization",
    icon: UserCheck,
    title: "You confirm every scan",
    body: "Each submission requires you to affirm you are authorized to test that target. We cannot verify it for you.",
  },
  {
    id: "acceptable-use",
    icon: Ban,
    title: "No scanning strangers",
    body: "Pointing SentryStrike at a system you have no permission to test is a breach of these terms and likely a crime.",
  },
  {
    id: "targets",
    icon: Network,
    title: "Private ranges are blocked",
    body: "Targets resolving to internal or loopback addresses are refused before a scan starts.",
  },
  {
    id: "findings",
    icon: ShieldAlert,
    title: "A clean scan proves nothing",
    body: "No automated tool finds every flaw. Treat results as a starting point, not a certificate.",
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

function TermsPage() {
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
                <Scale className='ico' />
                Terms of use
              </span>
              <h1>The rules for using SentryStrike.</h1>
              <p>
                SentryStrike sends real attack traffic at whatever you aim it
                at. That makes the question of what you are allowed to scan the
                most important thing on this page, so it comes early and in plain
                words.
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
              <section id='agreement'>
                <h2>The agreement</h2>
                <p>
                  These terms are between you and SentryStrike. By requesting
                  access, signing in, or running a scan, you accept them. If you
                  are agreeing on behalf of a company, you are confirming you
                  have the authority to bind it, and {'"'}you{'"'} means that
                  company.
                </p>
                <p>
                  How we handle the data behind all of this is covered
                  separately in the{" "}
                  <Link to='/privacy' viewTransition>
                    privacy policy
                  </Link>
                  , which forms part of this agreement.
                </p>
              </section>

              <section id='accounts'>
                <h2>Accounts and workspaces</h2>
                <p>
                  Access is granted by request rather than open signup. Give us
                  accurate details when you ask for it, and keep your
                  credentials to yourself. Anything done through your account is
                  treated as done by you, so tell us promptly if you think
                  someone else has got in.
                </p>
                <p>
                  Accounts belong to one workspace and carry one role. Owners and
                  administrators decide who joins, who leaves, and what each
                  member may do. Every member of a workspace can read that
                  workspace{"'"}s scans and findings, so invite people
                  accordingly. Do not share a login between colleagues when a
                  second invitation would do.
                </p>
              </section>

              <section id='authorization'>
                <h2>Authorization to test</h2>
                <p>
                  This is the clause that matters. You may only scan a system you
                  own, or one you have documented permission from its owner to
                  test. Permission from someone who merely uses the system,
                  administers a single account on it, or built part of it is not
                  enough.
                </p>
                <p>
                  Every scan submission requires you to confirm this. The
                  confirmation is mandatory and a scan will not start without it.
                  It is a statement of fact you are making to us, and we rely on
                  it, because no scanner can tell the difference between an
                  application you own and one that merely responds to requests.
                </p>
                <div className='legal-callout'>
                  <p>
                    Unauthorized scanning is a criminal offence in most
                    jurisdictions, including under Nepal{"'"}s Electronic
                    Transactions Act, the Computer Fraud and Abuse Act in the
                    United States, and the Computer Misuse Act in the United
                    Kingdom.
                  </p>
                  <p>
                    If you scan something you had no right to scan, that is your
                    liability, not ours. Get the permission in writing and keep
                    it. Agree the scope, the hosts, and the test window before
                    you start.
                  </p>
                </div>
              </section>

              <section id='acceptable-use'>
                <h2>Acceptable use</h2>
                <p>Do not use SentryStrike to:</p>
                <ul>
                  <li>
                    scan any system you do not own or have written permission to
                    test, including to {'"'}check if it is vulnerable{'"'} out of
                    curiosity
                  </li>
                  <li>
                    attempt to take a service down, exhaust its capacity, or
                    otherwise cause disruption rather than find defects
                  </li>
                  <li>
                    reach systems on networks that are not yours by using our
                    infrastructure as the origin of the traffic
                  </li>
                  <li>
                    extract, keep, or pass on personal data you encounter in a
                    target beyond what the assessment genuinely requires
                  </li>
                  <li>
                    resell scans to third parties, or run the service on behalf
                    of clients, without telling us first
                  </li>
                  <li>
                    probe, overload, or reverse engineer SentryStrike itself
                    outside a security disclosure we have agreed to
                  </li>
                  <li>
                    share credentials, evade a suspension, or register again
                    after we have removed you
                  </li>
                </ul>
                <p>
                  If you find a vulnerability in SentryStrike, report it to us
                  before doing anything else with it. We will work with you in
                  good faith and will not pursue researchers who act in good
                  faith.
                </p>
              </section>

              <section id='targets'>
                <h2>Targets we refuse</h2>
                <p>
                  We block targets that resolve to private, loopback, or
                  link-local addresses. That includes the usual internal ranges
                  and hostnames pointing at the local machine, and we resolve the
                  name before deciding rather than trusting how it looks.
                </p>
                <p>
                  This is a safety net, not a permission system. It stops our
                  infrastructure being used to reach networks it has no business
                  touching, and it stops an obvious category of mistake. It
                  cannot tell whether you were allowed to scan a public address,
                  which is why the confirmation above exists. A target passing
                  this check is not a target you are cleared to test.
                </p>
              </section>

              <section id='conduct'>
                <h2>Running a scan responsibly</h2>
                <p>
                  Active testing sends payloads that can create records, modify
                  data, trigger emails or webhooks, and lock accounts. Run scans
                  against staging where you can. When you must scan production,
                  agree a window with whoever operates it and have a way to reach
                  someone if the application starts misbehaving.
                </p>
                <p>
                  Use dedicated test accounts rather than a real user{"'"}s
                  login, and rotate them when the assessment ends. Seed test data
                  instead of pointing a crawler at genuine customer records. You
                  remain responsible for the effect a scan has on your systems
                  and on anyone using them.
                </p>
              </section>

              <section id='findings'>
                <h2>What a scan does not prove</h2>
                <p>
                  SentryStrike reports what it observed. It grades evidence,
                  flags likely false positives, and tells you where coverage was
                  incomplete, but it is not a substitute for a human review.
                  Review the evidence behind a finding before acting on it, and
                  read the coverage warnings before concluding an area is clean.
                </p>
                <p>
                  A scan with no findings does not mean the application is
                  secure. It means this tool did not find anything on this run
                  within the scope it was given. We provide the service and the
                  analysis, not a guarantee about the security of your
                  applications, and results are not legal or compliance advice.
                </p>
              </section>

              <section id='availability'>
                <h2>Availability</h2>
                <p>
                  We aim to keep the platform running and will give notice of
                  planned maintenance where we reasonably can. We do not promise
                  uninterrupted service, and scans can fail for reasons on your
                  side too, including an unreachable target, a login flow the
                  crawler cannot complete, or a rate limit on the application
                  being tested.
                </p>
                <p>
                  Scan data is deleted once its workspace retention window
                  passes. Export anything you need to keep before then, because
                  a purge cannot be undone.
                </p>
              </section>

              <section id='ip'>
                <h2>Ownership</h2>
                <p>
                  We own the platform: the scanner, the analysis, the interface,
                  and the name. You get permission to use it while your account
                  is in good standing, and nothing here transfers ownership of it
                  to you.
                </p>
                <p>
                  Your workspace content stays yours. That covers the
                  applications you register, the scans you run, the findings and
                  the evidence behind them, and the comments your team writes. We
                  use it to run the service for you and for nothing else. We do
                  not train models on your scan data.
                </p>
              </section>

              <section id='liability'>
                <h2>Liability</h2>
                <p>
                  The service is provided as it is, without warranties beyond
                  those the law will not let us exclude. We are not liable for
                  lost profit, lost data, or indirect and consequential losses,
                  and our total liability is limited to what you paid us in the
                  twelve months before the claim.
                </p>
                <p>
                  You agree to cover us against claims arising from scans you ran
                  without authorization, from your breach of these terms, and
                  from harm your testing caused to a third party. Nothing here
                  limits liability that cannot lawfully be limited.
                </p>
              </section>

              <section id='termination'>
                <h2>Suspension and termination</h2>
                <p>
                  You can stop using SentryStrike whenever you like, and an owner
                  can close a workspace. We may suspend or remove an account that
                  breaches these terms, and we will act immediately and without
                  warning where scanning appears to be unauthorized or is
                  harming someone else{"'"}s systems.
                </p>
                <p>
                  After termination your workspace content is deleted on the
                  normal retention schedule. Audit records outlive it, for the
                  reasons set out in the{" "}
                  <Link to='/privacy' viewTransition>
                    privacy policy
                  </Link>
                  . The clauses on authorization, ownership, and liability
                  survive.
                </p>
              </section>

              <section id='changes'>
                <h2>Changes and contact</h2>
                <p>
                  We will update the date at the top of this page when these
                  terms change, and notify workspace owners by email when a
                  change materially affects your obligations. Continuing to use
                  the service after that means you accept the revised terms.
                </p>
                <p>
                  Questions about any of this, or about a scan you are unsure is
                  in bounds, can be sent to us by email. Ask before you scan
                  rather than after.
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

export default TermsPage;
