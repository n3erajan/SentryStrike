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

const button =
  "inline-flex min-h-[42px] items-center justify-center gap-2 whitespace-nowrap rounded-lg border px-[15px] text-[13px] font-semibold no-underline transition duration-200 hover:-translate-y-px active:translate-y-px focus-visible:outline-3 focus-visible:outline-offset-2";
const primaryButton = `${button} border-[#006de2] bg-[#006de2] text-white hover:border-[#004bb7] hover:bg-[#004bb7] focus-visible:outline-[#d4eaff]`;
const secondaryButton = `${button} border-[#cbd5e3] bg-[#fafcfe] text-[#0a1421] hover:bg-[#e8eff8] focus-visible:outline-[#d4eaff]`;

const WORKFLOW = [
  { id: "provide", title: "Provide the application", description: "Add URL, authorization, and optional test users." },
  { id: "scan", title: "Run the scan", description: "Map routes, replay workflows, and test OWASP controls." },
  { id: "report", title: "Act on the report", description: "Review risk, evidence, remediation, and coverage." },
];

const OWASP = {
  a01: { nav: "A01 Access Control", label: "A01 - BROKEN ACCESS CONTROL", title: "Test what each identity can reach.", description: "Compare unauthenticated, normal-user, secondary-user, and administrator access to verify horizontal and vertical authorization failures.", chips: ["IDOR / BOLA", "Privilege escalation", "Cross-account access"] },
  a02: { nav: "A02 Misconfiguration", label: "A02 - SECURITY MISCONFIGURATION", title: "Find dangerous defaults and exposed surfaces.", description: "Inspect headers, sensitive paths, directory listings, backup files, and exception pages for security-impacting configuration gaps.", chips: ["Security headers", "Sensitive paths", "Error disclosure"] },
  a04: { nav: "A04 Cryptographic", label: "A04 - CRYPTOGRAPHIC FAILURES", title: "Inspect transport security.", description: "Analyze HTTPS, TLS configuration, certificates, and visible cryptographic weaknesses across the scanned application.", chips: ["TLS analysis", "Certificates", "HTTPS enforcement"] },
  a05: { nav: "A05 Injection", label: "A05 - INJECTION", title: "Verify input-driven execution.", description: "Test SQL injection, cross-site scripting, command injection, file inclusion, unsafe uploads, and server-side request forgery.", chips: ["SQL injection", "XSS", "Command injection", "SSRF"] },
  a07: { nav: "A07 Authentication", label: "A07 - AUTHENTICATION FAILURES", title: "Test sessions and login boundaries.", description: "Evaluate authentication workflows, sessions, CSRF protection, and role boundaries with the test access you provide.", chips: ["Session validation", "CSRF", "Auth boundaries"] },
};

const ROLES = {
  owner: { nav: "Business risk", title: "Make release decisions with clear priorities.", description: "See the overall risk score, verified findings, plain-language impact, and the work that should happen first.", items: ["Risk score and severity breakdown", "Executive summary", "Prioritized remediation", "Export-ready PDF and JSON"] },
  developer: { nav: "Developer evidence", title: "Go from finding to fix.", description: "Inspect endpoints, payloads, masked evidence, reproduction details, and focused remediation guidance.", items: ["Exact endpoint and parameter", "Request and response evidence", "CVSS and exploitability", "Focused remediation"] },
  security: { nav: "Coverage quality", title: "Judge coverage, not just findings.", description: "Review authentication context, evidence strength, detector metrics, attack chains, and scanner limitations.", items: ["SPA and API coverage", "Authenticated target verification", "Skipped-reason visibility", "Evidence strength breakdown"] },
};

const FAQS = [
  ["Can SentryStrike test behind login?", "Yes. Provide primary, secondary, and administrator test accounts for authenticated workflows and access-control testing. Credentials are used for the scan and are not stored."],
  ["Does this replace a human penetration test?", "No. It automates repeatable web application scanning. Threat modeling, business logic, insecure design, and monitoring review still benefit from skilled human testing."],
  ["What can I export?", "Completed scans can be downloaded as a formatted PDF or raw JSON, including findings, evidence, remediation, coverage, and scanner limitations."],
];

function Brand() {
  return (
    <Link to='/' className='flex items-center gap-2.5 text-[17px] font-bold text-[#0a1421] no-underline' aria-label='SentryStrike home'>
      <span className='grid h-[34px] w-[30px] shrink-0 place-items-center rounded-[48%_48%_40%_40%] bg-[#006de2] text-white'><ShieldCheck size={18} weight='bold' /></span>
      SentryStrike
    </Link>
  );
}

function ScanPreview() {
  return (
    <div className='relative grid min-h-[560px] place-items-center max-lg:min-h-[510px] max-sm:min-h-[470px] max-[440px]:min-h-[430px]' aria-label='Scan preview'>
      <div className='pointer-events-none absolute size-[500px] animate-[orbit_26s_linear_infinite] rounded-full border border-[#cbd5e3] max-lg:size-[440px] max-sm:size-[370px] max-[440px]:size-[315px]'>
        <span className='absolute inset-[68px] rounded-full border border-[#cbd5e3]' />
        <span className='absolute inset-[136px] rounded-full border border-[#cbd5e3]' />
        <i className='absolute -left-[5px] top-1/2 size-2.5 rounded-full bg-[#006de2]' />
      </div>
      <div className='relative w-full max-w-[500px] rounded-[14px] bg-[#05101e] p-[21px] text-[#e7ecf2] shadow-[0_24px_70px_rgba(35,50,83,0.2)] max-[440px]:p-[17px]'>
        <div className='flex justify-between border-b border-[#344059] pb-3.5 text-[13px]'><b>Scan preview</b><span className='flex items-center'><i className='mr-2 inline-block size-2 animate-[breathe_2s_cubic-bezier(0.16,1,0.3,1)_infinite] rounded-full bg-[#1c8742] shadow-[0_0_0_5px_rgba(39,135,93,0.14)]' />Ready</span></div>
        <div className='mt-[17px] grid grid-cols-[1fr_auto] gap-2 rounded-[7px] bg-[#0d1b2d] p-[9px_9px_9px_12px]'>
          <input className='min-w-0 border-0 bg-transparent font-mono text-xs text-[#e7ecf2] outline-none' value='https://staging.example.com' readOnly aria-label='Example target URL' />
          <Link className='grid size-[38px] place-items-center rounded-[5px] bg-[#006de2] text-white transition hover:bg-[#004bb7]' to='/register' aria-label='Create an account to start a scan'><ArrowUpRight size={18} weight='bold' /></Link>
        </div>
        <div className='mt-[18px] flex justify-between text-[11px] text-[#aeb9cf]'><span>Testing application controls</span><b className='font-mono tabular-nums'>64%</b></div>
        <div className='mt-2 h-1.5 bg-[#2d374d]'><span className='block h-full w-[64%] bg-[#006de2]' /></div>
        <div className='mt-4 grid grid-cols-4 gap-[7px] max-sm:grid-cols-2'>
          {[["Map app", "done"], ["Detect stack", "done"], ["Test controls", "active"], ["Build report", ""]].map(([label, state]) => <div key={label} className={`rounded-[5px] bg-[#0d1b2d] px-1.5 py-2 text-[9px] ${state === "done" ? "text-[#65c69b]" : state === "active" ? "outline outline-1 outline-[#006de2] text-[#e7ecf2]" : "text-[#929db2]"}`}>{label}</div>)}
        </div>
        <div className='mt-4 border-t border-[#344059]'>
          {[["Broken object-level authorization", "9.1", "#de3d34"], ["Stored cross-site scripting", "8.4", "#de3d34"], ["Cross-site request forgery", "6.2", "#d78c00"]].map(([name, score, color]) => <div key={name} className='grid grid-cols-[7px_1fr_auto] items-center gap-[9px] border-b border-[#303a50] py-[9px] text-[10px]'><i className='size-[7px] rounded-full' style={{ background: color }} /><span>{name}</span><b>{score}</b></div>)}
        </div>
      </div>
    </div>
  );
}

function CoverageRows({ rows }) {
  return <div className='mt-[19px] grid gap-3'>{rows.map(([label, width, value]) => <div key={label} className='grid grid-cols-[125px_1fr_38px] items-center gap-2.5 text-[11px] max-[440px]:grid-cols-[105px_1fr_38px]'><span>{label}</span><span className='h-1.5 bg-[#e8eff8]'><i className='block h-full bg-[#006de2]' style={{ width }} /></span><b>{value}</b></div>)}</div>;
}

function WorkflowPreview({ active }) {
  if (active === "scan") return <div className='animate-[enter_.35s_cubic-bezier(0.16,1,0.3,1)]'><h3 className='text-[15px] font-semibold'>Live application coverage</h3><CoverageRows rows={[["Routes discovered", "92%", "164"], ["API endpoints", "74%", "14"], ["Forms submitted", "75%", "21/28"], ["Security tests", "64%", "64%"]]} /></div>;
  if (active === "report") return <div className='animate-[enter_.35s_cubic-bezier(0.16,1,0.3,1)] rounded-[10px] border border-[#cbd5e3] bg-[#fafcfe] p-[19px]'><div className='flex justify-between border-b border-[#cbd5e3] pb-3 text-xs'><b>Example scan report</b><span>Complete</span></div><div className='grid grid-cols-[95px_1fr] gap-4 py-[19px]'><strong className='font-mono text-[43px] text-[#de3d34]'>42</strong><p className='text-[11px] text-[#415166]'><b className='text-[#0a1421]'>High risk</b><br />Cross-account exposure should block release.</p></div><div className='flex justify-between border-t border-[#cbd5e3] pt-3 text-[11px] text-[#415166]'><span>9 verified findings</span><b>96% coverage</b></div></div>;
  return <div className='animate-[enter_.35s_cubic-bezier(0.16,1,0.3,1)] overflow-hidden rounded-lg border border-[#cbd5e3]'><div className='flex h-9 items-center gap-1.5 bg-[#e8eff8] px-[11px]'>{[0, 1, 2].map((dot) => <i key={dot} className='size-2 rounded-full bg-[#cbd5e3]' />)}</div><div className='p-[19px]'><h3 className='text-[15px] font-semibold'>New scan</h3>{["Application URL", "Scan profile"].map((label, index) => <label key={label} className='mt-[13px] grid gap-1.5 text-[11px] font-semibold text-[#415166]'>{label}<span className='flex min-h-[43px] items-center rounded-[7px] border border-[#cbd5e3] bg-[#fafcfe] px-2.5 font-normal text-[#0a1421]'>{index === 0 ? "https://staging.example.com" : "Full site"}</span></label>)}<Link className={`${primaryButton} mt-[15px]`} to='/register'>Continue</Link></div></div>;
}

function RolePreview({ role }) {
  if (role === "developer") return <div className='rounded-[10px] border border-[#cbd5e3] bg-[#fafcfe] p-[19px]'><div className='flex justify-between border-b border-[#cbd5e3] pb-3 text-xs'><b>Developer evidence</b><span>Confirmed exploit</span></div><pre className='mt-[19px] overflow-x-auto rounded-[7px] bg-[#05101e] p-3.5 font-mono text-[11px] leading-7 text-[#e7ecf2]'>{`GET /api/v1/invoices/8842\nHTTP 200 OK\n{"customer":"Northstar","total":4280}`}</pre></div>;
  if (role === "security") return <div className='rounded-[10px] border border-[#cbd5e3] bg-[#fafcfe] p-[19px]'><div className='flex justify-between border-b border-[#cbd5e3] pb-3 text-xs'><b>Coverage quality</b><span>Dynamic partial</span></div><CoverageRows rows={[["Access control", "91%", "91%"], ["XSS", "84%", "84%"], ["Injection", "78%", "78%"]]} /></div>;
  return <div className='rounded-[10px] border border-[#cbd5e3] bg-[#fafcfe] p-[19px]'><div className='flex justify-between border-b border-[#cbd5e3] pb-3 text-xs'><b>Executive summary</b><span>Verified</span></div><div className='grid grid-cols-[95px_1fr] gap-4 py-[19px]'><strong className='font-mono text-[43px] text-[#de3d34]'>58</strong><p className='text-[11px] text-[#415166]'><b className='text-[#0a1421]'>High risk</b><br />Verified issues should be fixed before release.</p></div><div className='grid grid-cols-3 border-t border-[#cbd5e3] text-[11px] text-[#415166]'><span className='border-r border-[#cbd5e3] p-3'>1 Critical</span><span className='border-r border-[#cbd5e3] p-3'>2 High</span><span className='p-3'>3 Medium</span></div></div>;
}

function SectionHead({ title, children, dark = false }) {
  return <div className='mb-[46px] flex items-end justify-between gap-10 max-lg:flex-col max-lg:items-start'><h2 className='max-w-[12ch] text-[clamp(2.1rem,4.5vw,4rem)] font-bold leading-none tracking-[-.04em]'>{title}</h2><p className={`max-w-[52ch] ${dark ? "text-[#aeb9cf]" : "text-[#415166]"}`}>{children}</p></div>;
}

function LandingPage() {
  const [workflow, setWorkflow] = useState("provide");
  const [owasp, setOwasp] = useState("a01");
  const [role, setRole] = useState("owner");
  const [openFaq, setOpenFaq] = useState(0);
  const owaspItem = OWASP[owasp];
  const roleItem = ROLES[role];

  return (
    <div className='min-h-dvh bg-[#f6f9fd] font-sans text-[#0a1421]'>
      <nav className='sticky top-0 z-20 flex h-[72px] items-center justify-between border-b border-[#cbd5e3] bg-[#fafcfe] px-[clamp(18px,5vw,76px)] max-sm:h-16 max-sm:px-3.5' aria-label='Public navigation'>
        <Brand />
        <div className='flex gap-6 max-sm:hidden'><a className='text-[12px] font-semibold text-[#415166] no-underline transition hover:text-[#006de2]' href='#platform'>Platform</a><a className='text-[12px] font-semibold text-[#415166] no-underline transition hover:text-[#006de2]' href='#owasp'>OWASP 2025</a><a className='text-[12px] font-semibold text-[#415166] no-underline transition hover:text-[#006de2]' href='#teams'>For teams</a><a className='text-[12px] font-semibold text-[#415166] no-underline transition hover:text-[#006de2]' href='#faq'>FAQ</a></div>
        <div className='flex gap-2'><Link className={`${secondaryButton} max-sm:hidden`} to='/login'>Sign in</Link><Link className={`${primaryButton} max-[440px]:px-[11px] max-[440px]:text-[11px]`} to='/register'>New scan</Link></div>
      </nav>
      <main id='main-content'>
        <section className='grid min-h-[calc(100dvh-72px)] grid-cols-[minmax(0,1fr)_minmax(430px,.95fr)] items-center gap-[clamp(42px,7vw,110px)] overflow-hidden px-[clamp(18px,6vw,96px)] pb-[84px] pt-[70px] max-lg:grid-cols-1 max-lg:gap-[35px] max-sm:min-h-0 max-sm:px-4 max-sm:pb-16 max-sm:pt-[52px]'>
          <div className='animate-[enter_.7s_cubic-bezier(0.16,1,0.3,1)]'><span className='inline-flex items-center gap-2 rounded-full bg-[#d4eaff] px-2.5 py-1.5 text-[11px] font-bold text-[#004bb7]'><SealCheck size={16} weight='bold' />OWASP Top 10 web scanning</span><h1 className='mt-5 max-w-[10ch] text-[clamp(3.3rem,6.7vw,6rem)] font-bold leading-[.94] tracking-[-.04em] max-sm:text-[3.65rem] max-[440px]:text-5xl'>Know what your web app exposes.</h1><p className='mt-[23px] max-w-[58ch] text-[17px] leading-[1.55] text-[#415166]'>SentryStrike turns an application URL into verified vulnerabilities, clear business risk, developer evidence, and a report your team can act on.</p><div className='mt-[29px] flex gap-2.5 max-sm:flex-col'><Link className={primaryButton} to='/register'>Start a new scan</Link><a className={secondaryButton} href='#platform'>Explore the platform</a></div><div className='mt-[31px] flex flex-wrap gap-5 text-[11px] text-[#6f7c8c]'><span className='flex items-center gap-[7px]'><LockKey size={16} />Credentials never stored</span><span className='flex items-center gap-[7px]'><CheckCircle size={16} />Verified evidence</span><span className='flex items-center gap-[7px]'><FileText size={16} />Export-ready reports</span></div></div>
          <ScanPreview />
        </section>
        <div className='flex items-center gap-7 overflow-hidden border-y border-[#cbd5e3] bg-[#fafcfe] px-[clamp(18px,6vw,96px)] py-[17px]'><span className='shrink-0 text-[11px] text-[#6f7c8c]'>Built for</span><div className='flex min-w-max animate-[ticker_22s_linear_infinite] gap-[42px] text-[12px] font-semibold text-[#415166]'>{["Business owners", "Development teams", "Security teams", "Growing SaaS companies", "Business owners", "Development teams", "Security teams", "Growing SaaS companies"].map((item, index) => <span key={`${item}-${index}`}>{item}</span>)}</div></div>
        <section className='border-b border-[#cbd5e3] px-[clamp(18px,6vw,96px)] py-[92px] max-sm:px-4 max-sm:py-[66px]' id='platform'>
          <SectionHead title='From URL to security decision.'>A guided workflow keeps scan setup approachable without hiding the technical depth developers need.</SectionHead>
          <div className='grid grid-cols-[.85fr_1.15fr] gap-[65px] max-lg:grid-cols-1'><div className='border-t border-[#0a1421]'>{WORKFLOW.map((item, index) => <button key={item.id} type='button' onClick={() => setWorkflow(item.id)} className={`grid w-full grid-cols-[36px_1fr] gap-3 border-0 border-b border-[#cbd5e3] py-5 text-left text-[#0a1421] transition ${workflow === item.id ? "bg-[#fafcfe] pl-[9px]" : "bg-transparent hover:bg-[#fafcfe]/60"}`}><b className={`grid size-[30px] place-items-center rounded-md font-mono text-[11px] ${workflow === item.id ? "bg-[#006de2] text-white" : "bg-[#e8eff8]"}`}>0{index + 1}</b><span><strong className='block text-[15px]'>{item.title}</strong><small className='mt-[3px] block text-[12px] text-[#415166]'>{item.description}</small></span></button>)}</div><div className='min-h-[370px] rounded-[11px] border border-[#cbd5e3] bg-[#fafcfe] p-[23px]'><WorkflowPreview active={workflow} /></div></div>
        </section>
        <section className='border-b border-[#cbd5e3] bg-[#05101e] px-[clamp(18px,6vw,96px)] py-[92px] text-[#e7ecf2] max-sm:px-4 max-sm:py-[66px]' id='owasp'>
          <SectionHead title='OWASP coverage, stated honestly.' dark>Automated categories are tested actively. Coverage notes and scanner limitations remain visible in the final report.</SectionHead>
          <div className='grid grid-cols-[260px_1fr] gap-12 max-lg:grid-cols-1'><div className='grid max-lg:flex max-lg:overflow-x-auto'>{Object.entries(OWASP).map(([key, item]) => <button key={key} type='button' onClick={() => setOwasp(key)} className={`min-h-12 border-0 border-b border-[#344059] px-2 text-left font-semibold transition max-lg:min-w-[185px] ${owasp === key ? "bg-[#0d1b2d] text-[#e7ecf2]" : "bg-transparent text-[#9da9bf] hover:text-white"}`}>{item.nav}</button>)}</div><div className='animate-[enter_.35s_cubic-bezier(0.16,1,0.3,1)] border-t border-[#46516a] pt-6' key={owasp}><span className='font-mono text-[11px] font-medium text-[#9eb6ff]'>{owaspItem.label}</span><h3 className='mt-3 text-[clamp(2rem,4vw,3.4rem)] font-bold leading-[1.05] tracking-[-.035em]'>{owaspItem.title}</h3><p className='mt-[13px] max-w-[60ch] text-[#aeb9cf]'>{owaspItem.description}</p><div className='mt-5 flex flex-wrap gap-2'>{owaspItem.chips.map((chip) => <i key={chip} className='rounded-full border border-[#46516a] px-2.5 py-1.5 text-[10px] not-italic'>{chip}</i>)}</div></div></div>
        </section>
        <section className='border-b border-[#cbd5e3] px-[clamp(18px,6vw,96px)] py-[92px] max-sm:px-4 max-sm:py-[66px]' id='teams'>
          <SectionHead title='One report. Every useful layer.'>Business context, developer evidence, and coverage stay connected to the same verified findings.</SectionHead>
          <div className='mb-[25px] flex gap-[7px] overflow-x-auto'>{Object.entries(ROLES).map(([key, item]) => <button key={key} type='button' onClick={() => setRole(key)} className={`min-h-10 shrink-0 rounded-full border border-[#cbd5e3] px-3.5 font-semibold transition ${role === key ? "bg-[#0a1421] text-white" : "bg-[#fafcfe] text-[#415166] hover:bg-[#e8eff8]"}`}>{item.nav}</button>)}</div>
          <div className='grid animate-[enter_.35s_cubic-bezier(0.16,1,0.3,1)] grid-cols-[.85fr_1.15fr] items-center gap-[58px] max-lg:grid-cols-1' key={role}><div><h3 className='text-[clamp(2rem,4vw,3.3rem)] font-bold leading-[1.05] tracking-[-.035em]'>{roleItem.title}</h3><p className='mt-3 text-[#415166]'>{roleItem.description}</p><ul className='mt-5 grid list-none gap-[9px] p-0'>{roleItem.items.map((item) => <li className='flex items-center gap-2 text-xs' key={item}><Check size={15} weight='bold' className='text-[#1c8742]' />{item}</li>)}</ul></div><RolePreview role={role} /></div>
        </section>
        <section className='border-b border-[#cbd5e3] px-[clamp(18px,6vw,96px)] py-[92px] max-sm:px-4 max-sm:py-[66px]' id='faq'><div className='mx-auto max-w-[940px]'><h2 className='mb-[30px] text-[clamp(2.1rem,4vw,3.6rem)] font-bold tracking-[-.035em]'>Questions worth asking.</h2>{FAQS.map(([question, answer], index) => <article className='border-t border-[#cbd5e3] last:border-b' key={question}><button className='flex min-h-[62px] w-full items-center justify-between border-0 bg-transparent text-left font-semibold text-[#0a1421]' type='button' onClick={() => setOpenFaq(openFaq === index ? -1 : index)} aria-expanded={openFaq === index}>{question}<Plus className={`shrink-0 transition ${openFaq === index ? "rotate-45" : ""}`} size={18} weight='bold' /></button><div className={`grid transition-[grid-template-rows] duration-300 ${openFaq === index ? "grid-rows-[1fr]" : "grid-rows-[0fr]"}`}><div className='overflow-hidden'><p className='pb-[17px] pr-[38px] text-[12px] text-[#415166]'>{answer}</p></div></div></article>)}</div></section>
        <section className='flex items-center justify-between gap-[30px] bg-[#006de2] px-[clamp(18px,6vw,96px)] py-[68px] text-white max-sm:flex-col max-sm:items-start max-sm:px-4 max-sm:py-[55px]'><div><h2 className='text-[clamp(2.1rem,4vw,3.8rem)] font-bold leading-none tracking-[-.04em]'>Start with your application URL.</h2><p className='mt-[7px] text-[#dfe7ff]'>Run an evidence-backed scan your whole team can use.</p></div><Link className={`${button} border-white bg-[#fafcfe] text-[#004bb7] hover:bg-[#e8eff8] focus-visible:outline-white`} to='/register'>Create account</Link></section>
      </main>
      <footer className='flex justify-between px-[clamp(18px,6vw,96px)] py-[27px] text-[11px] text-[#6f7c8c] max-sm:flex-col max-sm:gap-2 max-sm:px-4'><span>Copyright {new Date().getFullYear()} SentryStrike</span><span>Authorized security testing only</span></footer>
    </div>
  );
}

export default LandingPage;
