import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { CaretDown, CheckCircle, CircleNotch, File as FileIcon, FileArrowDown, Globe, Lock, SealCheck, ShieldCheck, Sliders, TreeStructure, User, WarningCircle } from "@phosphor-icons/react";
import { useScanForm } from "../hooks/useScan.js";
import { CONFIG_GROUPS, CRED_FIELDS, CRED_ROLES, SCAN_MODES } from "../data/constants.js";

const NOTES = [
  { icon: ShieldCheck, title: "OWASP coverage", desc: "Injection, XSS, access control, SSRF, and misconfiguration detectors." },
  { icon: SealCheck, title: "Verified evidence", desc: "Findings are checked against request and response evidence." },
  { icon: FileArrowDown, title: "Portable reports", desc: "Export completed scans as PDF or JSON." },
];
const inputClass = "mt-1.5 min-h-10 w-full rounded-md border border-[#cbd5e3] bg-white px-3 text-[11px] text-[#0a1421] outline-none transition placeholder:text-[#a1aabb] focus:border-[#006de2] focus:ring-3 focus:ring-[#006de2]/10 disabled:cursor-not-allowed disabled:bg-[#e8eff8]";
const labelClass = "block text-[10px] font-semibold text-[#415166]";
const sectionClass = "border border-[#cbd5e3] bg-white";

function coerce(field, raw) {
  if (raw === "") return "";
  if (field.type === "int") { const n = parseInt(raw, 10); return Number.isNaN(n) ? "" : n; }
  if (field.type === "float") { const n = parseFloat(raw); return Number.isNaN(n) ? "" : n; }
  return raw;
}

function ConfigField({ field, value, onChange, disabled }) {
  const id = `cfg-${field.key}`;
  const props = { id, className: inputClass, value: value ?? "", onChange: (e) => onChange(field.key, field.type === "select" ? e.target.value : coerce(field, e.target.value)), disabled };
  return (
    <label className={labelClass} htmlFor={id}>{field.label}{field.unit && <span className='ml-1 font-normal text-[#98a2b3]'>({field.unit})</span>}
      {field.type === "select" ? <select {...props}><option value=''>Default</option>{field.options.map(([val, label]) => <option key={val} value={val}>{label}</option>)}</select> : <input {...props} type={field.type === "text" ? "text" : "number"} inputMode={field.type === "int" ? "numeric" : undefined} min={field.min} max={field.max} step={field.step ?? (field.type === "int" ? 1 : "any")} maxLength={field.maxLength} placeholder={field.placeholder || "Default"} />}
      {field.help && <span className='mt-1.5 block text-[9px] font-normal leading-4 text-[#6f7c8c]'>{field.help}</span>}
    </label>
  );
}

function CredentialAccount({ role, account, onField, disabled, lead }) {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const basic = CRED_FIELDS.filter((field) => !field.advanced);
  const advanced = CRED_FIELDS.filter((field) => field.advanced);
  return (
    <div className={`border-t px-4 py-4 first:border-t-0 sm:px-5 ${lead ? "border-[#b9c9f5] bg-[#f8faff]" : "border-[#cbd5e3]"}`}>
      <div className='flex flex-col gap-1 sm:flex-row sm:items-baseline sm:justify-between'><span className='text-[11px] font-semibold text-[#0a1421]'>{role.label}{lead && <span className='ml-2 rounded bg-[#d4eaff] px-1.5 py-0.5 text-[8px] font-bold text-[#004bb7]'>Drives crawl</span>}</span><span className='text-[9px] text-[#6f7c8c]'>{role.desc}</span></div>
      <div className='mt-3 grid gap-3 sm:grid-cols-2'>
        {basic.map((field) => <label key={field.key} className='relative block'><span className='sr-only'>{field.label}</span>{field.key === "username" ? <User className='absolute left-3 top-3 text-[#98a2b3]' size={15} /> : <Lock className='absolute left-3 top-3 text-[#98a2b3]' size={15} />}<input className={`${inputClass} mt-0 pl-9`} type={field.type} autoComplete='off' maxLength={field.maxLength} placeholder={field.label} value={account[field.key] ?? ""} onChange={(e) => onField(role.key, field.key, e.target.value)} disabled={disabled} /></label>)}
      </div>
      <button type='button' className='mt-3 inline-flex items-center gap-1.5 border-0 bg-transparent p-0 text-[9px] font-semibold text-[#415166] hover:text-[#006de2]' onClick={() => setShowAdvanced((open) => !open)} aria-expanded={showAdvanced}>Login-flow overrides<CaretDown className={showAdvanced ? "rotate-180" : ""} size={12} weight='bold' /></button>
      {showAdvanced && <div className='mt-3 grid gap-4 sm:grid-cols-2'>{advanced.map((field) => <label key={field.key} className={labelClass} htmlFor={`cred-${role.key}-${field.key}`}>{field.label}<input id={`cred-${role.key}-${field.key}`} className={inputClass} type='text' autoComplete='off' maxLength={field.maxLength} placeholder={field.placeholder || ""} value={account[field.key] ?? ""} onChange={(e) => onField(role.key, field.key, e.target.value)} disabled={disabled} />{field.help && <span className='mt-1.5 block text-[9px] font-normal leading-4 text-[#6f7c8c]'>{field.help}</span>}</label>)}</div>}
    </div>
  );
}

function Choice({ active, onClick, disabled, icon: Icon, title, desc }) {
  return <button type='button' className={`min-h-20 border p-3 text-left transition focus-visible:outline-2 focus-visible:outline-[#006de2] ${active ? "border-[#006de2] bg-[#f4f7ff]" : "border-[#cbd5e3] bg-white hover:border-[#aab7c9]"}`} onClick={onClick} disabled={disabled}><span className={`flex items-center gap-2 text-[11px] font-semibold ${active ? "text-[#004bb7]" : "text-[#0a1421]"}`}>{Icon && <Icon size={15} weight='bold' />}{title}</span><span className='mt-1.5 block text-[9px] leading-4 text-[#6f7c8c]'>{desc}</span></button>;
}

function ScanPage() {
  const navigate = useNavigate();
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const { url, setUrl, crawlMode, setCrawlMode, authText, setAuthText, consent, setConsent, touched, setTouched, config, setConfigField, credentials, setCredentialField, submitting, error, valid, canStart, startScan } = useScanForm();
  const scanMode = config.scan_mode || "";
  async function handleStart() {
    const result = await startScan();
    if (result) navigate(`/active/${result.scanId}`, { state: { target: result.target } });
  }

  return (
    <div className='mx-auto w-full max-w-[1440px] px-4 py-8 sm:px-6 lg:px-8 lg:py-10'>
      <header className='border-b border-[#cbd5e3] pb-7'><span className='text-[10px] font-semibold uppercase tracking-[0.16em] text-[#006de2]'>New scan</span><h1 className='mt-2 text-3xl font-semibold leading-tight'>Configure a security scan</h1><p className='mt-2 max-w-[68ch] text-[12px] leading-6 text-[#415166]'>Define the target, crawl boundary, and optional authenticated coverage. Scanner workers continue in the background after submission.</p></header>
      <div className='mt-7 grid items-start gap-7 xl:grid-cols-[minmax(0,1fr)_320px]'>
        <div className='grid gap-6'>
          {error && <div className='flex items-start gap-2 rounded-md border border-[#efbbb7] bg-[#fff0ef] px-3 py-2.5 text-[12px] text-[#de3d34]'><WarningCircle size={16} weight='fill' />{error}</div>}
          <section className={sectionClass}>
            <div className='border-b border-[#cbd5e3] px-4 py-4 sm:px-5'><span className='font-mono text-[9px] text-[#006de2]'>01</span><h2 className='mt-1 text-[13px] font-semibold'>Target and scope</h2></div>
            <div className='grid gap-5 p-4 sm:p-5'>
              <label className={labelClass} htmlFor='target-url'>Target URL<div className={`mt-1.5 flex min-h-11 items-center rounded-md border bg-white px-3 transition focus-within:border-[#006de2] focus-within:ring-3 focus-within:ring-[#006de2]/10 ${touched && url && !valid ? "border-[#de3d34]" : "border-[#cbd5e3]"}`}><Globe className='mr-2 shrink-0 text-[#6f7c8c]' size={16} /><input className='w-full min-w-0 border-0 bg-transparent font-mono text-[11px] outline-none placeholder:text-[#a1aabb]' id='target-url' type='url' placeholder='https://example.com' value={url} onChange={(event) => setUrl(event.target.value)} onBlur={() => setTouched(true)} disabled={submitting} />{valid && <CheckCircle className='shrink-0 text-[#1c8742]' size={17} weight='fill' />}</div>{touched && url && !valid && <span className='mt-1.5 block text-[9px] font-normal text-[#de3d34]'>Enter a valid URL including http:// or https://</span>}</label>
              <div><span className={labelClass}>Crawl mode</span><div className='mt-1.5 grid gap-2 sm:grid-cols-2'><Choice active={crawlMode === "full"} onClick={() => setCrawlMode("full")} disabled={submitting} icon={TreeStructure} title='Full site' desc='Crawl and test every reachable page.' /><Choice active={crawlMode === "single"} onClick={() => setCrawlMode("single")} disabled={submitting} icon={FileIcon} title='Single page' desc='Test only the target URL.' /></div></div>
              <label className={labelClass} htmlFor='auth-text'>Authorization reference <span className='font-normal text-[#98a2b3]'>optional</span><input id='auth-text' className={inputClass} type='text' maxLength={1000} placeholder='Ticket, contract, or scope note' value={authText} onChange={(event) => setAuthText(event.target.value)} disabled={submitting} /></label>
            </div>
          </section>

          <section className={sectionClass}>
            <button type='button' className='flex w-full items-center gap-3 border-0 bg-white px-4 py-4 text-left sm:px-5' onClick={() => setAdvancedOpen((open) => !open)} aria-expanded={advancedOpen}><span className='grid size-8 place-items-center rounded-md bg-[#eef2f7] text-[#415166]'><Sliders size={16} weight='bold' /></span><span className='flex-1'><span className='block text-[12px] font-semibold'>Advanced scan configuration</span><span className='mt-0.5 block text-[9px] text-[#6f7c8c]'>Optional tuning and authenticated testing accounts</span></span><CaretDown className={advancedOpen ? "rotate-180" : ""} size={14} weight='bold' /></button>
            {advancedOpen && <div className='border-t border-[#cbd5e3]'>
              <div className='p-4 sm:p-5'><h3 className='text-[11px] font-semibold'>Verification mode</h3><p className='mt-1 text-[9px] text-[#6f7c8c]'>Choose the evidence threshold before a finding is reported.</p><div className='mt-3 grid gap-2 md:grid-cols-3'>{SCAN_MODES.map(([val, title, desc]) => <Choice key={val} active={scanMode === val} onClick={() => setConfigField("scan_mode", scanMode === val ? "" : val)} disabled={submitting} title={title} desc={desc} />)}</div></div>
              {CONFIG_GROUPS.map((group) => { const GroupIcon = group.icon; return <div className='border-t border-[#cbd5e3] p-4 sm:p-5' key={group.title}><div className='flex gap-3'><span className='grid size-8 shrink-0 place-items-center rounded-md bg-[#eef2f7] text-[#415166]'><GroupIcon size={15} weight='bold' /></span><div><h3 className='text-[11px] font-semibold'>{group.title}</h3><p className='mt-1 text-[9px] leading-4 text-[#6f7c8c]'>{group.blurb}</p></div></div><div className='mt-4 grid gap-4 sm:grid-cols-2'>{group.fields.map((field) => <ConfigField key={field.key} field={field} value={config[field.key]} onChange={setConfigField} disabled={submitting} />)}</div></div>; })}
              <div className='border-t border-[#cbd5e3] bg-[#f8f9fb] px-4 py-4 sm:px-5'><h3 className='text-[11px] font-semibold'>Authenticated testing</h3><p className='mt-1 max-w-[72ch] text-[9px] leading-4 text-[#6f7c8c]'>Accounts are used for this scan only. A second or admin identity enables horizontal and vertical access-control checks.</p></div>
              {CRED_ROLES.map((role) => <CredentialAccount key={role.key} role={role} account={credentials[role.key] || {}} onField={setCredentialField} disabled={submitting} lead={role.key === "main"} />)}
              <label className='flex items-start gap-3 border-t border-[#cbd5e3] px-4 py-4 text-[10px] leading-5 text-[#415166] sm:px-5'><input className='mt-1 size-4 accent-[#006de2]' type='checkbox' checked={Boolean(config.allow_secondary_provisioning)} onChange={(e) => setConfigField("allow_secondary_provisioning", e.target.checked ? true : "")} disabled={submitting} /><span>Auto-provision a throwaway second identity when no second account is supplied for horizontal IDOR testing.</span></label>
            </div>}
          </section>

          <label className='flex items-start gap-3 border-l-2 border-[#006de2] bg-[#eef3ff] px-4 py-3 text-[10px] leading-5 text-[#3f4b60]'><input className='mt-1 size-4 accent-[#006de2]' type='checkbox' checked={consent} onChange={(event) => setConsent(event.target.checked)} disabled={submitting} /><span>I confirm I am authorized to scan this target. Unauthorized scanning may be illegal.</span></label>
        </div>

        <aside className='grid gap-5 xl:sticky xl:top-24'>
          <section className='border border-[#cfd7e3] bg-white'>
            <div className='border-b border-[#cbd5e3] px-5 py-4'><span className='text-[9px] font-semibold uppercase tracking-[0.13em] text-[#6f7c8c]'>Scan review</span><h2 className='mt-1 text-[13px] font-semibold'>Ready to queue</h2></div>
            <dl className='grid px-5 py-2'>{[["Target", url || "Not set"], ["Scope", crawlMode === "single" ? "Single page" : "Full site"], ["Verification", scanMode || "Server default"], ["Authentication", credentials.main?.username ? "Configured" : "Public pages"]].map(([term, value]) => <div key={term} className='grid grid-cols-[90px_minmax(0,1fr)] gap-3 border-b border-[#edf0f4] py-3 last:border-0'><dt className='text-[9px] text-[#6f7c8c]'>{term}</dt><dd className='m-0 truncate text-right font-mono text-[9px] font-semibold text-[#3f4b60]' title={value}>{value}</dd></div>)}</dl>
            <div className='border-t border-[#cbd5e3] p-4'><button className='inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-md bg-[#006de2] px-4 text-[11px] font-semibold text-white transition hover:bg-[#004bb7] active:translate-y-px disabled:cursor-not-allowed disabled:opacity-45 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#006de2]' disabled={!canStart} onClick={handleStart}>{submitting ? <><CircleNotch className='animate-spin' size={16} weight='bold' />Starting</> : <><ShieldCheck size={16} weight='bold' />Start security scan</>}</button></div>
          </section>
          <div className='grid border-y border-[#cbd5e3]'>{NOTES.map(({ icon: Icon, title, desc }) => <div key={title} className='grid grid-cols-[28px_minmax(0,1fr)] gap-3 border-b border-[#cbd5e3] py-3 last:border-0'><Icon className='mt-0.5 text-[#006de2]' size={18} weight='bold' /><div><h3 className='text-[10px] font-semibold'>{title}</h3><p className='mt-1 text-[9px] leading-4 text-[#6f7c8c]'>{desc}</p></div></div>)}</div>
        </aside>
      </div>
    </div>
  );
}

export default ScanPage;
