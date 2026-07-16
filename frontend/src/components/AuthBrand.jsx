function AuthBrand({ mode = "login" }) {
  const register = mode === "register";
  const proof = register
    ? [["Standard", "OWASP Top 10 web scanning"], ["Access", "Public and authenticated"], ["Output", "PDF and JSON reports"]]
    : [["Scans", "Live progress and worker state"], ["Reports", "Executive and developer detail"], ["History", "Every completed scan"]];

  return (
    <aside className='hidden min-h-dvh items-center bg-[#006de2] p-[50px] text-white lg:flex'>
      <div className='max-w-[760px]'>
        <h2 className='max-w-[12ch] text-[clamp(2.7rem,5vw,4.7rem)] font-bold leading-[.96] tracking-[-.04em]'>{register ? "Your first report starts with one URL." : "Security progress your team can see."}</h2>
        <p className='mt-[17px] max-w-[52ch] text-[15px] text-[#dfe7ff]'>{register ? "Run verified scans and give each stakeholder the detail they need." : "Keep every scan, report, and retest in one focused workspace."}</p>
        <div className='mt-[38px] border-t border-[#8eaeff]'>
          {proof.map(([label, value]) => <div key={label} className='grid grid-cols-[125px_1fr] border-b border-[#8eaeff] py-[11px] text-[11px]'><span className='text-[#d2ddff]'>{label}</span><b>{value}</b></div>)}
        </div>
      </div>
    </aside>
  );
}

export default AuthBrand;
