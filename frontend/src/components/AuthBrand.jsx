function AuthBrand({ mode = "login" }) {
  const register = mode === "register";

  return (
    <aside className='auth-art'>
      <div className='auth-copy'>
        <span className='auth-art-label'>SentryStrike workspace</span>
        <h2>{register ? "Your first report starts with one URL." : "Security progress your team can see."}</h2>
        <p>
          {register
            ? "Run verified assessments and give each stakeholder the detail they need."
            : "Keep every assessment, report, retest, and piece of evidence in one focused workspace."}
        </p>
        <div className='proof'>
          {(register
            ? [["Standard", "OWASP web assessment"], ["Access", "Public and authenticated"], ["Output", "PDF and JSON reports"]]
            : [["Assessments", "Live progress and history"], ["Reports", "Executive and developer detail"], ["Evidence", "Verified request and response data"]]
          ).map(([label, value]) => (
            <div key={label}><span>{label}</span><b>{value}</b></div>
          ))}
        </div>
      </div>
    </aside>
  );
}

export default AuthBrand;
