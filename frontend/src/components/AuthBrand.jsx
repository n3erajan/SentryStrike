function AuthBrand({ mode = "login" }) {
  const register = mode === "register";
  const heading = register
    ? "Your first report starts with one URL."
    : "Security progress your team can see.";
  const sub = register
    ? "Run verified assessments and give each stakeholder the detail they need."
    : "Keep every application, assessment, report, and retest in one place.";
  const proof = register
    ? [
        ["Standard", "OWASP Top 10 2025"],
        ["Access", "Public and authenticated"],
        ["Output", "Shareable PDF reports"],
      ]
    : [
        ["Applications", "Portfolio-level posture"],
        ["Reports", "Executive and developer views"],
        ["History", "Compare progress over time"],
      ];

  return (
    <aside className='auth-art'>
      <div className='auth-copy'>
        <h2>{heading}</h2>
        <p>{sub}</p>
        <div className='proof'>
          {proof.map(([label, value]) => (
            <div key={label}>
              <span>{label}</span>
              <b>{value}</b>
            </div>
          ))}
        </div>
      </div>
    </aside>
  );
}

export default AuthBrand;
