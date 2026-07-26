function AuthBrand({ mode = "login" }) {
  const register = mode === "register";
  const heading = register
    ? "Start with the app you need to test."
    : "Keep your security work in one place.";
  const sub = register
    ? "Run an authorized scan and get evidence your team can review."
    : "Track apps, scans, findings, and fixes from one workspace.";
  const proof = register
    ? [
        ["Standard", "OWASP Top 10 2025"],
        ["Coverage", "Public and authenticated"],
        ["Reports", "UI and PDF"],
      ]
    : [
        ["Applications", "Saved targets and history"],
        ["Findings", "Evidence and fix status"],
        ["Reports", "Results your team can share"],
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
