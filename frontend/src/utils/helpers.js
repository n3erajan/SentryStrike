// function isValidUrl(value) {
//   try {
//     const u = new URL(value);
//     return u.protocol === "http:" || u.protocol === "https:";
//   }
//   catch {
//     return false;
//   }
// }

function isValidUrl(value) {
  if (!value || typeof value !== "string") return false;

  try {
    const url = new URL(value.trim());

    if (url.protocol !== "http:" && url.protocol !== "https:") return false;

    const hostnameRegex =
      /^(localhost|([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|(\d{1,3}\.){3}\d{1,3})$/;

    return hostnameRegex.test(url.hostname);
  } catch {
    return false;
  }
}

function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function buildHtmlReport(report, dateStr) {
  return `<!DOCTYPE html><html><head><title>SentryStrike Report</title><style>body{font-family:sans-serif;padding:2rem;max-width:900px;margin:auto}pre{background:#f5f5f5;padding:1rem;border-radius:6px;overflow-x:auto}</style></head><body><h1>🛡 SentryStrike Report</h1><p><strong>Target:</strong> ${report.target}</p><p><strong>Scan Date:</strong> ${dateStr}</p><p><strong>Duration:</strong> ${report.durationSec}s</p><p><strong>Security Score:</strong> ${report.score}/100</p><pre>${JSON.stringify(report, null, 2)}</pre></body></html>`;
}

export { isValidUrl, buildHtmlReport };
