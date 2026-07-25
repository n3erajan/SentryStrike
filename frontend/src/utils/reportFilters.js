export function normalizedTargetUrl(value) {
  try {
    const url = new URL(value);
    const path = url.pathname === "/" ? "" : url.pathname;
    return `${url.protocol.toLowerCase()}//${url.host.toLowerCase()}${path}${url.search}${url.hash}`;
  } catch {
    return value || "";
  }
}

export function belongsToApplication(scan, application) {
  if (!application) return true;
  if (String(scan.application_id || "") === String(application.id)) return true;
  return (
    !scan.application_id &&
    normalizedTargetUrl(scan.target_url) ===
      normalizedTargetUrl(application.target_url)
  );
}
