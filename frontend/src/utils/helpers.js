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
  saveBlob(new Blob([content], { type: mimeType }), filename);
}

function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    const textarea = document.createElement('textarea')
    textarea.value = text
    textarea.style.position = 'fixed'
    textarea.style.opacity = '0'
    document.body.appendChild(textarea)
    textarea.select()
    document.execCommand('copy')
    document.body.removeChild(textarea)
  }
}

function parseUTCDate(iso) {
  if (iso == null) return null;
  if (typeof iso === "number" || (typeof iso === "string" && /^\d+$/.test(iso))) {
    const d = new Date(typeof iso === "number" ? iso : Number(iso));
    return Number.isNaN(d.getTime()) ? null : d;
  }
  const s = String(iso);
  if (s.includes("T") && !/Z$/i.test(s) && !/[+-]\d{2}:\d{2}$/.test(s)) {
    return new Date(s + "Z");
  }
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

// Resolves a "back" link from router state so a detail page returns to the list
// the user actually came from. Pages that can be reached from more than one list
// (a scan is reachable from /scans and from an application's own history) pass
// `state.from = { to, label }` when navigating; anything that arrives without it
// - a deep link, a notification, a refresh, which all drop router state - falls
// back to the page's default list.
function resolveBackTarget(state, fallbackTo, fallbackLabel) {
  const to = state?.from?.to;
  const label = state?.from?.label;
  // `to` is handed straight to navigate(), so only accept an in-app path.
  // "//host" and "/\host" both start with "/" yet resolve off-site.
  const isInAppPath =
    typeof to === "string" && /^\/(?![/\\])/.test(to);
  if (!isInAppPath) {
    return { to: fallbackTo, label: fallbackLabel };
  }
  return { to, label: label || fallbackLabel };
}

export {
  isValidUrl,
  downloadFile,
  saveBlob,
  copyToClipboard,
  parseUTCDate,
  resolveBackTarget,
};
