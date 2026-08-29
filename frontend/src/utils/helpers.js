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

// Compact "how long ago" for list rows. Always pair it with formatAbsolute in a
// title/tooltip: "5h ago" three rows running tells you nothing about which came
// first, and a relative-only timestamp is unreadable once a page is left open.
function formatRelative(iso) {
  const d = parseUTCDate(iso);
  if (!d) return "-";
  const diff = Math.max(0, Date.now() - d.getTime());
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

// Full local timestamp, for the title attribute behind a relative one.
function formatAbsolute(iso) {
  const d = parseUTCDate(iso);
  if (!d) return "";
  return d.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

// Machine-readable value for <time dateTime>.
function toISOString(iso) {
  const d = parseUTCDate(iso);
  return d ? d.toISOString() : undefined;
}

function hostnameOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url || "unknown";
  }
}

// Props for a table row that navigates when clicked.
//
// The row keeps `role="row"` so assistive tech still reads its cells; the
// keyboard route in is the real <Link> in the primary cell, not the row itself.
// Making the row a `role="button"` would have been fewer lines but collapses
// every cell into one flat label, so the score, the finding count and the
// timestamp all stop being announced.
//
// The click handler is the pointer-only convenience on top of that, and bails
// when the click landed on a control that has its own behaviour - otherwise the
// row would navigate on top of a download button or the title link.
function navigableRowProps(onActivate) {
  return {
    role: "row",
    onClick: (event) => {
      if (event.target.closest("a, button, input, select, textarea")) return;
      onActivate(event);
    },
  };
}

// Page numbers with ellipsis gaps, e.g. [1, "…", 7, 8, 9, "…", 24].
function paginate(current, total) {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  const set = new Set([
    1,
    total,
    ...[current - 1, current, current + 1].filter((p) => p > 1 && p < total),
  ]);
  const result = [];
  let prev = 0;
  for (const p of [...set].sort((a, b) => a - b)) {
    if (p - prev > 1) result.push("…");
    result.push(p);
    prev = p;
  }
  return result;
}

export {
  isValidUrl,
  downloadFile,
  saveBlob,
  copyToClipboard,
  parseUTCDate,
  formatRelative,
  formatAbsolute,
  toISOString,
  hostnameOf,
  navigableRowProps,
  paginate,
  resolveBackTarget,
};
