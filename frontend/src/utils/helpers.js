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

export { isValidUrl, downloadFile, saveBlob, copyToClipboard };
