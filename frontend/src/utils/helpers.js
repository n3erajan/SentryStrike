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

export { isValidUrl, downloadFile, saveBlob };
