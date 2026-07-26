const REDACTED = '[REDACTED]'

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`
}

function placeholderFromName(name) {
  const key = String(name || 'SECRET')
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
  return `<YOUR_${key || 'SECRET'}>`
}

function rewriteRedacted(text) {
  if (!text) return text
  let out = String(text)
  out = out.replace(
    /([A-Za-z0-9_.-]+)=\[REDACTED\]/g,
    (_, name) => `${name}=${placeholderFromName(name)}`,
  )
  out = out.replace(
    /(["'])([A-Za-z0-9_.-]+)\1(\s*:\s*)"\[REDACTED\]"/g,
    (_, q, name, space) => `${q}${name}${q}${space}"${placeholderFromName(name)}"`,
  )
  out = out.replace(
    /(["'])([A-Za-z0-9_.-]+)\1(\s*:\s*)\[REDACTED\]/g,
    (_, q, name, space) => `${q}${name}${q}${space}"${placeholderFromName(name)}"`,
  )
  out = out.replaceAll(REDACTED, '<YOUR_SECRET>')
  return out
}

function normalizeHeaderValue(name, value) {
  if (String(name).toLowerCase() !== 'content-type') return value

  const values = String(value)
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean)
  if (
    values.length > 1 &&
    values.every((part) => part.toLowerCase() === values[0].toLowerCase())
  ) {
    return values[0]
  }
  return value
}

function parseHttpRequest(snippet) {
  if (!snippet || typeof snippet !== 'string') return null
  const normalized = snippet.replace(/\r\n/g, '\n')
  const parts = normalized.split('\n\n')
  const head = parts[0] || ''
  const body = parts.slice(1).join('\n\n')
  const lines = head.split('\n').filter((l, i) => i === 0 || l.trim() !== '')
  if (!lines.length) return null
  const m = lines[0].match(/^([A-Z]+)\s+(\S+)(?:\s+HTTP\/\d(?:\.\d)?)?$/i)
  if (!m) return null
  const method = m[1].toUpperCase()
  const path = m[2]
  const headers = []
  for (const line of lines.slice(1)) {
    const idx = line.indexOf(':')
    if (idx <= 0) continue
    headers.push([line.slice(0, idx).trim(), line.slice(idx + 1).trim()])
  }
  return { method, path, headers, body: body || '' }
}

function absoluteUrl(path, headers, baseUrl) {
  if (/^https?:\/\//i.test(path)) return path
  const hostHeader = headers.find(([k]) => k.toLowerCase() === 'host')?.[1]
  let scheme = 'https'
  let host = hostHeader || ''
  if (baseUrl) {
    try {
      const u = new URL(baseUrl)
      scheme = u.protocol.replace(':', '') || scheme
      if (!host) host = u.host
    } catch {
      /* ignore */
    }
  }
  if (!host) return null
  if (!baseUrl) {
    const origin = headers.find(([k]) => k.toLowerCase() === 'origin')?.[1]
    const referer = headers.find(([k]) => k.toLowerCase() === 'referer')?.[1]
    const hint = origin || referer
    if (hint) {
      try {
        scheme = new URL(hint).protocol.replace(':', '') || scheme
      } catch {
        /* ignore */
      }
    }
    if (/^localhost(:\d+)?$/i.test(host) || /^127\.\d+\.\d+\.\d+/.test(host)) {
      scheme = 'http'
    }
  }
  const p = path.startsWith('/') ? path : `/${path}`
  return `${scheme}://${host}${p}`
}

function httpSnippetToCurl(snippet, options = {}) {
  const parsed = parseHttpRequest(snippet)
  if (!parsed) return null
  const url = absoluteUrl(parsed.path, parsed.headers, options.baseUrl)
  if (!url) return null

  const curlExe = options.curlExe || 'curl'
  const parts = [curlExe, '-i -X', parsed.method, shellQuote(url)]

  for (const [name, value] of parsed.headers) {
    const lower = name.toLowerCase()
    if (lower === 'host' || lower === 'content-length') continue
    let v = normalizeHeaderValue(name, value)
    if (v === REDACTED) {
      v = placeholderFromName(name)
    } else if (lower === 'cookie' || lower === 'set-cookie') {
      v = rewriteRedacted(v)
    } else if (v.includes(REDACTED)) {
      v = rewriteRedacted(v)
    }
    parts.push('-H', shellQuote(`${name}: ${v}`))
  }

  if (parsed.body && parsed.body.trim() !== '') {
    parts.push('--data-raw', shellQuote(rewriteRedacted(parsed.body)))
  }

  const curl = parts.join(' ')
  if (curl.includes(REDACTED)) {
    return curl.replaceAll(REDACTED, '<YOUR_SECRET>')
  }
  return curl
}

export {
  httpSnippetToCurl,
  parseHttpRequest,
  rewriteRedacted,
  placeholderFromName,
}
