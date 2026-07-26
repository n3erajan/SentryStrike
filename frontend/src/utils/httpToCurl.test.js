import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { httpSnippetToCurl } from './httpToCurl.js'

describe('httpSnippetToCurl', () => {
  it('converts GET with Host into absolute URL curl', () => {
    const snippet = [
      'GET /search?q=test HTTP/1.1',
      'Host: target.example',
      'Accept: text/html',
      '',
      '',
    ].join('\n')

    const curl = httpSnippetToCurl(snippet)

    assert.equal(
      curl,
      "curl -i -X GET 'https://target.example/search?q=test' -H 'Accept: text/html'",
    )
    assert.equal(curl.includes('[REDACTED]'), false)
  })

  it('rewrites redacted Authorization and Cookie crumbs to placeholders', () => {
    const snippet = [
      'POST /login HTTP/1.1',
      'Host: target.example',
      'Content-Type: application/x-www-form-urlencoded',
      'Cookie: session=[REDACTED]; theme=dark',
      'Authorization: [REDACTED]',
      '',
      'username=x&password=[REDACTED]',
    ].join('\n')

    const curl = httpSnippetToCurl(snippet)

    assert.match(curl, /^curl -i -X POST 'https:\/\/target\.example\/login'/)
    assert.match(curl, /-H 'Content-Type: application\/x-www-form-urlencoded'/)
    assert.match(curl, /-H 'Cookie: session=<YOUR_SESSION>; theme=dark'/)
    assert.match(curl, /-H 'Authorization: <YOUR_AUTHORIZATION>'/)
    assert.match(curl, /--data-raw 'username=x&password=<YOUR_PASSWORD>'/)
    assert.equal(curl.includes('[REDACTED]'), false)
  })

  it('uses baseUrl scheme/host when Host header is missing', () => {
    const snippet = ['GET /x HTTP/1.1', 'Accept: */*', '', ''].join('\n')
    const curl = httpSnippetToCurl(snippet, {
      baseUrl: 'http://app.local:8080/ignored',
    })
    assert.match(curl, /curl -i -X GET 'http:\/\/app\.local:8080\/x'/)
  })

  it('skips Host and Content-Length headers', () => {
    const snippet = [
      'GET /a HTTP/1.1',
      'Host: target.example',
      'Content-Length: 0',
      'X-Request-Id: abc',
      '',
      '',
    ].join('\n')
    const curl = httpSnippetToCurl(snippet)
    assert.equal(curl.includes('Host:'), false)
    assert.equal(curl.includes('Content-Length'), false)
    assert.match(curl, /-H 'X-Request-Id: abc'/)
  })

  it('collapses comma-joined duplicate Content-Type values', () => {
    const snippet = [
      'POST /rest/user/login HTTP/1.1',
      'Host: localhost:3000',
      'Content-Type: application/json, application/json',
      'Accept-Encoding: gzip, deflate',
      '',
      '{"email":"scanner@example.com","password":"secret"}',
    ].join('\n')

    const curl = httpSnippetToCurl(snippet)

    assert.match(curl, /-H 'Content-Type: application\/json'/)
    assert.equal(curl.includes('application/json, application/json'), false)
    assert.match(curl, /-H 'Accept-Encoding: gzip, deflate'/)
  })

  it('shell-escapes single quotes in values', () => {
    const snippet = [
      'GET /q HTTP/1.1',
      'Host: target.example',
      "X-Name: O'Brien",
      '',
      '',
    ].join('\n')
    const curl = httpSnippetToCurl(snippet)
    assert.match(curl, /-H 'X-Name: O'\\''Brien'/)
  })

  it('returns null for empty or unparseable snippet', () => {
    assert.equal(httpSnippetToCurl(''), null)
    assert.equal(httpSnippetToCurl('not a request'), null)
  })

  it('rewrites JSON body redacted credential fields', () => {
    const snippet = [
      'POST /api/profile HTTP/1.1',
      'Host: api.example',
      'Content-Type: application/json',
      '',
      '{"token":"[REDACTED]","name":"ada"}',
    ].join('\n')
    const curl = httpSnippetToCurl(snippet)
    assert.match(curl, /--data-raw '\{"token":"<YOUR_TOKEN>","name":"ada"\}'/)
    assert.equal(curl.includes('[REDACTED]'), false)
  })
})
