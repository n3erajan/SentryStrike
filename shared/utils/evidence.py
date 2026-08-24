"""Separate scanner-authored narrative from the server bytes in an evidence snippet.

Detectors compose evidence snippets as::

    VERIFICATION EVIDENCE:
    <the scanner's own conclusion about the finding>

    RESPONSE EXCERPT:
    <the bytes the target actually sent>

The narrative above ``RESPONSE EXCERPT:`` is the scanner's OWN verdict. Two
consumers must never ingest it as if it were target output:

* the AI false-positive adjudicator - feeding it the scanner's conclusion invites
  circular reasoning (the model reads "confirms data extraction" and agrees with
  it instead of judging the raw response), and
* secondary-disclosure harvesters that mine other findings' responses - a
  scanner-authored line naming an internal IP or error string would be reported
  as the application disclosing it.

``server_response_bytes`` returns only the target-origin bytes, so downstream
consumers judge evidence rather than the scanner's claim about it. This lives in
``shared`` because both the scanner and the analyzer service need it.
"""

from __future__ import annotations

# Section headers detectors have used to narrate their own evidence.
SCANNER_AUTHORED_PREAMBLES: tuple[str, ...] = (
    "VERIFICATION EVIDENCE:",
    "INTERACTION ID:",
    "INTERACTIONS (",
    "EXTERNAL CONTROL SAMPLES",
    "INTERNAL TARGET SAMPLES",
)

# Markers that introduce the real server bytes inside such a composite.
SERVER_RESPONSE_MARKERS: tuple[str, ...] = (
    "TARGET ENDPOINT RESPONSE:",
    "LAST INTERNAL PROBE RESPONSE:",
    "RESPONSE EXCERPT:",
)


def server_response_bytes(snippet: str | None) -> str:
    """Return only the target-origin bytes from a (possibly composite) snippet.

    A snippet with no scanner-authored preamble is returned unchanged - it is
    already pure server bytes. A composite is reduced to the text after its
    server-response marker; a composite with no such marker yields ``""`` rather
    than narrative a consumer would mistake for target output.
    """
    text = snippet or ""
    if not text.startswith(SCANNER_AUTHORED_PREAMBLES):
        return text
    for marker in SERVER_RESPONSE_MARKERS:
        index = text.find(marker)
        if index >= 0:
            return text[index + len(marker):].lstrip("\n")
    return ""
