import asyncio
import ssl
from urllib.parse import urlparse


class SslAnalyzer:
    """Lightweight TLS handshake checker.

    Performs an async TLS handshake with the target on port 443 and reports
    whether the connection succeeded. Does not inspect certificate chains or
    cipher suites — it is a basic gate that flags targets without HTTPS.
    Production-grade TLS evaluation is deferred to an external tool.
    """

    async def analyze(self, url: str) -> dict:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return {"valid": False, "issues": ["Invalid hostname"]}

        port = 443
        context = ssl.create_default_context()
        issues: list[str] = []

        try:
            reader, writer = await asyncio.open_connection(
                hostname, port, ssl=context, server_hostname=hostname
            )
            writer.close()
            await writer.wait_closed()
        except Exception:
            if parsed.scheme == "https":
                issues.append("Unable to validate TLS handshake in lightweight analyzer")
            else:
                issues.append("Target does not support HTTPS (no TLS response on port 443)")

        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "protocol": "TLS",
        }
