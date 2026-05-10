import asyncio
import ssl
from urllib.parse import urlparse


class SslAnalyzer:
    async def analyze(self, url: str) -> dict:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return {"valid": False, "issues": ["Invalid hostname"]}
        if parsed.scheme != "https":
            return {"valid": False, "issues": ["Target is not HTTPS"]}

        context = ssl.create_default_context()
        issues: list[str] = []

        try:
            reader, writer = await asyncio.open_connection(hostname, 443, ssl=context, server_hostname=hostname)
            writer.close()
            await writer.wait_closed()
        except Exception:
            issues.append("Unable to validate TLS handshake in lightweight analyzer")

        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "protocol": "TLS",
        }
