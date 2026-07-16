"""Refresh the vendored Wappalyzer-style fingerprint database.

Downloads the MIT-licensed community fingerprints from enthec/webappanalyzer
(the actively-maintained successor to the now-closed-source Wappalyzer client),
merges the per-letter technology files into a single ``technologies.json``, and
writes it alongside ``categories.json`` under ``app/integrations/fingerprints/``.

Run periodically to stay current:

    python scanner/scripts/update_fingerprints.py

No runtime dependency on the upstream project - we vendor the data only.
"""

from __future__ import annotations

import json
import string
import sys
import urllib.request
from pathlib import Path

RAW_BASE = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src"
# Fallback mirror (also MIT) if the primary is unavailable.
FALLBACK_BASE = "https://raw.githubusercontent.com/tunetheweb/wappalyzer/master/src"

OUT_DIR = Path(__file__).resolve().parent.parent / "app" / "integrations" / "fingerprints"

# Technology files are split by first character: "_" then "a".."z".
SHARDS = ["_"] + list(string.ascii_lowercase)


def _fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "SentryStrike-fingerprint-updater"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def _fetch_json(path: str) -> dict:
    for base in (RAW_BASE, FALLBACK_BASE):
        try:
            return json.loads(_fetch(f"{base}/{path}"))
        except Exception as exc:  # noqa: BLE001 - best-effort with fallback
            print(f"  ! {base}/{path} failed: {exc}", file=sys.stderr)
    raise RuntimeError(f"could not fetch {path} from any source")


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Fetching categories.json ...")
    categories = _fetch_json("categories.json")

    print(f"Fetching {len(SHARDS)} technology shard(s) ...")
    technologies: dict = {}
    for shard in SHARDS:
        try:
            data = _fetch_json(f"technologies/{shard}.json")
        except RuntimeError as exc:
            print(f"  ! skipping shard {shard}: {exc}", file=sys.stderr)
            continue
        technologies.update(data)
        print(f"  + {shard}.json: {len(data)} techs (total {len(technologies)})")

    (OUT_DIR / "categories.json").write_text(
        json.dumps(categories, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )
    (OUT_DIR / "technologies.json").write_text(
        json.dumps(technologies, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )

    print(
        f"\nWrote {len(technologies)} technologies + {len(categories)} categories to {OUT_DIR}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
