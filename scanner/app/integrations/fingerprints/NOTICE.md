# Fingerprint Database — Attribution

The files `technologies.json` and `categories.json` in this directory are a
**merged, vendored copy** of the community-maintained web technology fingerprint
database, used under the MIT License.

- **Upstream source:** https://github.com/enthec/webappanalyzer (`src/technologies/*.json`,
  `src/categories.json`), the actively-maintained successor to the original
  Wappalyzer fingerprint set after the Wappalyzer client went closed-source (2023).
- **License:** MIT (see the upstream repository for the full license text).
- **Fallback mirror:** https://github.com/tunetheweb/wappalyzer (also MIT).

SentryStrike vendors the **data only** — it does not depend on or bundle the
upstream matching engine (our engine is a clean-room reimplementation of the
documented pattern format in `../wappalyzer_engine.py`).

## Refreshing

Run the updater to pull the latest fingerprints:

```
python scanner/scripts/update_fingerprints.py
```

This regenerates both JSON files from upstream.
