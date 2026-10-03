#!/usr/bin/env python3
"""Confirm that every CVE a contribution targets is a published CVE record.

Looks each ID up in the CVE Services API (cve.org). REJECTED or unknown IDs are
errors; network failures are warnings so an API outage never blocks a PR.

Usage:
  scripts/check_cve.py --base origin/main      # CVEs of changed signature files
  scripts/check_cve.py CVE-2024-0012 suricata/2021/CVE-2021-44228.rules
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vedas_common import CVE_RE, NUCLEI_DIR, SURICATA_DIR, Reporter, changed_files  # noqa: E402

API = "https://cveawg.mitre.org/api/cve/{}"


def lookup(cve: str) -> tuple[str | None, str | None]:
    """Return (state, error). state is PUBLISHED / REJECTED / None if not found."""
    req = urllib.request.Request(API.format(cve), headers={"User-Agent": "vedas-signatures-ci"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                meta = json.load(resp).get("cveMetadata", {})
                return meta.get("state"), None
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None, None
            err = f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            err = str(exc)
        time.sleep(2 ** attempt)
    return None, err


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("items", nargs="*", help="CVE IDs or signature file paths")
    ap.add_argument("--base", help="git ref; check CVEs of files changed since the merge-base")
    args = ap.parse_args()

    targets: dict[str, Path | None] = {}
    if args.base:
        for f in changed_files(args.base, SURICATA_DIR, ".rules") + changed_files(args.base, NUCLEI_DIR, ".yaml"):
            targets.setdefault(f.stem, f)
    for item in args.items:
        p = Path(item)
        targets.setdefault(p.stem if p.suffix else item.upper(), p if p.suffix else None)

    rep = Reporter()
    for cve, path in sorted(targets.items()):
        if not CVE_RE.match(cve):
            rep.error(path, f"{cve} is not a CVE ID")
            continue
        state, err = lookup(cve)
        if err:
            rep.warning(path, f"could not look up {cve} on cve.org ({err}); maintainers will verify manually")
        elif state is None:
            rep.error(path, f"{cve} does not exist on cve.org")
        elif state != "PUBLISHED":
            rep.error(path, f"{cve} is {state} on cve.org; only published CVEs are accepted")
        else:
            print(f"ok      {cve}")
    return rep.summary("cve check", len(targets))


if __name__ == "__main__":
    sys.exit(main())
