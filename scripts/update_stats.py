#!/usr/bin/env python3
"""Regenerate the coverage table in README.md between the STATS markers.

Usage:
  scripts/update_stats.py          # rewrite README.md in place
  scripts/update_stats.py --check  # exit 1 if README.md is stale
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vedas_common import NUCLEI_DIR, REPO_ROOT, SURICATA_DIR  # noqa: E402

README = REPO_ROOT / "README.md"
START, END = "<!-- STATS:START -->", "<!-- STATS:END -->"


def count_rules(path: Path) -> int:
    return sum(1 for line in path.read_text(errors="replace").splitlines()
               if line.strip() and not line.lstrip().startswith("#"))


def render() -> str:
    sur_files, sur_rules, nuc_files = Counter(), Counter(), Counter()
    for f in SURICATA_DIR.glob("[0-9][0-9][0-9][0-9]/CVE-*.rules"):
        sur_files[f.parent.name] += 1
        sur_rules[f.parent.name] += count_rules(f)
    for f in NUCLEI_DIR.glob("[0-9][0-9][0-9][0-9]/CVE-*.yaml"):
        nuc_files[f.parent.name] += 1

    years = sorted(set(sur_files) | set(nuc_files))
    sur_stems = {f.stem for f in SURICATA_DIR.glob("*/CVE-*.rules")}
    nuc_stems = {f.stem for f in NUCLEI_DIR.glob("*/CVE-*.yaml")}
    total = len(sur_stems | nuc_stems)
    network_only = len(sur_stems - nuc_stems)
    header = f"**{total:,} unique CVEs covered.**"
    if network_only:
        header += (f" Most carry both a Suricata rule and a Nuclei template; "
                   f"{network_only:,} destructive or DoS CVEs are network-detection-only "
                   f"— a passive Suricata rule with no active Nuclei check "
                   f"(listed in [SURICATA_ONLY.txt](SURICATA_ONLY.txt)).")
    else:
        header += " Each carries a Suricata rule and a Nuclei template."
    lines = [
        START,
        header,
        "",
        "| CVE year | Suricata Signatures | Nuclei Signatures |",
        "| --- | ---: | ---: |",
    ]
    for y in years:
        lines.append(f"| {y} | {sur_rules[y]:,} | {nuc_files[y]:,} |")
    lines.append(END)
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    text = README.read_text()
    pattern = re.compile(re.escape(START) + r".*?" + re.escape(END), re.S)
    if not pattern.search(text):
        sys.exit(f"README.md has no {START} ... {END} block")
    updated = pattern.sub(lambda _: render(), text)
    if updated == text:
        print("README.md stats are up to date")
        return 0
    if args.check:
        print("README.md stats are stale; run scripts/update_stats.py")
        return 1
    README.write_text(updated)
    print("README.md stats updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
