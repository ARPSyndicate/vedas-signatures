#!/usr/bin/env python3
"""Verify Suricata <-> Nuclei coverage parity, honoring the network-only allowlist.

Active-detection CVEs must have BOTH a Suricata rule and a Nuclei template.
CVEs listed in SURICATA_ONLY.txt intentionally have a Suricata rule and NO Nuclei
template (destructive / DoS classes that cannot be actively probed without harm).
"""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from vedas_common import NUCLEI_DIR, REPO_ROOT, SURICATA_DIR  # noqa: E402

def load_only(name: str) -> set[str]:
    f = REPO_ROOT / name
    if not f.exists():
        return set()
    out = set()
    for line in f.read_text().splitlines():
        line = line.split("#")[0].strip()
        if line:
            out.add(line)
    return out

def main() -> int:
    sur = {p.stem for p in SURICATA_DIR.glob("*/CVE-*.rules")}
    nuc = {p.stem for p in NUCLEI_DIR.glob("*/CVE-*.yaml")}
    only = load_only("SURICATA_ONLY.txt")
    nuc_only = load_only("NUCLEI_ONLY.txt")  # Nuclei template, intentionally no Suricata rule
    errs = []
    # nuclei must have a suricata counterpart unless declared nuclei-only
    for c in sorted(nuc - sur - nuc_only):
        errs.append(f"{c}: Nuclei template has no Suricata rule and is not in NUCLEI_ONLY.txt")
    # a suricata rule without nuclei must be declared network-only
    for c in sorted(sur - nuc - only):
        errs.append(f"{c}: Suricata rule has no Nuclei template and is not in SURICATA_ONLY.txt")
    # SURICATA_ONLY entries must actually be suricata-only
    for c in sorted(only):
        if c not in sur:
            errs.append(f"{c}: listed in SURICATA_ONLY.txt but has no Suricata rule")
        if c in nuc:
            errs.append(f"{c}: listed in SURICATA_ONLY.txt but also has a Nuclei template")
    # NUCLEI_ONLY entries must actually be nuclei-only
    for c in sorted(nuc_only):
        if c not in nuc:
            errs.append(f"{c}: listed in NUCLEI_ONLY.txt but has no Nuclei template")
        if c in sur:
            errs.append(f"{c}: listed in NUCLEI_ONLY.txt but also has a Suricata rule")
    paired = len(sur & nuc)
    print(f"paired (active): {paired} | network-only (Suricata): {len(only)} | "
          f"host-only (Nuclei): {len(nuc_only)} | "
          f"suricata total: {len(sur)} | nuclei total: {len(nuc)}")
    if errs:
        print(f"PARITY ERRORS ({len(errs)}):")
        for e in errs[:40]:
            print("  " + e)
        return 1
    print("parity OK")
    return 0

if __name__ == "__main__":
    sys.exit(main())
