#!/usr/bin/env python3
"""Print the next free Suricata SID(s) for a contribution.

Usage:
  scripts/next_sid.py          # one community SID
  scripts/next_sid.py -n 3     # three consecutive SIDs
  scripts/next_sid.py --vedas  # next SID in the VEDAS generator range (maintainers)

Two open pull requests can be handed the same SID; CI on the second one will
flag the collision after the first is merged, so just re-run this script.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vedas_common import COMMUNITY_SID_RANGE, SURICATA_DIR, VEDAS_SID_RANGE  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-n", type=int, default=1, help="how many SIDs to allocate")
    ap.add_argument("--vedas", action="store_true", help="allocate from the VEDAS generator range")
    args = ap.parse_args()

    rng = VEDAS_SID_RANGE if args.vedas else COMMUNITY_SID_RANGE
    used = {
        int(m)
        for f in SURICATA_DIR.rglob("*.rules")
        for m in re.findall(r"\bsid:\s*(\d+)\s*;", f.read_text(errors="replace"))
    }
    start = max((s for s in used if s in rng), default=rng.start - 1) + 1
    if start + args.n - 1 >= rng.stop:
        sys.exit(f"SID range {rng.start}-{rng.stop - 1} is exhausted")
    for sid in range(start, start + args.n):
        print(sid)
    return 0


if __name__ == "__main__":
    sys.exit(main())
