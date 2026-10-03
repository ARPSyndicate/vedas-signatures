#!/usr/bin/env python3
"""Load Nuclei templates with `nuclei -validate` and map failures back to files.

Usage:
  scripts/validate_nuclei_engine.py                    # whole tree
  scripts/validate_nuclei_engine.py --base origin/main # changed files only
  scripts/validate_nuclei_engine.py nuclei/2024/CVE-2024-0012.yaml
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vedas_common import NUCLEI_DIR, Reporter, check_layout, resolve_targets  # noqa: E402

ANSI = re.compile(r"\x1b\[[0-9;]*m")
# [ERR] Error occurred loading template /abs/path.yaml: cause="..."
# [WRN] ... /abs/path.yaml ...
LEVEL = re.compile(r"^\[(?P<lvl>ERR|WRN|FTL)\]\s*(?P<msg>.*)$")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--base", help="git ref; validate only files changed since the merge-base")
    ap.add_argument("--nuclei", default=shutil.which("nuclei") or "nuclei")
    ap.add_argument("--timeout", type=int, default=600)
    args = ap.parse_args()

    rep = Reporter()
    all_files = check_layout(NUCLEI_DIR, ".yaml", Reporter())  # layout errors are reported by the lint scripts
    targets = resolve_targets(args.paths, args.base, NUCLEI_DIR, ".yaml", all_files)
    if not targets:
        print("no Nuclei templates to validate")
        return rep.summary("nuclei engine", 0)

    version = subprocess.run([args.nuclei, "-version"], capture_output=True, text=True,
                             stdin=subprocess.DEVNULL)
    ver = re.search(r"v\d+\.\d+\.\d+", ANSI.sub("", version.stdout + version.stderr))
    print(f"nuclei {ver.group() if ver else '?'} | {len(targets)} file(s)")

    by_path = {str(t.resolve()): t for t in targets}
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as lst:
        lst.write("\n".join(by_path) + "\n")
    try:
        proc = subprocess.run(
            [args.nuclei, "-duc", "-nc", "-validate", "-t", lst.name],
            capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=args.timeout,
        )
    finally:
        Path(lst.name).unlink(missing_ok=True)

    unattributed = []
    for raw in (proc.stdout + proc.stderr).splitlines():
        m = LEVEL.match(ANSI.sub("", raw).strip())
        if not m:
            continue
        msg = m.group("msg")
        owner = next((p for p in by_path if p in msg), None)
        if owner:
            msg = msg.replace(owner, by_path[owner].name)
            (rep.error if m.group("lvl") == "ERR" else rep.warning)(by_path[owner], f"nuclei: {msg}")
        elif m.group("lvl") in ("ERR", "FTL"):
            unattributed.append(msg)

    if proc.returncode != 0 and rep.errors == 0:
        for msg in unattributed or [f"nuclei -validate exited with status {proc.returncode}"]:
            rep.error(None, f"nuclei: {msg}")

    return rep.summary("nuclei engine", len(targets))


if __name__ == "__main__":
    sys.exit(main())
