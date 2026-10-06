#!/usr/bin/env python3
"""Load and compile Nuclei templates with the real engine, mapping failures to files.

Two passes, because `nuclei -validate` only parses structure and does NOT resolve
payload files / compile requests (so a template referencing a missing wordlist passes
-validate but breaks the engine at scan time):

  1. `-validate`                     -- structural load
  2. compile pass (`-u <dummy>`)     -- forces request + payload compilation

Usage:
  scripts/validate_nuclei_engine.py                    # whole tree
  scripts/validate_nuclei_engine.py --base origin/main # changed files only
  scripts/validate_nuclei_engine.py nuclei/2024/CVE-2024-0012.yaml
  scripts/validate_nuclei_engine.py --no-compile       # skip the compile pass
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
LEVEL = re.compile(r"^\[(?P<lvl>ERR|WRN|FTL)\]\s*(?P<msg>.*)$")
# Compile-time failures nuclei prints without a [ERR] prefix, e.g.
#   Error occurred parsing template CVE-2023-24489.yaml: could not compile request:
#   could not parse payloads: the helpers/wordlists/numbers.txt file ... does not exist
COMPILE_ERR = re.compile(
    r"(error occurred (?:parsing|loading) template|could not compile|"
    r"could not parse payloads|does not (?:exist|contain))", re.I)


def run_pass(nuclei_bin, listfile, extra, by_path, rep, timeout, label, warn_ok):
    """Run one nuclei pass and attribute ERR/FTL (and compile errors) back to files."""
    proc = subprocess.run(
        [nuclei_bin, "-duc", "-nc", *extra, "-t", listfile],
        capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=timeout,
    )
    unattributed = []
    for raw in (proc.stdout + proc.stderr).splitlines():
        line = ANSI.sub("", raw).strip()
        m = LEVEL.match(line)
        if m:
            lvl, msg = m.group("lvl"), m.group("msg")
        elif COMPILE_ERR.search(line):
            lvl, msg = "ERR", line
        else:
            continue
        if lvl == "WRN" and not warn_ok:
            continue  # connection warnings from the dummy-target compile pass are noise
        owner = next((p for p in by_path if p in msg), None) \
            or next((p for p in by_path if Path(p).name in msg), None)
        if owner:
            msg = msg.replace(owner, by_path[owner].name).replace(Path(owner).name, by_path[owner].name)
            (rep.error if lvl in ("ERR", "FTL") else rep.warning)(by_path[owner], f"nuclei {label}: {msg}")
        elif lvl in ("ERR", "FTL"):
            unattributed.append(msg)
    return proc, unattributed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--base", help="git ref; validate only files changed since the merge-base")
    ap.add_argument("--nuclei", default=shutil.which("nuclei") or "nuclei")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--no-compile", action="store_true", help="skip the request/payload compile pass")
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
        # Pass 1: structural validation.
        proc, un = run_pass(args.nuclei, lst.name, ["-validate"], by_path, rep,
                            args.timeout, "-validate", warn_ok=True)
        if proc.returncode != 0 and rep.errors == 0:
            for msg in un or [f"nuclei -validate exited with status {proc.returncode}"]:
                rep.error(None, f"nuclei -validate: {msg}")
        # Pass 2: compile pass -- forces request/payload compilation that -validate skips.
        # Scans an unroutable dummy target so nothing real is contacted; connection
        # failures are ignored, only load/compile errors are attributed.
        if not args.no_compile:
            cproc, cun = run_pass(
                args.nuclei, lst.name,
                ["-u", "http://127.0.0.1:1", "-no-interactsh", "-timeout", "1", "-retries", "0"],
                by_path, rep, args.timeout, "compile", warn_ok=False)
            for msg in cun:
                if COMPILE_ERR.search(msg):
                    rep.error(None, f"nuclei compile: {msg}")
    finally:
        Path(lst.name).unlink(missing_ok=True)

    return rep.summary("nuclei engine", len(targets))


if __name__ == "__main__":
    sys.exit(main())
