#!/usr/bin/env python3
"""Load signatures into a real Suricata engine (`suricata -T`) and map any
parse errors or warnings back to the source file and line.

All target files are concatenated into one temporary rule file (Suricata's -S
takes a single file), and the line offsets are kept so engine output can be
attributed to the original `suricata/<year>/CVE-*.rules` file.

Usage:
  scripts/validate_suricata_engine.py                    # whole tree
  scripts/validate_suricata_engine.py --base origin/main # changed files only
  scripts/validate_suricata_engine.py suricata/2024/CVE-2024-0012.rules
"""

from __future__ import annotations

import argparse
import bisect
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vedas_common import SURICATA_DIR, Reporter, check_layout, resolve_targets  # noqa: E402

CONFIG_CANDIDATES = [
    "/etc/suricata/suricata.yaml",
    "/usr/local/etc/suricata/suricata.yaml",
    "/opt/homebrew/etc/suricata/suricata.yaml",
]
ERR_AT_LINE = re.compile(r'error parsing signature "(?P<rule>.*)" from file .* at line (?P<line>\d+)\s*$')
SID_IN_RULE = re.compile(r"\bsid:\s*(\d+)\s*;")
# Engine warnings that quote the rule, e.g. "duplicate instance for http_uri in '<rule>'".
WARN_RULE = re.compile(r"^W: (?P<module>[\w-]+): (?P<msg>.*?) in '(?P<rule>alert .*)'\s*$")


def find_config(explicit: str | None) -> str:
    if explicit:
        return explicit
    for c in [os.environ.get("SURICATA_CONFIG", ""), *CONFIG_CANDIDATES]:
        if c and Path(c).is_file():
            return c
    sys.exit("could not find suricata.yaml; pass --config or set SURICATA_CONFIG")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--base", help="git ref; validate only files changed since the merge-base")
    ap.add_argument("--config", help="suricata.yaml to use (default: auto-detect)")
    ap.add_argument("--suricata", default=shutil.which("suricata") or "suricata")
    ap.add_argument("--errors-only", action="store_true", help="do not report engine warnings")
    args = ap.parse_args()

    rep = Reporter()
    all_files = check_layout(SURICATA_DIR, ".rules", Reporter())  # layout errors are reported by the lint scripts
    targets = resolve_targets(args.paths, args.base, SURICATA_DIR, ".rules", all_files)
    if not targets:
        print("no Suricata signatures to validate")
        return rep.summary("suricata engine", 0)

    config = find_config(args.config)
    version = subprocess.run([args.suricata, "-V"], capture_output=True, text=True).stdout.strip()
    print(f"{version} | config {config} | {len(targets)} file(s)")

    # Concatenate, recording (start_line, path) so engine line numbers map back.
    starts: list[int] = []
    owners: list[Path] = []
    sid_owner: dict[int, tuple[Path, int]] = {}
    combined: list[str] = []
    for f in targets:
        starts.append(len(combined) + 1)
        owners.append(f)
        for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
            combined.append(line)
            m = SID_IN_RULE.search(line)
            if m:
                sid_owner.setdefault(int(m.group(1)), (f, i))

    def locate(n: int) -> tuple[Path, int]:
        idx = bisect.bisect_right(starts, n) - 1
        return owners[idx], n - starts[idx] + 1

    with tempfile.TemporaryDirectory() as tmp:
        rules = Path(tmp) / "vedas.rules"
        rules.write_text("\n".join(combined) + "\n")
        logdir = Path(tmp) / "log"
        logdir.mkdir()
        # Pin the console format so parsing does not depend on the distro's suricata.yaml.
        env = {**os.environ, "SC_LOG_FORMAT": "%D: %S: %M", "SC_LOG_LEVEL": "notice"}
        proc = subprocess.run(
            [args.suricata, "-T", "-c", config, "-S", str(rules), "-l", str(logdir)],
            capture_output=True, text=True, env=env,
        )
    output = (proc.stdout + proc.stderr).splitlines()

    reason = None
    for line in output:
        m = ERR_AT_LINE.search(line)
        if m:
            path, ln = locate(int(m.group("line")))
            rep.error(path, f"suricata rejected rule: {reason or 'parse error'}", ln)
            reason = None
            continue
        if line.startswith("E: "):
            reason = line[3:].strip()
            continue
        w = WARN_RULE.match(line)
        if w and not args.errors_only:
            sid = SID_IN_RULE.search(w.group("rule"))
            if sid and int(sid.group(1)) in sid_owner:
                path, ln = sid_owner[int(sid.group(1))]
                rep.warning(path, f"suricata: {w.group('msg')}", ln)

    if proc.returncode != 0 and rep.errors == 0:
        # Failure we could not attribute to a rule (bad config, crash, ...): show raw output.
        print("\n".join(output[-40:]))
        rep.error(None, f"suricata -T exited with status {proc.returncode}")

    return rep.summary("suricata engine", len(targets))


if __name__ == "__main__":
    sys.exit(main())
