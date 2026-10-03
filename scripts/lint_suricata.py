#!/usr/bin/env python3
"""Structural and policy lint for Suricata signatures under suricata/.

This complements the engine check (validate_suricata_engine.py): the engine
tells us whether Suricata can load a rule, this script enforces the repository
conventions every rule must follow.

Usage:
  scripts/lint_suricata.py                       # whole tree
  scripts/lint_suricata.py suricata/2024/CVE-2024-0012.rules
  scripts/lint_suricata.py --base origin/main    # files changed vs main, with SID/rev change checks
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vedas_common import (  # noqa: E402
    COMMUNITY_SID_RANGE,
    SURICATA_DIR,
    VEDAS_SID_RANGE,
    Reporter,
    base_content,
    check_layout,
    rel,
    resolve_targets,
)

ACTIONS = {"alert", "pass", "drop", "reject", "rejectsrc", "rejectdst", "rejectboth"}
# Legacy content modifiers replaced by sticky buffers (http.uri; content:...).
LEGACY_MODIFIERS = {
    "uricontent", "http_uri", "http_raw_uri", "http_method", "http_header", "http_raw_header",
    "http_cookie", "http_client_body", "http_server_body", "http_stat_code", "http_stat_msg",
    "http_user_agent", "http_host", "http_raw_host",
}
STREAM_PROTOS = {"tcp", "http", "http1", "http2", "tls", "ssh", "ftp", "smtp", "smb", "dcerpc",
                 "imap", "pop3", "rdp", "sip", "mqtt", "ldap", "nfs", "modbus", "dnp3", "enip", "krb5"}


@dataclass
class Rule:
    path: Path
    line: int
    text: str
    action: str
    proto: str
    options: list[tuple[str, str | None]]

    def opt(self, key: str) -> list[str]:
        return [v or "" for k, v in self.options if k == key]

    @property
    def sid(self) -> int | None:
        vals = self.opt("sid")
        return int(vals[0]) if len(vals) == 1 and vals[0].strip().isdigit() else None

    @property
    def rev(self) -> int | None:
        vals = self.opt("rev")
        return int(vals[0]) if len(vals) == 1 and vals[0].strip().isdigit() else None


def split_options(body: str) -> list[tuple[str, str | None]] | None:
    """Split the option block the way Suricata does: on every ';' not escaped with '\\'.

    Suricata does not track quotes here, so neither do we. Returns None when the
    last option is missing its terminating ';'.
    """
    opts, buf, i = [], [], 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            buf.append(body[i:i + 2])
            i += 2
            continue
        if c == ";":
            tok = "".join(buf).strip()
            if tok:
                key, sep, val = tok.partition(":")
                opts.append((key.strip(), val.strip() if sep else None))
            buf = []
        else:
            buf.append(c)
        i += 1
    if "".join(buf).strip():
        return None
    return opts


def parse_rules(path: Path, text: str, rep: Reporter | None) -> list[Rule]:
    rules = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        def err(msg):
            if rep:
                rep.error(path, msg, n)
        if raw.rstrip().endswith("\\"):
            err("multi-line rules are not allowed; put each rule on a single line")
            continue
        head, paren, rest = line.partition("(")
        if not paren or not line.endswith(")"):
            err("rule must be of the form: <action> <header> (<options>;)")
            continue
        parts = head.split()
        if len(parts) < 7 or parts[-3] not in ("->", "<>"):
            err("malformed rule header; expected: action proto src sport -> dst dport")
            continue
        opts = split_options(rest[:-1])
        if opts is None:
            err("last option is missing its terminating ';'")
            continue
        rules.append(Rule(path, n, line, parts[0], parts[1].lower(), opts))
    return rules


def lint_file(path: Path, rep: Reporter, errors_only: bool) -> list[Rule]:
    data = path.read_bytes()
    if b"\r" in data:
        rep.error(path, "CRLF line endings; use LF")
    if data and not data.endswith(b"\n"):
        rep.error(path, "file must end with a newline")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        rep.error(path, "file is not valid UTF-8")
        return []
    rules = parse_rules(path, text, rep)
    if not rules:
        rep.error(path, "file contains no active rules")
        return rules

    cve = path.stem
    seen_text = set()
    for r in rules:
        e = lambda msg: rep.error(path, msg, r.line)  # noqa: E731
        w = (lambda msg: None) if errors_only else (lambda msg: rep.warning(path, msg, r.line))
        keys = [k for k, _ in r.options]

        if r.action not in ACTIONS:
            e(f"unknown action '{r.action}'")
        elif r.action != "alert":
            e(f"only 'alert' rules are accepted (got '{r.action}'); operators choose drop/reject locally")

        msgs = r.opt("msg")
        if len(msgs) != 1 or not msgs[0].strip('"').strip():
            e("exactly one non-empty msg is required")
        if len(r.opt("sid")) != 1 or r.sid is None:
            e("exactly one numeric sid is required")
        if len(r.opt("rev")) != 1 or r.rev is None or r.rev < 1:
            e("exactly one rev >= 1 is required")
        refs = [v.replace(" ", "") for v in r.opt("reference")]
        if f"cve,{cve}" not in refs:
            e(f"missing 'reference:cve,{cve};' matching the file name")
        if r.text in seen_text:
            e("duplicate rule in the same file")
        seen_text.add(r.text)

        if "classtype" not in keys:
            w("no classtype; add one from classification.config (e.g. web-application-attack)")
        if r.proto in STREAM_PROTOS and "flow" not in keys:
            w("no flow keyword; add e.g. 'flow:established,to_server;'")
        if not any(k in ("content", "uricontent") for k in keys):
            w("no content match; pcre-only or content-less rules are expensive and noisy")
        legacy = sorted(set(keys) & LEGACY_MODIFIERS)
        if legacy:
            w(f"legacy content modifier(s) {', '.join(legacy)}; prefer sticky buffers (e.g. http.uri; content:...)")
        if not any("vedas.arpsyndicate.io" in v for v in r.opt("reference")):
            w(f"no VEDAS reference; add 'reference:url,https://vedas.arpsyndicate.io/?vuln={cve};'")
    return rules


def check_changes(targets: list[Path], parsed: dict[Path, list[Rule]], base: str,
                  rep: Reporter, allow_vedas_sids: bool, base_sids: set[int]) -> None:
    """Compare changed files against the merge-base: rev bumps and SID ranges."""
    for path in targets:
        old_text = base_content(base, path)
        old = {r.sid: r for r in parse_rules(path, old_text, None)} if old_text else {}
        for r in parsed.get(path, []):
            if r.sid is None:
                continue
            prev = old.get(r.sid)
            if prev is not None:
                if prev.text != r.text and (r.rev or 0) <= (prev.rev or 0):
                    rep.error(path, f"sid {r.sid} was modified; bump rev to {(prev.rev or 0) + 1}", r.line)
                continue
            if r.sid in base_sids:
                continue  # rule moved from another file; uniqueness is checked globally
            if r.sid in COMMUNITY_SID_RANGE:
                continue
            if allow_vedas_sids and r.sid in VEDAS_SID_RANGE:
                continue
            rep.error(path, f"new sid {r.sid} is outside the community range "
                            f"{COMMUNITY_SID_RANGE.start}-{COMMUNITY_SID_RANGE.stop - 1}; "
                            "run scripts/next_sid.py to get a free one", r.line)


def collect_base_sids(base: str) -> set[int]:
    from vedas_common import git
    mb = git("merge-base", base, "HEAD").strip()
    out = git("grep", "-hoE", r"[(; ]sid: *[0-9]+", mb, "--", rel(SURICATA_DIR))
    return {int(re.search(r"\d+", s).group()) for s in out.splitlines()}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", help="files or directories to lint (default: whole tree)")
    ap.add_argument("--base", help="git ref to diff against; lints changed files and checks rev/SID policy")
    ap.add_argument("--errors-only", action="store_true", help="suppress style warnings")
    ap.add_argument("--allow-vedas-sids", action="store_true",
                    default=os.environ.get("ALLOW_VEDAS_SIDS") == "true",
                    help="permit new SIDs in the VEDAS range (generator output)")
    args = ap.parse_args()

    rep = Reporter()
    all_files = check_layout(SURICATA_DIR, ".rules", rep)
    targets = resolve_targets(args.paths, args.base, SURICATA_DIR, ".rules", all_files)
    target_set = set(targets)

    parsed: dict[Path, list[Rule]] = {}
    for f in targets:
        parsed[f] = lint_file(f, rep, args.errors_only)

    # Global SID uniqueness: index every rule in the tree, report on targets.
    by_sid: dict[int, list[Rule]] = defaultdict(list)
    for f in all_files:
        rules = parsed[f] if f in parsed else parse_rules(f, f.read_text(errors="replace"), None)
        for r in rules:
            if r.sid is not None:
                by_sid[r.sid].append(r)
    for sid, rules in by_sid.items():
        if len(rules) < 2:
            continue
        where = ", ".join(f"{rel(r.path)}:{r.line}" for r in rules)
        for r in rules:
            if r.path in target_set:
                rep.error(r.path, f"sid {sid} is used more than once ({where})", r.line)

    if args.base and targets:
        check_changes(targets, parsed, args.base, rep, args.allow_vedas_sids, collect_base_sids(args.base))

    return rep.summary("suricata lint", len(targets))


if __name__ == "__main__":
    sys.exit(main())
