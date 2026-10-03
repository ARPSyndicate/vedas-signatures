#!/usr/bin/env python3
"""Structural and policy lint for Nuclei templates under nuclei/.

Complements validate_nuclei_engine.py (`nuclei -validate`): the engine checks
that Nuclei can load a template, this script enforces repository conventions
and refuses templates that are unsafe to run from a public signature feed.

Usage:
  scripts/lint_nuclei.py                       # whole tree
  scripts/lint_nuclei.py nuclei/2024/CVE-2024-0012.yaml
  scripts/lint_nuclei.py --base origin/main    # files changed vs main
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vedas_common import NUCLEI_DIR, Reporter, check_layout, resolve_targets  # noqa: E402

SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
PROTOCOLS = {"http", "requests", "network", "tcp", "dns", "ssl", "websocket", "whois",
             "headless", "javascript", "code", "file", "flow", "workflows"}
# Protocols that execute arbitrary code or read the scanning host's filesystem.
FORBIDDEN_PROTOCOLS = {
    "code": "code protocol templates execute commands on the scanner host",
    "file": "file protocol templates read the scanner host's filesystem, not the target",
    "workflows": "workflows are not accepted; submit one template per CVE",
}
REVIEW_PROTOCOLS = {
    "javascript": "javascript templates run scripts on the scanner; explain why http/network is insufficient",
    "headless": "headless templates need a browser; prefer http where possible",
}


class UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys (PyYAML silently keeps the last one)."""


def _construct_mapping(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key '{key}'", key_node.start_mark)
        seen.add(key)
    return loader.construct_mapping(node, deep)


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, str):
        return [s.strip() for s in v.split(",") if s.strip()]
    return list(v) if isinstance(v, (list, tuple)) else [v]


def has_matcher_or_extractor(block) -> bool:
    if isinstance(block, dict):
        if block.get("matchers") or block.get("extractors"):
            return True
        return any(has_matcher_or_extractor(v) for v in block.values())
    if isinstance(block, list):
        return any(has_matcher_or_extractor(v) for v in block)
    return False


def lint_file(path: Path, rep: Reporter, errors_only: bool) -> None:
    data = path.read_bytes()
    w = (lambda msg, line=None: None) if errors_only else (lambda msg, line=None: rep.warning(path, msg, line))
    if b"\r" in data:
        rep.error(path, "CRLF line endings; use LF")
    if data and not data.endswith(b"\n"):
        rep.error(path, "file must end with a newline")
    if b"\t" in data:
        rep.error(path, "tab characters are not allowed in YAML; indent with spaces")
    try:
        doc = yaml.load(data.decode("utf-8"), Loader=UniqueKeyLoader)
    except UnicodeDecodeError:
        rep.error(path, "file is not valid UTF-8")
        return
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
        rep.error(path, f"invalid YAML: {getattr(exc, 'problem', None) or exc}",
                  mark.line + 1 if mark else None)
        return
    if not isinstance(doc, dict):
        rep.error(path, "template must be a YAML mapping")
        return

    cve = path.stem
    if doc.get("id") != cve:
        rep.error(path, f"id must be '{cve}' (the file name), got {doc.get('id')!r}")

    info = doc.get("info")
    if not isinstance(info, dict):
        rep.error(path, "missing info block")
        return
    for key in ("name", "author", "severity", "description"):
        if not info.get(key):
            rep.error(path, f"info.{key} is required")
    sev = str(info.get("severity", "")).lower()
    if sev and sev not in SEVERITIES:
        rep.error(path, f"info.severity must be one of {', '.join(sorted(SEVERITIES))}")

    cls = info.get("classification") or {}
    cve_ids = [str(c).upper() for c in as_list(cls.get("cve-id"))]
    if cve not in cve_ids:
        rep.error(path, f"info.classification.cve-id must include {cve}")
    for c in cve_ids:
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", c):
            rep.error(path, f"malformed cve-id {c!r}")

    tags = {t.lower() for t in as_list(info.get("tags"))}
    year = cve.split("-")[1]
    for t in ("cve", f"cve{year}"):
        if t not in tags:
            rep.error(path, f"info.tags must include '{t}'")

    refs = [str(r) for r in as_list(info.get("reference"))]
    if not refs:
        rep.error(path, "info.reference must list at least one advisory/source URL")
    if not any("vedas.arpsyndicate.io" in r for r in refs):
        w(f"no VEDAS reference; add https://vedas.arpsyndicate.io/?vuln={cve} to info.reference")
    if not cls.get("cvss-score") and not cls.get("cvss-metrics"):
        w("info.classification has no cvss-metrics/cvss-score")
    if "cwe-id" not in cls:
        w("info.classification has no cwe-id")

    protos = [k for k in doc if k in PROTOCOLS]
    if not protos:
        rep.error(path, f"no request block found (expected one of: {', '.join(sorted(PROTOCOLS - set(FORBIDDEN_PROTOCOLS)))})")
    for p in protos:
        if p in FORBIDDEN_PROTOCOLS:
            rep.error(path, f"'{p}:' is not accepted: {FORBIDDEN_PROTOCOLS[p]}")
        elif p in REVIEW_PROTOCOLS:
            w(f"'{p}:' needs extra maintainer review: {REVIEW_PROTOCOLS[p]}")
    if doc.get("self-contained") or any(isinstance(b, dict) and b.get("self-contained")
                                        for p in protos for b in as_list(doc.get(p))):
        rep.error(path, "self-contained requests are not accepted; templates must target the scanned host")

    request_blocks = {p: doc[p] for p in protos if p not in ("flow",)}
    if request_blocks and not has_matcher_or_extractor(request_blocks):
        rep.error(path, "template has no matchers or extractors and would report every target")

    text = data.decode("utf-8")
    if "interactsh-url" in text and "interactsh_protocol" not in text and "interactsh_request" not in text:
        w("uses {{interactsh-url}} but never matches on interactsh_protocol/interactsh_request")
    if re.search(r"(?m)^\s*-\s*type:\s*status\s*$", text) and len(re.findall(r"(?m)^\s*-\s*type:", text)) == 1:
        w("the only matcher is a status code; add a word/regex matcher to avoid false positives")

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--base", help="git ref to diff against; lints only changed files")
    ap.add_argument("--errors-only", action="store_true", help="suppress style warnings")
    args = ap.parse_args()

    rep = Reporter()
    all_files = check_layout(NUCLEI_DIR, ".yaml", rep)
    targets = resolve_targets(args.paths, args.base, NUCLEI_DIR, ".yaml", all_files)
    for f in targets:
        lint_file(f, rep, args.errors_only)
    return rep.summary("nuclei lint", len(targets))


if __name__ == "__main__":
    sys.exit(main())
