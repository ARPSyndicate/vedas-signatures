"""Shared helpers for the vedas-signatures validation tooling.

Every check script reports through `Reporter`, which prints plain text locally
and GitHub Actions annotations when running in CI, so contributors see errors
inline on the pull request diff.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SURICATA_DIR = REPO_ROOT / "suricata"
NUCLEI_DIR = REPO_ROOT / "nuclei"

CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$")

# SID allocation. Keep in sync with CONTRIBUTING.md.
#   1000000-1999999  VEDAS autonomous generation (reserved for the generator)
#   3000000-3999999  community contributions
VEDAS_SID_RANGE = range(1_000_000, 2_000_000)
COMMUNITY_SID_RANGE = range(3_000_000, 4_000_000)

# Files allowed at the top level of a signature tree besides year directories.
TREE_DOCS = {"README.md"}

IN_CI = os.environ.get("GITHUB_ACTIONS") == "true"


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _escape_annotation(msg: str) -> str:
    return msg.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


@dataclass
class Reporter:
    errors: int = 0
    warnings: int = 0
    _seen: set = field(default_factory=set)

    def _emit(self, level: str, path: Path | str | None, line: int | None, msg: str) -> None:
        loc = rel(Path(path)) if path else None
        key = (level, loc, line, msg)
        if key in self._seen:
            return
        self._seen.add(key)
        if IN_CI:
            props = []
            if loc:
                props.append(f"file={loc}")
            if line:
                props.append(f"line={line}")
            print(f"::{level} {','.join(props)}::{_escape_annotation(msg)}")
        else:
            where = loc or "-"
            if line:
                where += f":{line}"
            print(f"{level.upper():7} {where}: {msg}")

    def error(self, path, msg: str, line: int | None = None) -> None:
        self.errors += 1
        self._emit("error", path, line, msg)

    def warning(self, path, msg: str, line: int | None = None) -> None:
        self.warnings += 1
        self._emit("warning", path, line, msg)

    def summary(self, label: str, checked: int) -> int:
        print(f"\n{label}: checked {checked} file(s), {self.errors} error(s), {self.warnings} warning(s)")
        return 1 if self.errors else 0


def check_layout(tree: Path, ext: str, rep: Reporter) -> list[Path]:
    """Validate `<tree>/<YYYY>/CVE-YYYY-NNNN<ext>` and return every signature file."""
    files: list[Path] = []
    if not tree.is_dir():
        return files
    for entry in sorted(tree.iterdir()):
        if entry.is_file():
            if entry.name not in TREE_DOCS:
                rep.error(entry, f"unexpected file; signatures belong in {rel(tree)}/<YYYY>/CVE-YYYY-NNNN{ext}")
            continue
        if not re.fullmatch(r"\d{4}", entry.name):
            rep.error(entry, f"unexpected directory; only CVE year directories are allowed in {rel(tree)}/")
            continue
        for f in sorted(entry.rglob("*")):
            if f.is_dir():
                rep.error(f, "nested directories are not allowed inside a year directory")
                continue
            if f.suffix != ext:
                rep.error(f, f"unexpected file type; expected CVE-YYYY-NNNN{ext}")
                continue
            m = CVE_RE.match(f.stem)
            if not m:
                rep.error(f, f"file name must be the CVE ID, e.g. CVE-2024-12345{ext}")
                continue
            if f.parent != entry:
                continue  # already reported as nested
            if m.group(1) != entry.name:
                rep.error(f, f"{f.stem} is in {entry.name}/; move it to {rel(tree)}/{m.group(1)}/")
            files.append(f)
    return files


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, check=True, capture_output=True, text=True
    ).stdout


def changed_files(base: str, tree: Path, ext: str) -> list[Path]:
    """Added/modified/renamed signature files under `tree` since the merge-base with `base`."""
    out = git("diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD", "--", rel(tree))
    return [REPO_ROOT / p for p in out.splitlines() if p.endswith(ext)]


def base_content(base: str, path: Path) -> str | None:
    """Content of `path` at the merge-base with `base`, or None if it did not exist."""
    mb = git("merge-base", base, "HEAD").strip()
    try:
        return git("show", f"{mb}:{rel(path)}")
    except subprocess.CalledProcessError:
        return None


def resolve_targets(paths: list[str], base: str | None, tree: Path, ext: str,
                    all_files: list[Path]) -> list[Path]:
    if paths:
        targets = []
        for p in paths:
            pp = Path(p)
            pp = pp if pp.is_absolute() else (Path.cwd() / pp)
            if pp.is_dir():
                targets.extend(sorted(pp.rglob(f"*{ext}")))
            elif pp.exists():
                targets.append(pp)
            else:
                print(f"warning: {p} does not exist, skipping", file=sys.stderr)
        return [t.resolve() for t in targets]
    if base:
        return [t.resolve() for t in changed_files(base, tree, ext) if t.exists()]
    return all_files
