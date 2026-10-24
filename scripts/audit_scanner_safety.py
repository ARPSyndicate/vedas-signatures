#!/usr/bin/env python3
"""Audit Nuclei templates for SELF-COMPROMISE of the SCANNER/host that runs Nuclei.

Key principle: http/network/dns/ssl/whois templates only SEND bytes to the target, so a
scary-looking payload there (/etc/shadow, a reverse shell, curl|sh, 169.254.169.254) is a
TARGET-directed exploit and is harmless to the scanner. The scanner is only endangered by
blocks that EXECUTE LOCALLY: code / javascript / headless (and the already-blocked
`self-contained` / `file`). So dangerous patterns are HARD findings ONLY inside those blocks,
plus any local-exec block that contacts a HARD-CODED host that isn't the target or the OOB
server (possible exfiltration).

Exit 1 on any HARD finding. Usage: python3 scripts/audit_scanner_safety.py [paths...]"""
import re, sys, glob, os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NUCLEI = os.path.join(REPO, "nuclei")
LOCAL_EXEC = ("code", "javascript", "headless")

# HARD: no legitimate detection need; unambiguous harm to the scanner host.
DANGER_HARD = [
    (r"/dev/tcp/", "reverse shell via /dev/tcp"),
    (r"\bnc\b[^\n]{0,40}\s-e\b|\bncat\b[^\n]{0,40}-e\b", "netcat/ncat -e reverse shell"),
    (r"\bsocat\b[^\n]{0,60}exec", "socat exec shell"),
    (r"\b(ba)?sh\s+-i\b", "interactive shell spawn"),
    (r"rm\s+-rf\s+(/|~|\$HOME|\*)", "destructive rm on scanner fs"),
    (r"\bmkfs\b|\bdd\s+if=/dev", "disk-destroying command"),
    (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "fork bomb"),
    (r"(curl|wget)\b[^\n|]{0,120}\|\s*(ba)?sh", "curl|bash on scanner"),
    (r"\bid_rsa\b|/root/\.ssh|~/\.ssh|\$HOME/\.ssh", "reads scanner SSH keys"),
    (r"\.aws/credentials|AWS_SECRET_ACCESS_KEY", "reads scanner AWS creds"),
    (r"\.puncia\b", "reads the stored puncia key"),
    (r"\bos\.environ\b|process\.env\b|\bprintenv\b", "exfiltrates scanner environment"),
    (r"169\.254\.169\.254|metadata\.google\.internal", "scanner cloud-metadata access"),
]
# SOFT: expected inside a legitimate code: block (it runs a client against the target);
# surfaced for review, not a hard failure on its own.
DANGER_SOFT = [
    (r"\bfetch\(|\brequire\(['\"]child_process|\bos\.system\b|\bsubprocess\b|\bos/exec\b",
     "scanner-side process/network call — confirm it only contacts {{Host}}/{{interactsh-url}}"),
]
DANGER_HARD_RE = [(re.compile(p, re.I), d) for p, d in DANGER_HARD]
DANGER_SOFT_RE = [(re.compile(p, re.I), d) for p, d in DANGER_SOFT]
# hosts a local-exec block may legitimately reference
ALLOWED = ("{{host", "{{hostname", "{{baseurl", "{{rooturl", "{{interactsh", "{{fqdn",
           "{{ip", "{{port", "127.0.0.1", "localhost", "{{randstr", "{{rand")
HOSTLIKE = re.compile(r"https?://([a-z0-9.\-]+)|([a-z0-9\-]+\.[a-z]{2,}(?::\d+)?)", re.I)

def local_exec_blocks(txt):
    """Return concatenated text of code/javascript/headless blocks (crude but sufficient:
    from the block key to the next top-level key)."""
    out = []
    lines = txt.splitlines()
    cap = False
    for ln in lines:
        if re.match(rf"^({'|'.join(LOCAL_EXEC)}):", ln):
            cap = True; out.append(ln); continue
        if cap:
            if re.match(r"^\S", ln) and not ln.startswith(tuple(f"{p}:" for p in LOCAL_EXEC)):
                cap = False
            else:
                out.append(ln)
    return "\n".join(out)

def audit(path):
    txt = open(path, encoding="utf-8", errors="replace").read()
    has_local = bool(re.search(rf"^({'|'.join(LOCAL_EXEC)}):", txt, re.M))
    if not has_local:
        return [], [], False
    block = local_exec_blocks(txt)
    hard, soft = [], []
    for rx, desc in DANGER_HARD_RE:
        m = rx.search(block)
        if m:
            hard.append(f"{desc}  [{m.group(0)[:40]!r}]")
    for rx, desc in DANGER_SOFT_RE:
        m = rx.search(block)
        if m:
            soft.append(f"{desc}")
    low = block.lower()
    for m in HOSTLIKE.finditer(block):
        host = (m.group(0)).lower()
        if any(a in low[max(0, m.start()-12):m.end()+2] for a in ALLOWED):
            continue
        if any(a in host for a in ALLOWED):
            continue
        if "example" in host or "exploit.observer" in host or "subdomain.center" in host:
            continue
        hard.append(f"local-exec block contacts hard-coded host {m.group(0)!r} (not the target/OOB) — possible exfiltration")
        break
    return hard, soft, True

def main():
    paths = sys.argv[1:] or sorted(glob.glob(f"{NUCLEI}/*/*.yaml"))
    hard, soft, review = [], [], []
    for p in paths:
        h, s, has_local = audit(p)
        rp = os.path.relpath(p, REPO)
        if has_local:
            review.append(rp)
        hard += [(rp, d) for d in h]
        soft += [(rp, d) for d in s]
    print(f"audited {len(paths)} templates; {len(review)} contain local-exec (code/js/headless) blocks")
    for p in review:
        print(f"  [local-exec] {p}")
    if soft:
        print(f"\n[REVIEW] {len(soft)} local-exec blocks make process/network calls (expected for code:, confirm target-only):")
        for p, d in soft:
            print(f"  {p}: {d}")
    if hard:
        print(f"\n[HARD] {len(hard)} scanner self-compromise findings:")
        for p, d in hard:
            print(f"  {p}: {d}")
        print("\nRESULT: FAIL")
        sys.exit(1)
    print("RESULT: PASS — no scanner self-compromise")

if __name__ == "__main__":
    main()
