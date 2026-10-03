# Contributing to VEDAS Signatures

Thanks for helping make VEDAS detection content trustworthy. The most valuable contributions are usually not new signatures. They are **evidence**: a pcap that shows a false positive, a PoC request a rule misses, or a note that a rule has been confirmed in production.

- [Ground rules](#ground-rules)
- [Reporting problems](#reporting-problems)
- [Pull request workflow](#pull-request-workflow)
- [Suricata rules](#suricata-rules)
- [Nuclei templates](#nuclei-templates)
- [Validate locally](#validate-locally)
- [What CI checks](#what-ci-checks)
- [Review and merge](#review-and-merge)

## Ground rules

- **One CVE per file.** The file name is the CVE ID and it lives in the directory for the CVE's year.
- **Only published CVEs.** Reserved, rejected or made-up IDs are refused automatically.
- **Detection, not exploitation.** Nuclei templates must prove a target is vulnerable without changing state on it. No destructive payloads, no persistence, no data exfiltration, no reverse shells.
- **No sensitive data.** Strip real hostnames, IPs, credentials, cookies and customer data from pcaps, requests and logs before you attach them.
- **Use your own words and work.** Do not copy signatures from sources whose licence is incompatible with this repository's [LICENSE](LICENSE). If you adapt a public PoC, cite it in the `reference`.
- Be kind. This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting problems

Use the [issue forms](../../issues/new/choose). They ask for the details maintainers need:

| Issue | Use when |
| --- | --- |
| **False positive** | A rule or template fires on benign traffic or a non-vulnerable target. |
| **False negative** | A rule or template misses real exploitation or a vulnerable target. |
| **Broken signature** | A rule fails to load, triggers engine warnings, or is too slow. |
| **Signature request** | You want coverage for a CVE that has none. |

## Pull request workflow

1. Fork the repository and create a branch, e.g. `fix/CVE-2024-0012-fp` or `add/CVE-2025-1234-nuclei`.
2. Add or edit files under `suricata/` and/or `nuclei/`. Keep each PR to one CVE or one closely related change. That makes review faster.
3. [Validate locally](#validate-locally).
4. Open the PR and fill in the template. Say **how you tested** (pcap replay, lab target, production traffic) and include evidence where you can.
5. Fix anything CI flags. Errors appear as annotations on the changed lines.

Do **not** edit the coverage table in `README.md`. A bot updates it after merge.

## Suricata rules

### File format

`suricata/<YYYY>/CVE-YYYY-NNNNN.rules`, UTF-8, LF line endings, ending with a newline. One rule per line, no multi-line `\` continuations. A file may hold several rules for the same CVE (e.g. different exploitation paths). Lines starting with `#` are comments.

### Required options

Every rule must have:

| Option | Rule |
| --- | --- |
| action | `alert` only. Operators choose `drop`/`reject` themselves. |
| `msg` | Non-empty and descriptive: product, vulnerability class, "Attempt". |
| `sid` | Unique across the whole repository (see [SID ranges](#sid-ranges)). |
| `rev` | Starts at `1`. **Bump it every time you change an existing rule.** |
| `reference:cve,<CVE>` | Must match the file name. |

Strongly recommended (CI warns when they are missing):

- `flow:established,to_server;` (or the direction you need) on TCP-based protocols
- `classtype:` from `classification.config`, e.g. `web-application-attack`, `attempted-admin`
- at least one `content` match. pcre-only rules are slow.
- sticky buffers (`http.uri; content:"..."`) instead of legacy modifiers (`content:"..."; http_uri;`, `uricontent`)
- `reference:url,https://vedas.arpsyndicate.io/?vuln=<CVE>;`, plus advisory/PoC URLs
- `metadata:` such as `created_at`, `updated_at`, `confidence`, `signature_severity`

### SID ranges

| Range | Owner |
| --- | --- |
| `1000000`-`1999999` | VEDAS autonomous generation. Do not allocate new SIDs here. |
| `3000000`-`3999999` | **Community contributions** |

Get a free SID with:

```bash
python3 scripts/next_sid.py        # or -n 3 for three
```

Never reuse or renumber an existing SID. Modify the rule and bump `rev`. To retire a rule, delete it and explain why in the PR. If another PR merges first and takes your SID, CI will flag the collision; run `next_sid.py` again.

### Example

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Palo Alto PAN-OS Management Interface Auth Bypass Attempt (CVE-2024-0012)"; flow:established,to_server; http.uri; content:"/php/"; startswith; http.header; content:"X-PAN-AUTHCHECK|3a 20|off"; nocase; fast_pattern; classtype:web-application-attack; reference:cve,CVE-2024-0012; reference:url,https://vedas.arpsyndicate.io/?vuln=CVE-2024-0012; sid:3000000; rev:1;)
```

### Testing a rule against traffic

Syntax checks only prove that a rule loads. If you can, replay a pcap of the exploit (and of benign traffic) through it:

```bash
suricata -c /etc/suricata/suricata.yaml -S suricata/2024/CVE-2024-0012.rules -r exploit.pcap -l /tmp/out -k none
cat /tmp/out/fast.log
```

Attach redacted pcaps to the PR or issue when you can share them.

## Nuclei templates

### File format

`nuclei/<YYYY>/CVE-YYYY-NNNNN.yaml` (`.yaml`, not `.yml`), spaces only, LF line endings.

### Required fields

```yaml
id: CVE-2024-0012                     # must equal the file name

info:
  name: Palo Alto PAN-OS - Management Interface Authentication Bypass
  author: your-github-handle          # comma-separated for several authors
  severity: critical                  # info | low | medium | high | critical | unknown
  description: |
    One or two sentences on the vulnerability and what the template checks.
  reference:
    - https://vedas.arpsyndicate.io/?vuln=CVE-2024-0012
    - https://security.paloaltonetworks.com/CVE-2024-0012
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: 9.8
    cve-id: CVE-2024-0012             # must include the file's CVE
    cwe-id: CWE-306
  metadata:
    verified: false                   # true only if tested against a real vulnerable target
    max-request: 1
  tags: cve,cve2024,paloalto,panos,auth-bypass   # must include `cve` and `cve<YYYY>`

http:
  - method: GET
    path:
      - "{{BaseURL}}/php/ztp_gate.php/.js.map"
    headers:
      X-PAN-AUTHCHECK: "off"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "Zero Touch Provisioning"
      - type: status
        status:
          - 200
```

### Template rules

- **Accepted protocols:** `http`, `network`/`tcp`, `dns`, `ssl`, `websocket`, `whois`. `headless` and `javascript` are accepted but get extra review. Explain why `http`/`network` is not enough.
- **Not accepted:** `code` (runs commands on the scanner host), `file` (reads the scanner host), `workflows`, and `self-contained` requests.
- Every template needs matchers or extractors. A status-code-only matcher is a false-positive magnet, so combine it with a `word`/`regex` match on something specific to the vulnerable product.
- Prefer version-agnostic proof of the bug over banner/version matching. If you must match versions, use `dsl` comparisons and say so in the description.
- Payloads must be harmless: use unique random markers (`{{randstr}}`) and `{{interactsh-url}}` for out-of-band checks, and match on `interactsh_protocol`.
- Do not sign templates. Leave any `# digest:` line out.

## Validate locally

You need Python 3.10+ and, for engine checks, [Suricata](https://docs.suricata.io/en/latest/install.html) 8.x and/or [Nuclei](https://github.com/projectdiscovery/nuclei#install-nuclei) v3.

```bash
python3 -m pip install -r scripts/requirements.txt

# Suricata
python3 scripts/lint_suricata.py suricata/2024/CVE-2024-0012.rules
python3 scripts/validate_suricata_engine.py suricata/2024/CVE-2024-0012.rules

# Nuclei
python3 scripts/lint_nuclei.py nuclei/2024/CVE-2024-0012.yaml
python3 scripts/validate_nuclei_engine.py nuclei/2024/CVE-2024-0012.yaml

# Everything you changed relative to upstream main, exactly like CI
git fetch upstream main
python3 scripts/lint_suricata.py --base upstream/main
python3 scripts/lint_nuclei.py --base upstream/main
python3 scripts/check_cve.py --base upstream/main
```

With no arguments, each script checks the whole tree.

## What CI checks

| Workflow | Check | Fails on |
| --- | --- | --- |
| **Suricata** | `lint_suricata.py` | wrong path/name, missing `msg`/`sid`/`rev`/CVE reference, non-`alert` action, duplicate SID, modified rule without a `rev` bump, new SID outside the community range |
| | `validate_suricata_engine.py` | any rule the latest stable Suricata refuses to load |
| **Nuclei** | `lint_nuclei.py` | wrong path/name, `id` ≠ file name, missing `info` fields, missing `cve`/`cve<YYYY>` tags, forbidden protocols, no matchers |
| | `validate_nuclei_engine.py` | any template `nuclei -validate` rejects |
| **CVE check** | `check_cve.py` | CVE not found on cve.org, or REJECTED/RESERVED |

Warnings (e.g. missing `classtype`, legacy HTTP modifiers) do not block a merge, but reviewers may ask you to fix them in the lines you touch.

## Review and merge

- At least one maintainer review is required. Changes to `scripts/` and `.github/` need a maintainer from [CODEOWNERS](.github/CODEOWNERS).
- PRs are squash-merged. The coverage table in `README.md` is regenerated automatically afterwards.
- Maintainers label generator output `vedas-generated`. That label is the only way to add new SIDs in the VEDAS range.
- By contributing, you agree your contribution is licensed under this repository's [LICENSE](LICENSE).
