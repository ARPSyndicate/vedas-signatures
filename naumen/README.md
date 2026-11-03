# Naumen signatures

Standalone detection and vulnerability signatures for [Naumen](https://www.naumen.ru/)
products. Kept **outside** the `nuclei/<YYYY>/CVE-*.yaml` and `suricata/<YYYY>/` layout on
purpose: Naumen ships **no public CVEs** — advisories exist only in Russia's
**BDU FSTEC** database — so there is no CVE id to name files after.

## Why this folder exists

Puncia / Exploit Observer research on Naumen returns BDU-only entries, and
subdomain.center / Shodan / FOFA had no way to recognise a Naumen deployment in the first
place. These signatures close that gap: identify the product, read its version, and fire
only when that version falls in a BDU advisory's affected range.

## Contents

| File | Purpose |
| --- | --- |
| [`naumen-service-desk-detect.yaml`](naumen-service-desk-detect.yaml) | Nuclei: detect Naumen Service Desk / SMP and extract version + build |
| [`bdu/BDU-*.yaml`](bdu/) | Nuclei: one **version-gated** detection per BDU FSTEC advisory (see catalog) |

All advisories were enumerated recursively through Exploit Observer / puncia
(`puncia exploit naumen`, then `puncia enrich BDU:<id>` per identifier) — BDU FSTEC blocks
scripted access directly, so Exploit Observer is the pivot.

### BDU advisory catalog — every template is version-gated

Each template extracts the marketing version from the login-page `buildInfo.version` field
and fires only when `compare_versions(version, <gate>)` is true. An instance that exposes no
version field is never flagged (no false positives on hosts whose version can't be read).

| BDU | PT alias | Product | Affected | Type | Sev | Version gate |
| --- | --- | --- | --- | --- | --- | --- |
| [BDU:2026-00670](bdu/BDU-2026-00670.yaml) | — | Naumen Service Desk | 4.17.5.13 (build 1056) | Unauth RCE | critical | `<= 4.17.5.13` |
| [BDU:2026-08548](bdu/BDU-2026-08548.yaml) | — | Naumen SMP | ≤ 4.13 | Missing-auth RCE | critical | `< 4.14` |
| [BDU:2025-05680](bdu/BDU-2025-05680.yaml) | PT-2024-41364 | Naumen SMP | < 4.19.5 | RCE | critical | `< 4.19.5` |
| [BDU:2024-11090](bdu/BDU-2024-11090.yaml) | PT-2024-9398 | Naumen SMP | 4.15.5.24 | Credential disclosure | high | `<= 4.15.5.24` |
| [BDU:2026-03557](bdu/BDU-2026-03557.yaml) | PT-2026-48796 | Naumen SMP | < 4.19 | Web-interface XSS | medium | `< 4.19` |
| [BDU:2024-11085](bdu/BDU-2024-11085.yaml) | PT-2024-9393 | Naumen SMP | 4.15.5.24 | Stored XSS (Excel) | medium | `<= 4.15.5.24` |
| [BDU:2024-11089](bdu/BDU-2024-11089.yaml) | PT-2024-9397 | Naumen SMP Portal | < 3.12 | Stored XSS | medium | `< 4.19` (platform proxy) |
| [BDU:2025-12429](bdu/BDU-2025-12429.yaml) | — | NaumenKMS | 5.8.5 | Stored XSS | medium | `<= 5.8.5` (unverified fp) |
| [BDU:2025-12430](bdu/BDU-2025-12430.yaml) | — | NaumenKMS | 5.8.5 | pdf.js XSS | medium | `<= 5.8.5` (unverified fp) |

Notes on two entries:
- **SMP Portal (2024-11089)** has its own independent 3.x module version that is not exposed
  unauthenticated, so it is gated on the SMP **platform** version (`< 4.19`) as a proxy.
- **NaumenKMS (2025-12429/30)** is a separate product (5.x versioning) with no publicly
  verified web fingerprint; both templates are `verified: false` — confirm markers against a
  known instance before relying on them.

> **Run note — use `-dc -c 1`:** these templates gate with an internal extractor feeding
> `compare_versions`, and every one hits the same `/sd/` URL. nuclei's request *clustering*
> and its concurrent same-host request handling both drop gated results nondeterministically,
> so run the per-BDU set with `-dc -c 1` (disable clustering, one template at a time) for
> complete, repeatable output. Each template is also correct run on its own
> (`nuclei -t naumen/bdu/BDU-xxxx.yaml -u ...`). The single `naumen-service-desk-detect.yaml`
> is unaffected.

## HTTP fingerprint (Naumen Service Desk / SMP)

Reverse-engineered from live public instances (e.g. `servicedesk.eltex-co.ru/sd/`):

| Signal | Value |
| --- | --- |
| Web root | `/sd/` (Tomcat webapp `/opt/naumen/nausd4/tomcat/webapps/sd/`) |
| Title | `<title>Naumen Service Desk</title>` |
| Login assets | `/sd/js/login.js`, `/sd/login.css`, `/sd/themeSite.css`, `/sd/auth/css` |
| **Version object** | `var buildInfo = { "buildNumber": "<n>", "buildTime": "<n>", "version": "<4.x.x.x>" }` — the `version` field is the marketing version used for gating; current 4.19-era builds omit it and expose only `buildNumber` |
| **Version on assets** | `/sd/js/login.js?v=<buildNumber>` (`?v=` on every static asset) |
| Cookie | `JSESSIONID` (Java/Tomcat — corroborating only) |
| Favicon | `/sd/favicons/favicon.ico` → Shodan/FOFA mmh3 `453065545` (themeable, so treat as a hint) |

## Internet-wide discovery

- subdomain.center (ammonites): `?engine=ammonites&keyword=naumen&match=exact`
- FOFA: `title="Naumen Service Desk" || icon_hash="453065545"`
- Shodan: `http.favicon.hash:453065545` or `http.title:"Naumen Service Desk"`
- Censys: `services.http.response.html_title: "Naumen Service Desk"`

## Version, build number, and the build↔version timeline

The login page exposes both the marketing **version** (`buildInfo.version`) and an internal
**buildNumber**. Gating uses the version directly. The build number is kept as a secondary
signal and is useful when the `version` field is absent (current 4.19-era builds): build
numbers are monotonic, so the anchors below place an instance on the release timeline.

Build numbering was reset ~2019 to a small-integer scheme. Observed (version, build) anchors:

| Version | buildNumber | Source |
| --- | --- | --- |
| 4.0.1.18.5 | 4025 | sd.kari.com archive, 2013 (old scheme) |
| 4.4.1.2 | 5882 | support.naumen.ru archive, 2015 (old scheme) |
| 4.9.0.6 | 11051 | support.naumen.ru archive, 2018 (old scheme) |
| 4.9.0.18 | 533 | servicedesk.eltex-co.ru archive, 2020 (new scheme) |
| 4.10.0.15 | 692 | sd.kari.com archive, 2019 (new scheme) |
| **4.17.5.13** | **1056** | Exploit Observer product record (BDU:2026-00670) |
| 4.19-era (no `version` field) | 1318 / 1525 / 1758 | eltex / support.naumen.ru / itsm365, 2026 |

So on the new scheme a build ≤ 1056 ⇒ version ≤ 4.17.5.13, and the current public instances
(1318–1758) are the 4.19 line, consistent with the `version` field having been dropped there.

## Scope

Covers Naumen Service Desk (built on the SMP platform). Other Naumen products
(Contact Center / Phone, DMS, Network Manager) use different web roots and need their own
fingerprints via the same method.

## Usage

```bash
# product + version/build detection
nuclei -t naumen/naumen-service-desk-detect.yaml -u https://target.example

# version-gated BDU advisories (serialize for complete output)
nuclei -t naumen/bdu/ -u https://target.example -dc -c 1
```

`-dc -c 1` is required for the per-BDU version gating to report completely and repeatably;
see the run note above. Only scan systems you are authorised to test.
