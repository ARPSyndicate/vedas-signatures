<!-- Thanks for contributing! Keep each PR to one CVE (or one closely related change). -->

## What does this PR do?

- [ ] Adds a new signature
- [ ] Fixes a false positive
- [ ] Fixes a false negative
- [ ] Fixes a broken / slow signature
- [ ] Tooling / docs

**CVE(s):** CVE-YYYY-NNNNN
**Related issue:** #

## Signature type

- [ ] Suricata rule
- [ ] Nuclei template

## How was it tested?

<!-- Syntax checks run in CI. Tell us how you checked the logic. -->

- [ ] pcap replay (`suricata -r`): exploit traffic alerts
- [ ] pcap replay: benign traffic does **not** alert
- [ ] Nuclei run against a vulnerable lab target
- [ ] Nuclei run against a patched / non-vulnerable target (no match)
- [ ] Observed in production traffic
- [ ] Not logically tested (syntax only)

<!-- Evidence: redacted output, eve.json alert, nuclei result, attached pcap, lab setup... -->

## Checklist

- [ ] File is `suricata/<YYYY>/CVE-….rules` or `nuclei/<YYYY>/CVE-….yaml`, named after the CVE
- [ ] Suricata: new rules use a SID from `scripts/next_sid.py`; modified rules have `rev` bumped
- [ ] Nuclei: detection only, no destructive or state-changing payloads
- [ ] No real hostnames, IPs, credentials or customer data
- [ ] I ran the [local validation](../CONTRIBUTING.md#validate-locally) and it passes
