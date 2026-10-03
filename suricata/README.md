# Suricata rules

One file per CVE, at `suricata/<YYYY>/CVE-YYYY-NNNNN.rules`, one rule per line.

| SID range | Source |
| --- | --- |
| `1000000`-`1999999` | VEDAS autonomous generation |
| `3000000`-`3999999` | Community contributions (`scripts/next_sid.py`) |

```bash
cat suricata/*/*.rules > vedas.rules
suricata -T -c /etc/suricata/suricata.yaml -S vedas.rules
```

See [CONTRIBUTING.md](../CONTRIBUTING.md#suricata-rules) for the rule format.
