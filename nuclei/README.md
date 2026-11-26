# Nuclei templates

One template per CVE, at `nuclei/<YYYY>/CVE-YYYY-NNNNN.yaml`.

Templates here are **detection only**: they confirm exposure without changing state on the target. See [CONTRIBUTING.md](../CONTRIBUTING.md#nuclei-templates) for the required fields, accepted protocols and an example.

```bash
nuclei -t nuclei/ -u https://target.example   # only against systems you are authorised to test
```
