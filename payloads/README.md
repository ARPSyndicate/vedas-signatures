# Payloads

Self-hosted proof-of-concept payloads referenced by some Nuclei templates
(e.g. SVG-based XSS/SSRF checks). Templates fetch these over HTTP from this
repository's raw URL so the detection does not depend on any third-party host.

- `vedas-xss.svg` — a minimal SVG carrying a JavaScript payload, used by
  image-proxy / SSRF templates to confirm that a target renders attacker-supplied
  SVG content.

Only use these against systems you are authorised to test.
