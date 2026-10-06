#!/usr/bin/env bash
# Validate the whole corpus inside the canonical upstream engine images, so results
# do not depend on a locally installed Suricata/Nuclei. Used locally and in CI.
#
#   scripts/validate_docker.sh                 # both engines, whole tree
#   scripts/validate_docker.sh suricata        # Suricata only
#   scripts/validate_docker.sh nuclei          # Nuclei only
#
# Override images/versions with env vars:
#   SURICATA_IMAGE=jasonish/suricata:8.0.7 NUCLEI_IMAGE=projectdiscovery/nuclei:v3.11.1
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SURICATA_IMAGE="${SURICATA_IMAGE:-jasonish/suricata:latest}"
NUCLEI_IMAGE="${NUCLEI_IMAGE:-projectdiscovery/nuclei:latest}"
WHAT="${1:-all}"
rc=0

run_suricata() {
  echo "== Suricata ($SURICATA_IMAGE) =="
  local tmp; tmp="$(mktemp)"
  find "$ROOT/suricata" -name '*.rules' -exec cat {} + > "$tmp"
  echo "rules: $(grep -cvE '^\s*(#|$)' "$tmp")"
  local log; log="$(mktemp)"
  # -T test-loads every rule; non-zero exit means at least one rule was rejected.
  if docker run --rm -v "$tmp":/vedas.rules:ro "$SURICATA_IMAGE" \
       -T -c /etc/suricata/suricata.yaml -S /vedas.rules -l /tmp >"$log" 2>&1; then
    grep -E 'successfully loaded' "$log" | tail -1
  else
    echo "FAILED: rules rejected by $SURICATA_IMAGE"
    grep -E '^E:' "$log" | head -40
    rc=1
  fi
  rm -f "$tmp" "$log"
}

run_nuclei() {
  echo "== Nuclei ($NUCLEI_IMAGE) =="
  local log; log="$(mktemp)"
  # Pass 1: structural validation.
  if docker run --rm -v "$ROOT/nuclei":/nuclei:ro --entrypoint nuclei "$NUCLEI_IMAGE" \
       -duc -nc -validate -t /nuclei >"$log" 2>&1; then
    grep -iE 'validated successfully' "$log" | tail -1 || echo "validated"
  else
    echo "FAILED: templates rejected by $NUCLEI_IMAGE (-validate)"
    grep -iE 'ERR|FTL|could not compile|does not exist' "$log" | head -40
    rc=1
  fi
  # Pass 2: compile pass -- forces request/payload compilation that -validate skips
  # (e.g. missing payload wordlists). Scans an unroutable dummy target; only
  # load/compile errors matter, connection failures are ignored.
  docker run --rm -v "$ROOT/nuclei":/nuclei:ro --entrypoint nuclei "$NUCLEI_IMAGE" \
       -duc -nc -no-interactsh -timeout 1 -retries 0 -u http://127.0.0.1:1 -t /nuclei >"$log" 2>&1 || true
  if grep -qiE 'error occurred (parsing|loading) template|could not compile|could not parse payloads|does not (exist|contain)' "$log"; then
    echo "FAILED: templates failed to compile in $NUCLEI_IMAGE (compile pass)"
    grep -iE 'error occurred (parsing|loading) template|could not compile|could not parse payloads|does not (exist|contain)' "$log" | head -40
    rc=1
  else
    echo "compile pass: OK"
  fi
  rm -f "$log"
}

if ! docker info >/dev/null 2>&1; then
  echo "docker daemon is not running" >&2
  exit 2
fi

case "$WHAT" in
  suricata) run_suricata ;;
  nuclei)   run_nuclei ;;
  all)      run_suricata; echo; run_nuclei ;;
  *) echo "usage: $0 [all|suricata|nuclei]" >&2; exit 2 ;;
esac

echo
[ "$rc" -eq 0 ] && echo "docker validation: OK" || echo "docker validation: FAILED"
exit "$rc"
