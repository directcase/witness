#!/usr/bin/env bash
# Verify a capture created by create.sh.
#
#   ./verify.sh captures/<domain>/<page>/<time> [--timestamp] [--eidas] [--online] [--json]
#   (the capture folder, or its evidence.zip)
#
# Always checked: every file hash in the zip, the TLSNotary receipt (signature
# against the notary's published key, key window, signed bytes = transcript,
# notary's own /verify), and that report.pdf names this zip.
# Checked when present next to the zip:
#   evidence.zip.ots    OpenTimestamps proof (retrieves the Bitcoin proof when ready)
#   report_signed.pdf   eIDAS / PAdES signature of the report
#
#   --timestamp   fail if there is no OpenTimestamps proof
#   --eidas       fail if there is no signed report
#   --online      also validate the eIDAS signature with the EU DSS service
#                 (uploads the signed report to the European Commission)
#   --json        full machine-readable report
set -euo pipefail
source "$(dirname "$0")/witness/lib.sh"

[ $# -gt 0 ] || { sed -n '2,19p' "$0"; exit 1; }
zip=""; flags=()
for a in "$@"; do
  case "$a" in
    --timestamp|--eidas|--online|--json) flags+=("$a") ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    *) zip="$a" ;;
  esac
done
[ -e "$zip" ] || { echo "error: no such capture: $zip" >&2; exit 2; }
run "$IMAGE" verify "$(in_container "$zip")" ${flags[@]+"${flags[@]}"}
