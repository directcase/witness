#!/usr/bin/env bash
# Capture a web page as evidence.
#
#   ./create.sh URL [--id NAME] [--expect TEXT ...] [--timestamp] [--eidas]
#   ./create.sh --urls urls.json [--timestamp] [--eidas]
#
# Output: captures/<domain>/<page or --id>/<UTC time>/{evidence.zip, report.pdf, ...}
#
#   --timestamp   OpenTimestamps proof of the evidence zip  -> evidence.zip.ots
#   --eidas       sign the capture report with your eID card -> report_signed.pdf
#                 (eidas/esign.py, PAdES-B-LT; one PIN entry for all reports;
#                  card settings in eidas/.env, see eidas/.env.example)
set -euo pipefail
source "$(dirname "$0")/witness/lib.sh"

[ $# -gt 0 ] || { sed -n '2,12p' "$0"; exit 1; }
eidas=0; urls=""; args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --eidas) eidas=1 ;;
    --urls)  urls="$(abspath "$2")"; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) args+=("$1") ;;
  esac
  shift
done

if [ "$eidas" = 1 ] && [ ! -x "$ESIGN_DIR/.venv/bin/python" ]; then
  echo "Setting up eIDAS signing in $ESIGN_DIR/.venv ..." >&2
  python3 -m venv "$ESIGN_DIR/.venv"
  "$ESIGN_DIR/.venv/bin/pip" install -q -r "$ESIGN_DIR/requirements.txt"
fi

marker="$(mktemp)"
if [ -n "$urls" ]; then
  run -v "$urls:/urls.json:ro" "$IMAGE" batch /urls.json ${args[@]+"${args[@]}"}
else
  run "$IMAGE" capture ${args[@]+"${args[@]}"} > /dev/null
fi

# Capture folders written by this run (each has a fresh report.pdf).
reports=()
while IFS= read -r f; do reports+=("$f"); done < <(find "$OUT" -name report.pdf -newer "$marker" | sort)
rm -f "$marker"
[ ${#reports[@]} -gt 0 ] || { echo "error: no capture was produced" >&2; exit 1; }

if [ "$eidas" = 1 ]; then
  echo "Signing ${#reports[@]} report(s) with the eID card..." >&2
  (cd "$ESIGN_DIR" && .venv/bin/python esign.py sign "${reports[@]}")   # -> report_signed.pdf
fi

echo
for r in "${reports[@]}"; do
  dir="$(dirname "$r")"
  echo "Created ${dir#"$HERE"/}/"
  for f in evidence.zip evidence.zip.ots report.pdf report_signed.pdf; do
    [ -e "$dir/$f" ] && echo "  $f"
  done
  echo "Verify:  ./verify.sh ${dir#"$HERE"/}"
done
