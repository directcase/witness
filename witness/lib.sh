# Shared by create.sh and verify.sh.
HERE="$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)"
OUT="${WITNESS_OUT:-$HERE/captures}"
IMAGE="${WITNESS_IMAGE:-witness}"
ESIGN_DIR="${ESIGN_DIR:-$HERE/eidas}"   # eIDAS signing (esign.py) lives in this repo
NOTARY="${WITNESS_NOTARY:-https://pavoltravnik.witness.directcase.ai}"
mkdir -p "$OUT"

# Build the image on first use.
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker build -t "$IMAGE" "$HERE/witness" >&2

run() { docker run --rm -v "$OUT:/out" -e WITNESS_NOTARY="$NOTARY" "$@"; }

abspath() { echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; }

in_container() {  # host path under $OUT -> /out/...
  local p; p="$(abspath "$1")"
  case "$p" in "$OUT"/*) echo "/out/${p#"$OUT"/}" ;; *) echo "error: $1 is not under $OUT" >&2; exit 2 ;; esac
}
