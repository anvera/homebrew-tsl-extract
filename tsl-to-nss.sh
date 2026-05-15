#!/usr/bin/env bash
# tsl-to-nss.sh — Import TSL certificates into an NSS database.
#
# Usage: tsl-to-nss.sh <tsl-url> <nss-db-dir>
#
#   tsl-url     URL of a TSL XML file to download
#   nss-db-dir  Path to an NSS database directory (created if missing,
#               no password protection)
#
# Root (self-signed) certificates are imported with trust CT,CT,CT so they are
# treated as trusted CAs for TLS, S/MIME, and object signing.
# Non-root certificates are imported without trust flags (they are made
# available for chain building but are not explicitly trusted).
#
# Dependencies: curl, tsl-extract, certutil (from the nss package)

set -euo pipefail

usage() {
    echo "Usage: $(basename "$0") <tsl-url> <nss-db-dir>" >&2
    exit 1
}

die() { echo "Error: $*" >&2; exit 1; }

[[ $# -eq 2 ]] || usage
TSL_URL="$1"
DB_DIR="$2"

for cmd in curl tsl-extract certutil; do
    command -v "$cmd" &>/dev/null || die "'$cmd' is not installed or not in PATH"
done

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

tsl_file="$work_dir/tsl.xml"
root_dir="$work_dir/roots"
non_root_dir="$work_dir/non_roots"

echo "Downloading TSL from $TSL_URL ..."
curl -fsSL "$TSL_URL" -o "$tsl_file"

if [[ ! -f "$DB_DIR/cert9.db" && ! -f "$DB_DIR/cert8.db" ]]; then
    echo "Creating NSS database at $DB_DIR ..."
    mkdir -p "$DB_DIR"
    certutil -N -d "$DB_DIR" --empty-password
else
    echo "Using existing NSS database at $DB_DIR."
fi

echo "Extracting root certificates ..."
tsl-extract "$tsl_file" --root -f der -o "$root_dir" 2>&1 || true

if [[ -d "$root_dir" ]]; then
    for der_file in "$root_dir"/*.der; do
        [[ -e "$der_file" ]] || break
        nickname=$(basename "${der_file%.der}")
        echo "  [root] $nickname"
        certutil -A -d "$DB_DIR" -n "$nickname" -t "CT,CT,CT" -i "$der_file" \
            || echo "  Warning: could not add '$nickname' (skipping)" >&2
    done
fi

echo "Extracting non-root certificates ..."
tsl-extract "$tsl_file" --not-root -f der -o "$non_root_dir" 2>&1 || true

if [[ -d "$non_root_dir" ]]; then
    for der_file in "$non_root_dir"/*.der; do
        [[ -e "$der_file" ]] || break
        nickname=$(basename "${der_file%.der}")
        echo "  [non-root] $nickname"
        certutil -A -d "$DB_DIR" -n "$nickname" -t ",," -i "$der_file" \
            || echo "  Warning: could not add '$nickname' (skipping)" >&2
    done
fi

echo "Done."
