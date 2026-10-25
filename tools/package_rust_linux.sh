#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || ( $# -eq 2 && $2 != --release ) ]]; then
    echo "usage: tools/package_rust_linux.sh FRESH_DESTINATION [--release]" >&2
    exit 2
fi

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
destination=$1
profile=debug
flags=()
if [[ ${2:-} == --release ]]; then
    profile=release
    flags+=(--release)
fi

cd "$repo"
cargo build --locked -p emumee-cli -p emumee-worker "${flags[@]}"
target=${CARGO_TARGET_DIR:-$repo/target}
[[ $target == /* ]] || target="$repo/$target"
library=$(find "$target/$profile/build" -path '*/out/lib/libunicorn.so.2' -type f -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)
if [[ -z $library ]]; then
    echo "built libunicorn.so.2 was not found" >&2
    exit 1
fi
mkdir "$destination"
destination=$(cd "$destination" && pwd)
chmod 700 "$destination"
cp "$target/$profile/emumee-rs" "$target/$profile/emumee-worker" "$destination/"
cp -L "$library" "$destination/libunicorn.so.2"

controller_info=$(LD_LIBRARY_PATH="$destination" "$destination/emumee-rs" build-info)
worker_info=$(LD_LIBRARY_PATH="$destination" "$destination/emumee-worker" --build-info)
python3 - "$destination" "$controller_info" "$worker_info" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
controller = json.loads(sys.argv[2])
worker = json.loads(sys.argv[3])
source_hash = controller["source_tree_sha256"]
if source_hash != worker["source_tree_sha256"]:
    raise SystemExit("controller and worker source fingerprints differ")

def digest(name):
    return hashlib.sha256((root / name).read_bytes()).hexdigest()

receipt = {
    "schema": 1,
    "source_tree_sha256": source_hash,
    "controller_sha256": digest("emumee-rs"),
    "worker_sha256": digest("emumee-worker"),
    "unicorn_sha256": digest("libunicorn.so.2"),
}
(root / "linux-worker-build.json").write_text(
    json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
)
print(f"Packaged Linux worker: {root}")
PY
