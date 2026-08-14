#!/bin/sh
set -eu

if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "refusing to package a dirty worktree" >&2
    exit 2
fi

output=${1:-dist/ContinuitySeal-0.1.0-public.zip}
case "$output" in
    /*|*..*) echo "output must be a relative path without '..'" >&2; exit 2 ;;
esac

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/continuityseal-source.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

build_zip() {
    destination=$1
    python3 - "$destination" <<'PY'
from pathlib import Path
import stat
import subprocess
import sys
import zipfile

destination = Path(sys.argv[1])
rows = subprocess.check_output(
    ["git", "ls-tree", "-rz", "HEAD"],
).split(b"\0")
with zipfile.ZipFile(
    destination,
    "w",
    compression=zipfile.ZIP_DEFLATED,
    compresslevel=9,
    strict_timestamps=True,
) as archive:
    for row in rows:
        if not row:
            continue
        metadata, raw_path = row.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split()
        if kind != "blob":
            raise SystemExit("source archive accepts regular blobs only")
        path = raw_path.decode("utf-8")
        payload = subprocess.check_output(["git", "cat-file", "blob", object_id])
        info = zipfile.ZipInfo(f"ContinuitySeal-0.1.0/{path}")
        info.date_time = (1980, 1, 1, 0, 0, 0)
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, payload, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
PY
}

build_zip "$work_dir/one.zip"
build_zip "$work_dir/two.zip"
cmp "$work_dir/one.zip" "$work_dir/two.zip"

mkdir -p "$(dirname "$output")"
cp "$work_dir/one.zip" "$output"
sha256sum "$output"
