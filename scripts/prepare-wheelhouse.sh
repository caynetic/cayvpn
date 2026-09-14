#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

log() { printf '[cayvpn-wheelhouse] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
OUTPUT="${1:-${ROOT}/dist/wheelhouse}"
LOCK="${ROOT}/requirements.lock"

[[ -f "${LOCK}" ]] || die "requirements.lock is missing."
command -v python3 >/dev/null || die "python3 is required."
[[ ! -e "${OUTPUT}" ]] || die "The output directory already exists: ${OUTPUT}"
install -d -m 0755 "${OUTPUT}/amd64" "${OUTPUT}/arm64"
COMPLETE=0
cleanup_partial() {
  if [[ "${COMPLETE}" != "1" && -d "${OUTPUT}" ]]; then
    rm -rf -- "${OUTPUT}"
  fi
}
trap cleanup_partial EXIT

validate_wheelhouse() {
  local architecture="$1"
  python3 - "${LOCK}" "${OUTPUT}/${architecture}" <<'PY'
import re
import sys
import zipfile
from email.parser import Parser
from pathlib import Path

lock_path, wheelhouse_path = map(Path, sys.argv[1:])
normalize = lambda value: re.sub(r"[-_.]+", "-", value).lower()
locked = {}
for line in lock_path.read_text().splitlines():
    match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\s]+)", line.strip())
    if not match:
        raise SystemExit(f"requirements.lock contains an unsupported line: {line!r}")
    name = normalize(match.group(1))
    if name in locked:
        raise SystemExit(f"requirements.lock contains a duplicate package: {name}")
    locked[name] = match.group(2)

bundled = {}
for wheel in wheelhouse_path.glob("*.whl"):
    with zipfile.ZipFile(wheel) as archive:
        metadata_names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            raise SystemExit(f"{wheel.name} has invalid package metadata")
        metadata = Parser().parsestr(archive.read(metadata_names[0]).decode("utf-8", "strict"))
    name = normalize(metadata.get("Name", ""))
    version = metadata.get("Version", "")
    if not name or name in bundled:
        raise SystemExit(f"{wheel.name} is missing or duplicates package metadata")
    bundled[name] = version

if bundled != locked:
    raise SystemExit(
        "wheelhouse does not exactly match requirements.lock package names and versions"
    )
PY
}

download_for() {
  local architecture="$1" platform_arch="$2" glibc_minor
  local -a platform_args=()
  for glibc_minor in $(seq 39 -1 17); do
    platform_args+=(--platform "manylinux_2_${glibc_minor}_${platform_arch}")
  done
  platform_args+=(--platform "manylinux2014_${platform_arch}")
  log "Downloading the locked Python 3.12 wheels for ${architecture}."
  python3 -m pip download \
    --disable-pip-version-check \
    --only-binary=:all: \
    --implementation cp \
    --python-version 312 \
    --abi cp312 \
    "${platform_args[@]}" \
    --dest "${OUTPUT}/${architecture}" \
    --requirement "${LOCK}"
  find "${OUTPUT}/${architecture}" -type f ! -name '*.whl' -print -quit | grep -q . \
    && die "The ${architecture} wheelhouse contains a non-wheel dependency."
  [[ -n "$(find "${OUTPUT}/${architecture}" -type f -name '*.whl' -print -quit)" ]] \
    || die "The ${architecture} wheelhouse is empty."
  validate_wheelhouse "${architecture}"
}

download_for amd64 x86_64
download_for arm64 aarch64

(
  cd "${OUTPUT}"
  find . -type f -name '*.whl' -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
) > "${OUTPUT}/SHA256SUMS"
(cd "${OUTPUT}" && sha256sum --check --strict SHA256SUMS >/dev/null)
chmod -R a+rX,go-w "${OUTPUT}"
COMPLETE=1
log "Prepared both signed-release wheelhouses at ${OUTPUT}."
log "Transfer this directory to the offline release-signing environment."
