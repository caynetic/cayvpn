#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

log() { printf '[cayvpn] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

[[ "${EUID}" -eq 0 ]] || die "Run this command with sudo."

VERSION="2.0.0"
REPOSITORY="caynetic/cayvpn"
TAG="v${VERSION}"
BASE_URL="https://github.com/${REPOSITORY}/releases/download/${TAG}"
RELEASE_API_URL="https://api.github.com/repos/${REPOSITORY}/releases/tags/${TAG}"
ARCHIVE_NAME="cayvpn-${VERSION}.tar.gz"
MANIFEST_NAME="cayvpn-${VERSION}.sha256"
SIGNATURE_NAME="${MANIFEST_NAME}.sig"
PUBLIC_KEY_NAME="cayvpn-release.pub"
PINNED_RELEASE_KEY_SHA256="71b9f699c59c62410c76b8c2241251ffdea000412a3988c6a2f29a1ec14381c2"

[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "The pinned CayVPN release version is invalid."
[[ "${REPOSITORY}" == "caynetic/cayvpn" ]] || die "The pinned CayVPN release repository is invalid."

if [[ ! -r /etc/os-release ]]; then
  die "CayVPN requires Ubuntu 24.04."
fi
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]] || die "CayVPN requires Ubuntu 24.04."

case "$(dpkg --print-architecture)" in
  amd64|arm64) ;;
  *) die "CayVPN supports x86_64 and ARM64 VPSs only." ;;
esac

missing=()
for command in update-ca-certificates curl openssl sha256sum tar python3; do
  command -v "${command}" >/dev/null 2>&1 || missing+=("${command}")
done
if (( ${#missing[@]} )); then
  log "Installing the small set of tools needed to verify the CayVPN release."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends ca-certificates curl openssl coreutils tar python3-minimal
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf -- "${WORK_DIR}"' EXIT

log "Confirming that ${TAG} is a published immutable CayVPN release."
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --noproxy '*' \
  --connect-timeout 15 --max-time 60 --max-filesize 2097152 \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2026-03-10' \
  "${RELEASE_API_URL}" -o "${WORK_DIR}/release.json"
python3 - "${WORK_DIR}/release.json" "${REPOSITORY}" "${TAG}" "${ARCHIVE_NAME}" "${MANIFEST_NAME}" "${SIGNATURE_NAME}" "${PUBLIC_KEY_NAME}" <<'PY'
import json
import re
import sys
from pathlib import Path

metadata_path, repository, tag, *required_names = sys.argv[1:]
try:
    release = json.loads(Path(metadata_path).read_text())
except (OSError, ValueError, TypeError) as exc:
    raise SystemExit("GitHub returned invalid release metadata") from exc
if not isinstance(release, dict):
    raise SystemExit("GitHub returned invalid release metadata")
expected_page = f"https://github.com/{repository}/releases/tag/{tag}"
if (
    release.get("tag_name") != tag
    or release.get("html_url") != expected_page
    or release.get("draft") is not False
    or release.get("prerelease") is not False
    or release.get("immutable") is not True
):
    raise SystemExit("The requested CayVPN release is not published and immutable")
assets = {}
for raw in release.get("assets") or []:
    if not isinstance(raw, dict) or raw.get("name") not in required_names:
        continue
    name = raw["name"]
    expected_url = f"https://github.com/{repository}/releases/download/{tag}/{name}"
    size = raw.get("size")
    digest = raw.get("digest")
    if (
        name in assets
        or raw.get("state") != "uploaded"
        or raw.get("browser_download_url") != expected_url
        or not isinstance(size, int)
        or not 0 < size <= 512 * 1024 * 1024
        or (digest is not None and re.fullmatch(r"sha256:[0-9a-fA-F]{64}", str(digest)) is None)
    ):
        raise SystemExit("The CayVPN release contains invalid required assets")
    assets[name] = raw
if set(assets) != set(required_names):
    raise SystemExit("The CayVPN release is missing one or more required signed assets")
PY

download() {
  local name="$1"
  log "Downloading ${name}"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --noproxy '*' \
    --connect-timeout 15 --max-time 900 --max-filesize 536870912 \
    "${BASE_URL}/${name}" -o "${WORK_DIR}/${name}"
}

download "${ARCHIVE_NAME}"
download "${MANIFEST_NAME}"
download "${SIGNATURE_NAME}"
download "${PUBLIC_KEY_NAME}"

python3 - "${WORK_DIR}/release.json" "${WORK_DIR}" "${ARCHIVE_NAME}" "${MANIFEST_NAME}" "${SIGNATURE_NAME}" "${PUBLIC_KEY_NAME}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

metadata_path, work_path, *required_names = sys.argv[1:]
release = json.loads(Path(metadata_path).read_text())
assets = {item.get("name"): item for item in release.get("assets") or [] if isinstance(item, dict)}
work = Path(work_path)
for name in required_names:
    asset = assets[name]
    path = work / name
    if not path.is_file() or path.stat().st_size != asset["size"]:
        raise SystemExit(f"The downloaded release asset size did not match GitHub metadata: {name}")
    published = asset.get("digest")
    if published:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        observed = digest.hexdigest()
        if observed.lower() != published.split(":", 1)[1].lower():
            raise SystemExit(f"The downloaded release asset digest did not match GitHub metadata: {name}")
PY

EXPECTED_RELEASE_KEY_SHA256="${PINNED_RELEASE_KEY_SHA256}"
[[ "${EXPECTED_RELEASE_KEY_SHA256}" =~ ^[0-9a-fA-F]{64}$ ]] \
  || die "The CayVPN release signing key fingerprint has not been pinned for this release."
printf '%s  %s\n' "${EXPECTED_RELEASE_KEY_SHA256}" "${WORK_DIR}/${PUBLIC_KEY_NAME}" | sha256sum --check --status \
  || die "The CayVPN release signing key fingerprint did not match."

openssl pkeyutl -verify -rawin -pubin \
  -inkey "${WORK_DIR}/${PUBLIC_KEY_NAME}" \
  -sigfile "${WORK_DIR}/${SIGNATURE_NAME}" \
  -in "${WORK_DIR}/${MANIFEST_NAME}" >/dev/null \
  || die "The CayVPN release signature is invalid."

python3 - "${WORK_DIR}/${ARCHIVE_NAME}" "${WORK_DIR}/${MANIFEST_NAME}" "${WORK_DIR}" "${VERSION}" <<'PY'
import hashlib
import os
import re
import sys
import tarfile
from pathlib import Path, PurePosixPath

archive_path, manifest_path, destination_path, version = sys.argv[1:]
root_name = f"cayvpn-{version}"
line_pattern = re.compile(r"^([0-9a-fA-F]{64})[ \t]+\*?([A-Za-z0-9._/-]+)$")

def safe_relative(raw):
    path = PurePosixPath(raw)
    parts = raw.split("/")
    if not raw or raw.startswith("/") or path.is_absolute() or any(part in {"", ".", ".."} for part in parts):
        raise SystemExit("The release contains an unsafe path")
    return path

manifest = {}
try:
    lines = Path(manifest_path).read_text(encoding="utf-8").splitlines()
except (OSError, UnicodeError) as exc:
    raise SystemExit("The release manifest is invalid") from exc
for line in lines:
    match = line_pattern.fullmatch(line)
    if not match:
        raise SystemExit("The release manifest contains an invalid entry")
    name = str(safe_relative(match.group(2)))
    if name in manifest:
        raise SystemExit("The release manifest contains a duplicate entry")
    manifest[name] = match.group(1).lower()
if not manifest or len(manifest) > 20_000:
    raise SystemExit("The release manifest has an invalid number of entries")

destination = Path(destination_path)
release_root = destination / root_name
files = {}
seen = set()
expanded_bytes = 0
try:
    archive = tarfile.open(archive_path, "r:gz")
except (OSError, tarfile.TarError) as exc:
    raise SystemExit("The release archive is invalid") from exc
with archive:
    members = archive.getmembers()
    if len(members) > 40_000:
        raise SystemExit("The release archive contains too many entries")
    for member in members:
        raw = member.name.rstrip("/")
        path = PurePosixPath(raw)
        if not raw or path.is_absolute() or not path.parts or path.parts[0] != root_name or any(part in {"", ".", ".."} for part in raw.split("/")):
            raise SystemExit("The release archive contains an unsafe path")
        if raw in seen:
            raise SystemExit("The release archive contains a duplicate entry")
        seen.add(raw)
        if not (member.isdir() or member.isfile()):
            raise SystemExit("The release archive contains a link or unsupported file type")
        if member.isfile():
            relative = str(PurePosixPath(*path.parts[1:]))
            safe_relative(relative)
            expanded_bytes += member.size
            if member.size < 0 or expanded_bytes > 512 * 1024 * 1024 or relative in files:
                raise SystemExit("The expanded release archive is invalid or too large")
            files[relative] = member
    if set(files) != set(manifest):
        raise SystemExit("The release archive contains missing or unlisted files")
    release_root.mkdir(mode=0o700)
    for name in sorted(files):
        member = files[name]
        target = release_root.joinpath(*PurePosixPath(name).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        source = archive.extractfile(member)
        if source is None:
            raise SystemExit("A release file could not be read")
        digest = hashlib.sha256()
        written = 0
        with target.open("xb") as output:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                written += len(chunk)
                if written > member.size:
                    raise SystemExit("A release file exceeded its declared size")
                output.write(chunk)
                digest.update(chunk)
        if written != member.size or digest.hexdigest() != manifest[name]:
            raise SystemExit(f"The signed checksum failed for {name}")
        os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
    os.chmod(release_root, 0o755)
PY

SOURCE_DIR="${WORK_DIR}/cayvpn-${VERSION}"
[[ -f "${SOURCE_DIR}/install.sh" && -f "${SOURCE_DIR}/requirements.txt" ]] || die "The release archive has an unexpected layout."

log "Release ${VERSION} is signed and verified. Starting the guided installer."
CAYVPN_RELEASE_VERSION="${VERSION}" \
CAYVPN_RELEASE_MANIFEST="${WORK_DIR}/${MANIFEST_NAME}" \
CAYVPN_RELEASE_SIGNATURE="${WORK_DIR}/${SIGNATURE_NAME}" \
CAYVPN_RELEASE_PUBLIC_KEY="${WORK_DIR}/${PUBLIC_KEY_NAME}" \
CAYVPN_RELEASE_CONTENT_DIR="${SOURCE_DIR}" \
CAYVPN_RELEASE_DIGEST="$(sha256sum "${WORK_DIR}/${MANIFEST_NAME}" | awk '{print $1}')" \
  "${SOURCE_DIR}/install.sh"
