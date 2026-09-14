#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
# macOS libarchive otherwise serializes Finder/provenance metadata as hidden
# AppleDouble entries (._*), which are not release source and must never enter
# the signed archive.
export COPYFILE_DISABLE=1

log() { printf '[cayvpn-release] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
VERSION="${1:-}"
SIGNING_KEY="${2:-}"
WHEELHOUSE="${3:-}"
OUTPUT_DIR="${4:-${ROOT}/dist}"
METADATA_FILE="${5:-}"
COMPONENT_BUNDLE="${CAYVPN_COMPONENT_BUNDLE:-}"
MINIMUM_VERSION="${CAYVPN_MINIMUM_VERSION:-2.0.0-dev}"
RELEASE_PYTHON="${CAYVPN_RELEASE_PYTHON:-python3.12}"

[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]   || die "Usage: $0 <stable-version> <offline-ed25519-private-key> <prepared-wheelhouse> [output-directory] [impact-metadata.json]"
[[ "${MINIMUM_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]   || die "CAYVPN_MINIMUM_VERSION is not a semantic version."
[[ -f "${SIGNING_KEY}" ]] || die "The Ed25519 signing key was not found."
[[ -d "${WHEELHOUSE}/amd64" && -d "${WHEELHOUSE}/arm64" ]]   || die "Prepare and transfer both architecture wheelhouses before signing."
[[ -d "${COMPONENT_BUNDLE}" ]]   || die "Set CAYVPN_COMPONENT_BUNDLE to the prepared amd64 and arm64 optional-component bundle."
[[ -z "${METADATA_FILE}" || -f "${METADATA_FILE}" ]]   || die "The optional release impact metadata file was not found."

for command in realpath git openssl sha256sum tar gzip shellcheck node; do
  command -v "${command}" >/dev/null || die "${command} is required."
done
command -v "${RELEASE_PYTHON}" >/dev/null   || die "Python 3.12 is required for release signing."
"${RELEASE_PYTHON}" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)'   || die "CAYVPN_RELEASE_PYTHON must resolve to Python 3.12."

SIGNING_KEY="$(realpath -- "${SIGNING_KEY}")"
case "${SIGNING_KEY}" in
  "${ROOT}"/*) die "Keep the release signing key outside the repository." ;;
esac
KEY_MODE="$(stat -c '%a' "${SIGNING_KEY}" 2>/dev/null || stat -f '%Lp' "${SIGNING_KEY}")"
(( (8#${KEY_MODE} & 8#077) == 0 ))   || die "The offline signing key must not be readable by group or other users."
openssl pkey -in "${SIGNING_KEY}" -check -noout >/dev/null   || die "The release signing key could not be validated."
openssl pkey -in "${SIGNING_KEY}" -text -noout 2>/dev/null | grep -qi 'ED25519'   || die "The release signing key must be Ed25519."

GIT_STATUS="$(git -C "${ROOT}" status --porcelain)"   || die "Unable to verify release worktree status."
[[ -z "${GIT_STATUS}" ]]   || die "Build releases only from a clean committed worktree."
if git -C "${ROOT}" ls-files -s | grep -q '^120000 '; then
  die "Release source must not contain tracked symbolic links."
fi

ARTIFACT_LOCK="${ROOT}/release-locks/${VERSION}.json"
[[ -f "${ARTIFACT_LOCK}" ]]   || die "A reviewed release lock is required at release-locks/${VERSION}.json."
git -C "${ROOT}" ls-files --error-unmatch "release-locks/${VERSION}.json" >/dev/null 2>&1   || die "The reviewed release artifact lock must be committed before offline signing."

# These adjacent checksums detect transfer damage. They are deliberately not
# the signing authority; the committed release lock below is independent.
[[ -f "${WHEELHOUSE}/SHA256SUMS" ]]   || die "The transferred wheelhouse is missing SHA256SUMS."
(cd "${WHEELHOUSE}" && sha256sum --check --strict SHA256SUMS >/dev/null)   || die "The transferred wheelhouse failed its transport checksum verification."
[[ -f "${COMPONENT_BUNDLE}/SHA256SUMS" ]]   || die "The transferred optional-component bundle is missing SHA256SUMS."
(cd "${COMPONENT_BUNDLE}" && sha256sum --check --strict SHA256SUMS >/dev/null)   || die "The transferred optional-component bundle failed its transport checksum verification."

WORK_DIR="$(mktemp -d)"
trap 'rm -rf -- "${WORK_DIR}"' EXIT
FOLDER="cayvpn-${VERSION}"
STAGED_ASSETS="${WORK_DIR}/release-assets"
FINAL_ASSETS="${OUTPUT_DIR}/${FOLDER}-release"
COMPONENT_LOCK="${WORK_DIR}/components.lock.json"
[[ ! -e "${FINAL_ASSETS}" ]]   || die "Refusing to mix a new build with existing assets at ${FINAL_ASSETS}."
install -d -m 0755 "${STAGED_ASSETS}"

"${RELEASE_PYTHON}" "${ROOT}/scripts/validate-release-artifacts.py"   --lock "${ARTIFACT_LOCK}"   --requirements "${ROOT}/requirements.lock"   --wheelhouse "${WHEELHOUSE}"   --components "${COMPONENT_BUNDLE}"   --release-version "${VERSION}"   --write-component-lock "${COMPONENT_LOCK}"   || die "Transferred release dependencies do not match the committed reviewed lock."

"${ROOT}/scripts/release-preflight.sh" "${WHEELHOUSE}"   || die "The canonical release preflight failed."

openssl pkey -in "${SIGNING_KEY}" -pubout -out "${WORK_DIR}/cayvpn-release.pub"
KEY_FINGERPRINT="$(sha256sum "${WORK_DIR}/cayvpn-release.pub" | awk '{print $1}')"
BOOTSTRAP_VERSION="$(awk -F'"' '/^VERSION="/ {print $2; exit}' "${ROOT}/bootstrap.sh")"
PINNED_FINGERPRINT="$(awk -F'"' '/^PINNED_RELEASE_KEY_SHA256="/ {print $2; exit}' "${ROOT}/bootstrap.sh")"
[[ "${BOOTSTRAP_VERSION}" == "${VERSION}" ]]   || die "Set VERSION in bootstrap.sh to ${VERSION}, commit that change, then build again."
[[ "${PINNED_FINGERPRINT,,}" == "${KEY_FINGERPRINT}" ]]   || die "Set PINNED_RELEASE_KEY_SHA256 in bootstrap.sh to ${KEY_FINGERPRINT}, commit that change, then build again."

git -C "${ROOT}" archive --format=tar --prefix="${FOLDER}/" HEAD > "${WORK_DIR}/source.tar"
tar -xf "${WORK_DIR}/source.tar" -C "${WORK_DIR}"
"${RELEASE_PYTHON}" "${ROOT}/scripts/validate-python-source.py" "${WORK_DIR}/${FOLDER}"   || die "The committed release contains malformed Python source."

install -d -m 0755   "${WORK_DIR}/${FOLDER}/wheelhouse/amd64"   "${WORK_DIR}/${FOLDER}/wheelhouse/arm64"   "${WORK_DIR}/${FOLDER}/components"
cp -- "${WHEELHOUSE}/amd64/"*.whl "${WORK_DIR}/${FOLDER}/wheelhouse/amd64/"
cp -- "${WHEELHOUSE}/arm64/"*.whl "${WORK_DIR}/${FOLDER}/wheelhouse/arm64/"
cp -a -- "${COMPONENT_BUNDLE}/." "${WORK_DIR}/${FOLDER}/components/"
install -m 0644 -- "${COMPONENT_LOCK}" "${WORK_DIR}/${FOLDER}/components.lock.json"

cat > "${WORK_DIR}/${FOLDER}/release.json" <<EOF
{
  "schema_version": 1,
  "version": "${VERSION}",
  "channel": "stable",
  "supported_os": ["ubuntu-24.04"],
  "supported_architectures": ["amd64", "arm64"],
  "minimum_cayvpn_version": "${MINIMUM_VERSION}",
  "offline_dependencies": true,
  "offline_optional_components": true,
  "summary": "",
  "migration_notes": "",
  "component_changes": [],
  "compatibility_notes": [],
  "expected_interruption_seconds": 0,
  "requires_reboot": false,
  "security_fixes": false
}
EOF

"${RELEASE_PYTHON}" - "${WORK_DIR}/${FOLDER}/release.json" "${METADATA_FILE}" "${VERSION}" <<'PY'
import json
import pathlib
import sys

release_path = pathlib.Path(sys.argv[1])
metadata_path = sys.argv[2]
version = sys.argv[3]
release = json.loads(release_path.read_text())
if metadata_path:
    supplied = json.loads(pathlib.Path(metadata_path).read_text())
    allowed = {
        "summary",
        "migration_notes",
        "component_changes",
        "compatibility_notes",
        "expected_interruption_seconds",
        "requires_reboot",
        "security_fixes",
    }
    if not isinstance(supplied, dict) or set(supplied) - allowed:
        raise SystemExit("release impact metadata may contain only the documented optional fields")
    release.update(supplied)

summary = release.get("summary", "")
migration_notes = release.get("migration_notes", "")
component_changes = release.get("component_changes", [])
compatibility_notes = release.get("compatibility_notes", [])
interruption = release.get("expected_interruption_seconds", 0)
if (
    not isinstance(summary, str)
    or len(summary) > 500
    or not isinstance(migration_notes, str)
    or len(migration_notes) > 2000
    or not isinstance(component_changes, list)
    or len(component_changes) > 20
    or not all(isinstance(item, str) and len(item) <= 240 for item in component_changes)
    or not isinstance(compatibility_notes, list)
    or len(compatibility_notes) > 20
    or not all(isinstance(item, str) and len(item) <= 240 for item in compatibility_notes)
    or type(interruption) is not int
    or not 0 <= interruption <= 3600
    or type(release.get("requires_reboot", False)) is not bool
    or type(release.get("security_fixes", False)) is not bool
):
    raise SystemExit(f"invalid release impact metadata for CayVPN {version}")

release_path.write_text(json.dumps(release, indent=2, sort_keys=True) + "\n")
PY

ARCHIVE="${STAGED_ASSETS}/${FOLDER}.tar.gz"
MANIFEST="${STAGED_ASSETS}/${FOLDER}.sha256"
SIGNATURE="${MANIFEST}.sig"
PUBLIC_KEY="${STAGED_ASSETS}/cayvpn-release.pub"

(
  cd "${WORK_DIR}/${FOLDER}"
  while IFS= read -r -d '' file; do
    sha256sum "${file#./}"
  done < <(find . -type f -print0 | LC_ALL=C sort -z)
) > "${MANIFEST}"
tar --no-xattrs -C "${WORK_DIR}" -cf "${WORK_DIR}/source-with-wheels.tar" "${FOLDER}"
gzip -n -c "${WORK_DIR}/source-with-wheels.tar" > "${ARCHIVE}"
openssl pkeyutl -sign -rawin -inkey "${SIGNING_KEY}" -in "${MANIFEST}" -out "${SIGNATURE}"
cp -- "${WORK_DIR}/cayvpn-release.pub" "${PUBLIC_KEY}"
chmod 0644 "${ARCHIVE}" "${MANIFEST}" "${SIGNATURE}" "${PUBLIC_KEY}"

openssl pkeyutl -verify -rawin -pubin -inkey "${PUBLIC_KEY}"   -sigfile "${SIGNATURE}" -in "${MANIFEST}" >/dev/null   || die "The staged release signature did not verify."

"${RELEASE_PYTHON}" - "${ARCHIVE}" "${MANIFEST}" "${FOLDER}" <<'PY'
import hashlib
import re
import sys
import tarfile
from pathlib import PurePosixPath

archive_path, manifest_path, folder = sys.argv[1:]
pattern = re.compile(r"^([0-9a-f]{64})[ \t]+\*?([A-Za-z0-9._/-]+)$")
manifest = {}
for line in open(manifest_path, encoding="utf-8"):
    match = pattern.fullmatch(line.rstrip("\n"))
    if not match:
        raise SystemExit("The staged release manifest has an unsafe entry")
    name = match.group(2).removeprefix("./")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or name in manifest:
        raise SystemExit("The staged release manifest has an unsafe or duplicate path")
    manifest[name] = match.group(1)

observed = {}
expanded = 0
with tarfile.open(archive_path, "r:gz") as archive:
    for member in archive:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != folder:
            raise SystemExit("The staged release archive contains an unsafe path")
        if not (member.isdir() or member.isfile()):
            raise SystemExit("The staged release archive contains a link or special file")
        if not member.isfile():
            continue
        relative = PurePosixPath(*path.parts[1:]).as_posix()
        if relative in observed:
            raise SystemExit("The staged release archive contains a duplicate file")
        expanded += member.size
        if expanded > 512 * 1024 * 1024:
            raise SystemExit("The staged release archive exceeds the safe expanded size")
        source = archive.extractfile(member)
        if source is None:
            raise SystemExit("The staged release archive file could not be read")
        digest = hashlib.sha256()
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
        observed[relative] = digest.hexdigest()
if observed != manifest:
    raise SystemExit("The staged release archive does not exactly match its signed manifest")
PY

[[ "$(sha256sum "${PUBLIC_KEY}" | awk '{print $1}')" == "${KEY_FINGERPRINT}" ]]   || die "The staged release public key fingerprint changed."

install -d -m 0755 "${OUTPUT_DIR}"
mv -- "${STAGED_ASSETS}" "${FINAL_ASSETS}"

log "Created one atomic directory containing the four signed release assets:"
log "  ${FINAL_ASSETS}"
log "Release key SHA-256: ${KEY_FINGERPRINT}"
log "Upload all four files from that directory to draft GitHub release v${VERSION}, then publish it as immutable."
