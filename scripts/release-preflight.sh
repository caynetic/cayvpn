#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

log() { printf '[cayvpn-preflight] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
WHEELHOUSE="${1:-}"
RELEASE_PYTHON="${CAYVPN_RELEASE_PYTHON:-python3.12}"

[[ -d "${WHEELHOUSE}" ]] || die "Usage: $0 <reviewed-wheelhouse>"
command -v "${RELEASE_PYTHON}" >/dev/null   || die "Python 3.12 is required for the canonical release preflight."
"${RELEASE_PYTHON}" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)'   || die "CAYVPN_RELEASE_PYTHON must resolve to Python 3.12."
command -v git >/dev/null || die "git is required."
command -v shellcheck >/dev/null || die "ShellCheck is required."
command -v node >/dev/null || die "Node.js is required for JavaScript syntax validation."
GIT_STATUS="$(git -C "${ROOT}" status --porcelain)"   || die "Unable to verify release worktree status."
[[ -z "${GIT_STATUS}" ]]   || die "Release preflight requires a clean committed worktree."

case "$(uname -m)" in
  x86_64) ARCHITECTURE="amd64" ;;
  arm64|aarch64) ARCHITECTURE="arm64" ;;
  *) die "Release preflight supports amd64 and arm64 builders only." ;;
esac
[[ -d "${WHEELHOUSE}/${ARCHITECTURE}" ]]   || die "The reviewed ${ARCHITECTURE} wheelhouse is missing."

WORK_DIR="$(mktemp -d)"
trap 'rm -rf -- "${WORK_DIR}"' EXIT
VENV="${WORK_DIR}/venv"

log "Validating source with Python 3.12."
PYTHONDONTWRITEBYTECODE=1 "${RELEASE_PYTHON}"   "${ROOT}/scripts/validate-python-source.py" "${ROOT}"

log "Creating an offline Python 3.12 test environment."
"${RELEASE_PYTHON}" -m venv "${VENV}"
"${VENV}/bin/python" -m pip install   --disable-pip-version-check   --no-index   --no-deps   --no-compile   --find-links "${WHEELHOUSE}/${ARCHITECTURE}"   --requirement "${ROOT}/requirements.lock" >/dev/null
"${VENV}/bin/python" -m pip check >/dev/null

log "Running the complete CayVPN test suite with ResourceWarnings fatal."
(
  cd -- "${ROOT}"
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${ROOT}"     "${VENV}/bin/python" -W error::ResourceWarning     -m unittest discover -s tests
)

log "Checking shell, JavaScript, and whitespace."
mapfile -d '' SHELL_FILES < <(
  find "${ROOT}" -maxdepth 2 -type f \
    \( -path "${ROOT}/bootstrap.sh" -o -path "${ROOT}/install.sh" -o -path "${ROOT}/scripts/*.sh" \) \
    -print0 | LC_ALL=C sort -z
)
(("${#SHELL_FILES[@]}" > 0)) || die "No release shell files were found."
bash -n "${SHELL_FILES[@]}"
shellcheck "${SHELL_FILES[@]}"
node --check "${ROOT}/static/app.js"
git -C "${ROOT}" diff --check HEAD --

log "Canonical release preflight passed."
