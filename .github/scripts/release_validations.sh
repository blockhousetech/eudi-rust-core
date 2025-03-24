#!/bin/bash

set -euo pipefail

function help() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Preliminary checks to ensure the crate is ready for publishing.
Also retrieves the Changelog entry for the release version, and
makes it available as a step output for the rest of the job.

Args:
  -h | --help    Show this help message.
  -C             Turn on colored output.
  -c <crate>     The crate name to be published.
  -v <version>   The release version of the crate.
EOF
}

# Vars for colored output
readonly NC="\e[0m"
readonly RED="\e[31m"
readonly GREEN="\e[32m"
COLORED_OUTPUT=false

function log_success() {
  if [[ ${COLORED_OUTPUT} == true ]]; then
    echo -e "${GREEN}$*${NC}"
  else
    echo "$*"
  fi
}

function log_err() {
  if [[ ${COLORED_OUTPUT} == true ]]; then
    echo -e "${RED}Err - $*${NC}" >&2
  else
    echo "Err - $*"
  fi
}

for arg in "$@"; do
  if [[ "${arg}" == "--help" ]]; then
    help
    exit 0
  fi
done

if [[ $# -eq 0  || ($# -eq 1 && "$1" == "-C") ]]; then
  log_err "No arguments provided, showing help."
  help
  exit 1
fi

while getopts ":hCc:v:" opt; do
  case "${opt}" in
    h)
      help
      exit 0
      ;;
    c)
      readonly CRATE="$OPTARG"
      ;;
    C)
      COLORED_OUTPUT=true
      ;;
    v)
      readonly VERSION="$OPTARG"
      ;;
    \?)
      log_err "Invalid option: -${OPTARG}"
      help
      exit 1
      ;;
    :)
      log_err "Option -$OPTARG requires an argument."
      help
      exit 1
      ;;
  esac
done

set +u
if [[ -z "${CRATE}" ]]; then
  log_err "Crate (-c) not specified. Both CRATE (-c) and VERSION (-v) must be specified."
  help
  exit 1
fi

if [[ -z "${VERSION}" ]]; then
  log_err "Version (-v) not specified. Both CRATE (-c) and VERSION (-v) must be specified."
  help
  exit 1
fi
set -u

######################################################
# Check if VERSION adheres to the SemVer convention
# Globals:
#  VERSION
# Errors:
#   If VERSION doesn't adhere to SemVer convention.
######################################################
function semver_check() {
  if [[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    log_success "$VERSION is a valid SemVer tag."
  else
    log_err "$VERSION isn't a valid SemVer tag."
    exit 1
  fi
}


######################################################
# Check if the git tag already exists on remote.
# Globals:
#  VERSION
# Errors:
#   If the git tag already exists on remote.
######################################################
function check_if_git_tag_exists() {
  local -r RELEASE_GIT_TAG="${CRATE}/v${VERSION}"

  set +e
  git ls-remote --tags --exit-code origin "${RELEASE_GIT_TAG}"
  ret=$?
  set -e

  if [[ $ret -eq 0 ]]; then
    log_err "Tag ${RELEASE_GIT_TAG} already exists on remote."
    exit 1
  elif [[ $ret -eq 2 ]]; then
    log_success "Tag ${RELEASE_GIT_TAG} is not currently used on remote."
  else
    log_err "Another error occurred with code ${ret}."
    exit 1
  fi
}


######################################################
# Check if the crate's manifest version matches the
# version to be published.
# Globals:
#  CRATE
#  VERSION
# Errors:
#   If the manifest and release versions don't match.
######################################################
function check_manifest_version() {
  local -r CRATE_CARGO_VERSION=$(cargo metadata --format-version=1 --no-deps | \
            jq --arg PKG "${CRATE}" --raw-output --exit-status '.packages[] | select(.name == $PKG) | .version')

  if [[ -z "${CRATE_CARGO_VERSION}" ]]; then
    log_err "Version info not found for ${CRATE}. Check that you provided a valid Rust crate name."
    exit 1
  fi

  if [[ "${VERSION}" != "${CRATE_CARGO_VERSION}" ]]; then
    log_err "The version to release (${VERSION}) does not match the version defined in Cargo.toml (${CRATE_CARGO_VERSION})"
    exit 1
  fi
  log_success "Release and manifest versions are matching."
}


######################################################
# Fetches the crate's Changelog entry for the
# specified version.
# Globals:
#   CRATE
#   VERSION
# Outputs:
#   Writes the Changelog entry to $GITHUB_OUTPUT
#   when running on GitHub Actions; otherwise, prints
#   a message to stdout.
# Errors:
#   Exits with an error if the Changelog entry cannot
#   be found.
######################################################
function fetch_changelog_entry() {
  local -r ENTRY="$(awk -v ver="${VERSION}" '
    /^#+ \[/ {
      if (p) exit
      if ($2 == "[" ver "]") { p=1; next }
    }
    /^\[Unreleased\]/ { if (p) exit }
    p { print }
  ' "./${CRATE}/CHANGELOG.md")"

  if [[ -z "${ENTRY}" ]]; then
    log_err "Changelog entry not found for ${VERSION}"
    exit 1
  fi

  printf "Read the Changelog entry for the release version:\n${ENTRY}\n\n"

  # GITHUB_OUTPUT will be unbound locally, available only on runners
  set +u
  if [[ -z "$GITHUB_OUTPUT" ]]; then
    echo "Running locally; skip writing to GITHUB_OUTPUT"
  else
    echo "changelog-entry<<EOF" >> "$GITHUB_OUTPUT"
    echo "${ENTRY}" >> "$GITHUB_OUTPUT"
    echo "EOF" >> "$GITHUB_OUTPUT"
    log_success "Set 'changelog_entry' as the step output."
  fi
  set -u
}

semver_check
check_if_git_tag_exists
check_manifest_version
fetch_changelog_entry
