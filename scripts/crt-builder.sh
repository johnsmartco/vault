#!/usr/bin/env bash

# The crt builder can used to detemine build metadata and create Vault builds.
# We use it in build.yml for building release artifacts with CRT. It is also used
# by Enos for artifact_source:local scenario variants.

set -euo pipefail

# We don't want to get stuck in some kind of interactive pager
export GIT_PAGER=cat

# Get the full version information
function version() {
  : "${VERSION_FILE:=$(repo_root)/sdk/version/version_base.go}"

  local version
  local prerelease
  local metadata

  version=$(awk '$1 == "Version" && $2 == "=" { gsub(/"/, "", $3); print $3 }' < "$VERSION_FILE")
  prerelease=$(awk '$1 == "VersionPrerelease" && $2 == "=" { gsub(/"/, "", $3); print $3 }' < "$VERSION_FILE")
  metadata=$(awk '$1 == "VersionMetadata" && $2 == "=" { gsub(/"/, "", $3); print $3 }' < "$VERSION_FILE")

  if [ -n "$metadata" ] && [ -n "$prerelease" ]; then
    echo "$version-$prerelease+$metadata"
  elif [ -n "$metadata" ]; then
    echo "$version+$metadata"
  elif [ -n "$prerelease" ]; then
    echo "$version-$prerelease"
  else
    echo "$version"
  fi
}

# Get the base version which strips any pre-release and metadata
function base_version() {
  local base_version
  local edition_version
  local _other

  if [[ $(repo) = "vault" ]]; then
    IFS="-" read -r base_version _other <<< "$(version)"
    echo "$base_version"
  else
    IFS="-" read -r edition_version _other <<< "$(version)"
    IFS="+" read -r base_version _other <<< "$edition_version"
    echo "$base_version"
  fi
}

# Get the build date from the latest commit since it can be used across all
# builds
function build_date() {
  # It's tricky to do an RFC3339 format in a cross platform way, so we hardcode UTC
  : "${DATE_FORMAT:="%Y-%m-%dT%H:%M:%SZ"}"
  git show --no-show-signature -s --format=%cd --date=format:"$DATE_FORMAT" HEAD
}

# Get the revision, which is the latest commit SHA
function build_revision() {
  git rev-parse HEAD
}

# Determine our repository by looking at our origin URL
function repo() {
  basename -s .git "$(git config --get remote.origin.url)"
}

# Determine the root directory of the repository
function repo_root() {
  git rev-parse --show-toplevel
}

# Build the UI
function build_ui() {
  local repo_root
  repo_root=$(repo_root)

  pushd "$repo_root"
  mkdir -p http/web_ui
  popd
  pushd "$repo_root/ui"
  yarn install --ignore-optional
  npm rebuild node-sass
  yarn --verbose run build
  popd
}

# Build Vault
function build() {
  # Get or set our build metadata variables
  : "${VAULT_VERSION:=$(base_version)}"
  : "${VAULT_REVISION:=$(build_revision)}"
  : "${GO_TAGS:=$(build_revision)}"
  : "${VAULT_BUILD_DATE:=$(build_date)}"

  echo "--> Building Vault v$VAULT_VERSION ($VAULT_REVISION), built $VAULT_BUILD_DATE"
  pushd "$(repo_root)"
  mkdir -p dist
  mkdir -p out
  set -x
  go build -v -tags "$GO_TAGS" -ldflags " -X github.com/hashicorp/vault/sdk/version.Version=$VAULT_VERSION -X github.com/hashicorp/vault/sdk/version.GitCommit=$VAULT_REVISION -X github.com/hashicorp/vault/sdk/version.BuildDate=$VAULT_BUILD_DATE" -o dist/
  set +x
  popd
}

# Bundle the dist directory
function bundle() {
  : "${BUNDLE_PATH:=$(repo_root)/vault.zip}"
  echo "--> Bundling dist/* to $BUNDLE_PATH"
  zip -r -j "$BUNDLE_PATH" dist/
}

# Run the CRT Builder
function main() {
  case $1 in
  base-version)
    base_version
  ;;
  build)
    build
  ;;
  build-ui)
    build_ui
  ;;
  bundle)
    bundle
  ;;
  date)
    build_date
  ;;
  revision)
    build_revision
  ;;
  version)
    version
  ;;
  *)
    echo "unknown sub-command" >&2
    exit 1
  ;;
  esac
}

main "$@"
