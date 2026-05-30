#!/usr/bin/env sh
set -eu

VERSION="${TRUSTMOD_VERSION:-latest}"
MODULE="github.com/maksemen2/trustmod/cmd/trustmod@${VERSION}"

if ! command -v go >/dev/null 2>&1; then
  echo "Go 1.23 or newer is required to install trustmod." >&2
  exit 1
fi

echo "Installing ${MODULE}"
go install "${MODULE}"

gobin="$(go env GOBIN)"
if [ -z "$gobin" ]; then
  gobin="$(go env GOPATH)/bin"
fi
echo "trustmod installed to ${gobin}/trustmod"
