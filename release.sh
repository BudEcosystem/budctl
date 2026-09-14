#!/usr/bin/env bash
# Build the release artifacts for budctl (FRD-020 §9.1, WS-7).
#
# One static binary per platform with no host dependencies: client-go, Helm,
# SOPS and age are linked in, so the target needs no kubectl, helm, sops or age.
# CGO is off so the result is genuinely static and runs on any glibc/musl host.
set -euo pipefail

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo none)"
OUT="${OUT:-dist}"
PLATFORMS="${PLATFORMS:-linux/amd64 linux/arm64 darwin/arm64 darwin/amd64}"

rm -rf "$OUT" && mkdir -p "$OUT"
for p in $PLATFORMS; do
  os="${p%/*}"; arch="${p#*/}"
  name="budctl-${os}-${arch}"
  echo "building $name"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags "-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT}" \
    -o "$OUT/$name" ./cmd/budctl
  gzip -9 -k -f "$OUT/$name"
done

( cd "$OUT" && sha256sum budctl-* > SHA256SUMS )
echo
echo "artifacts in $OUT (version ${VERSION}):"
ls -lh "$OUT" | awk 'NR>1 {print "  " $5, $9}'
echo
echo "verify:  sha256sum -c SHA256SUMS"
