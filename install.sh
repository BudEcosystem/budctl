#!/bin/sh
# Install budctl — the cluster readiness checker for the Bud platform.
#
#   curl -fsSL https://raw.githubusercontent.com/BudEcosystem/budctl/main/install.sh | sh
#
# Environment:
#   BUDCTL_VERSION      version to install (default: the pinned version below)
#   BUDCTL_INSTALL_DIR  where to put the binary (default: /usr/local/bin, else ~/.local/bin)
#   BUDCTL_BASE_URL     where to fetch from, for an internal mirror
#
# Everything is wrapped in main() and called on the last line, so a download cut
# short by a dropped connection defines functions and does nothing else.
set -eu

# Bumped by hand in the commit that gets tagged; the release workflow refuses a
# tag that disagrees with it. Pinned rather than resolved from the GitHub
# API at runtime: the unauthenticated API allows 60 requests per hour per IP,
# which one NATed customer site can exhaust between two engineers.
VERSION="${BUDCTL_VERSION:-0.3.1}"
REPO="BudEcosystem/budctl"

die() { echo "install.sh: $*" >&2; exit 1; }

detect_platform() {
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$os" in
    linux|darwin) ;;
    *) die "unsupported operating system: $os. Linux and macOS binaries are published; build from source for anything else." ;;
  esac
  # Rosetta reports x86_64 on Apple silicon; the amd64 binary it then gets is
  # the correct one to run under it.
  case "$(uname -m)" in
    x86_64|amd64)  arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "unsupported architecture: $(uname -m). amd64 and arm64 are published." ;;
  esac
  platform="${os}-${arch}"
}

fetch() { # fetch <url> <dest>
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 --retry-delay 1 -o "$2" "$1" || die "could not download $1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1" || die "could not download $1"
  else
    die "neither curl nor wget is installed"
  fi
}

# macOS ships shasum, not sha256sum; a checked download needs whichever exists.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else die "no sha256sum or shasum available to verify the download"
  fi
}

choose_dir() {
  if [ -n "${BUDCTL_INSTALL_DIR:-}" ]; then dest="$BUDCTL_INSTALL_DIR"
  elif [ -w /usr/local/bin ]; then dest=/usr/local/bin
  else dest="$HOME/.local/bin"
  fi
  mkdir -p "$dest" || die "cannot create $dest"
  [ -w "$dest" ] || die "$dest is not writable. Set BUDCTL_INSTALL_DIR to somewhere you own, or re-run as a user who can write there."
}

main() {
  detect_platform
  choose_dir

  # A site that mirrors the artifacts internally points BUDCTL_BASE_URL at them;
  # the checksum is still fetched and checked from the same place.
  base="${BUDCTL_BASE_URL:-https://github.com/${REPO}/releases/download/v${VERSION}}"
  file="budctl-${platform}.gz"

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT INT TERM

  echo "budctl ${VERSION} (${platform}) -> ${dest}"

  fetch "${base}/${file}" "$tmp/$file"
  fetch "${base}/SHA256SUMS" "$tmp/SHA256SUMS"

  # Verify before anything is decompressed or made executable. An installer
  # that skips this is a remote code execution channel with extra steps.
  want="$(awk -v f="$file" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/SHA256SUMS")"
  [ -n "$want" ] || die "SHA256SUMS for ${VERSION} does not list ${file}"
  got="$(sha256_of "$tmp/$file")"
  if [ "$want" != "$got" ]; then
    die "checksum mismatch for ${file}
  expected $want
  got      $got
Nothing was installed. Retry, and if it persists report it — the published artifact may be corrupt."
  fi

  gunzip -c "$tmp/$file" > "$tmp/budctl" || die "could not decompress $file"
  chmod +x "$tmp/budctl"

  # Install over any existing copy atomically, so a half-written binary is never
  # left behind and a running budctl is not corrupted mid-flight.
  mv -f "$tmp/budctl" "$dest/budctl" || die "could not install into $dest"

  echo "installed $dest/budctl"
  if ! command -v budctl >/dev/null 2>&1; then
    echo
    echo "$dest is not on your PATH. Add it:"
    echo "  export PATH=\"$dest:\$PATH\""
  fi
  echo
  echo "Check a cluster:  budctl check      (uses your current kubeconfig context)"
}

main "$@"
