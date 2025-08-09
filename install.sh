#!/bin/sh
# install.sh — Simple installer for nps and npc
# Usage:
#   ./install.sh [mode] [version]
# mode: npc | nps | all (default all)
# version: release tag (default latest)

# Must run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "Error: Please run as root or use sudo." >&2
  exit 1
fi

set -e

# Pre-flight checks: ensure all external commands we rely on are present
for cmd in uname tar grep sed mktemp file; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: missing required command: $cmd" >&2
    exit 1
  fi
done
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
  echo "Error: need curl or wget" >&2
  exit 1
fi

TMP_DIRS=""
cleanup() {
  for d in $TMP_DIRS; do
    rm -rf "$d"
  done
}
trap cleanup EXIT

INSTALL_MODE="${1:-${NPS_INSTALL_MODE:-all}}"
INSTALL_VERSION="${2:-${NPS_INSTALL_VERSION:-latest}}"
INSTALL_DIR="${3:-${NPS_INSTALL_DIR:-}}"

# Validate mode
case "$INSTALL_MODE" in
  npc|nps|all) ;;
  *)
    echo "Error: unsupported mode: $INSTALL_MODE" >&2
    exit 1
    ;;
esac

echo "Mode: $INSTALL_MODE"

USE_CF_LATEST=0

# Fetch latest version if unspecified
if [ "$INSTALL_VERSION" = "latest" ]; then
  echo "Get latest version..."
  API_URL="https://api.github.com/repos/djylb/nps/releases/latest"
  if command -v curl >/dev/null 2>&1; then
    RAW_JSON=$(curl -sSLf "$API_URL" || true)
  else
    RAW_JSON=$(wget -qO- "$API_URL" || true)
  fi

  INSTALL_VERSION=$(printf '%s' "$RAW_JSON" \
    | grep -m1 '"tag_name"' \
    | sed 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/')

  if [ -z "$INSTALL_VERSION" ]; then
    echo "Warn: failed to detect version from GitHub API, will use CDN @latest." >&2
    USE_CF_LATEST=1
    INSTALL_VERSION=latest
  fi
fi

if [ "$USE_CF_LATEST" -eq 1 ]; then
  echo "Version: latest (CDN @latest fallback)"
else
  echo "Version: $INSTALL_VERSION"
fi

# Determine OS
OS="$(uname -s)"
case "$OS" in
  Linux)   OS=linux;;
  Darwin)  OS=darwin;;
  FreeBSD) OS=freebsd;;
  *)
    echo "Error: OS not supported: $OS" >&2
    exit 1
    ;;
esac

# Determine ARCH
RAW_ARCH="$(uname -m)"
case "$RAW_ARCH" in
  x86_64|amd64)      ARCH=amd64;;
  i?86)              ARCH=386;;
  aarch64|arm64)     ARCH=arm64;;
  armv7*|armv7l)     ARCH=arm_v7;;
  armv6*|armv6l)     ARCH=arm_v6;;
  armv5*|armv5l)     ARCH=arm_v5;;
  arm)               ARCH=arm;;
  mips64le)          ARCH=mips64le;;
  mips64)            ARCH=mips64;;
  mipsle)            ARCH=mipsle;;
  mips)              ARCH=mips;;
  loongarch64)       ARCH=loong64;;
  riscv64)           ARCH=riscv64;;
  *)
    echo "Error: ARCH not supported: $RAW_ARCH" >&2
    exit 1
    ;;
esac

echo "Detected OS/ARCH: $OS/$ARCH"

# MIPS float ABI detection
if [ "$ARCH" = "mips" ] || [ "$ARCH" = "mipsle" ]; then
  if file /bin/sh | grep -qi 'hard-float'; then
    echo "Use hard-float for $ARCH"
  else
    ARCH="${ARCH}_softfloat"
    echo "Use soft-float, new ARCH: $ARCH"
  fi
fi

# Download helper
download() {
  NAME=$1
  FILE="${OS}_${ARCH}_${NAME}.tar.gz"

  if [ "$USE_CF_LATEST" -eq 1 ]; then
    URLS="
      https://cdn.jsdelivr.net/gh/djylb/nps-mirror@latest/${FILE}
      https://fastly.jsdelivr.net/gh/djylb/nps-mirror@latest/${FILE}
      https://github.com/djylb/nps/releases/latest/download/${FILE}
    "
  else
    URLS="
      https://github.com/djylb/nps/releases/download/${INSTALL_VERSION}/${FILE}
      https://cdn.jsdelivr.net/gh/djylb/nps-mirror@${INSTALL_VERSION}/${FILE}
      https://fastly.jsdelivr.net/gh/djylb/nps-mirror@${INSTALL_VERSION}/${FILE}
    "
  fi

  if [ -n "$INSTALL_DIR" ]; then
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"
  else
    TMPD=$(mktemp -d 2>/dev/null || mktemp -d -t nps-install.XXXXXX)
    TMP_DIRS="$TMP_DIRS $TMPD"
    cd "$TMPD"
  fi

  success=0
  for u in $URLS; do
    echo "Trying $u" >&2
    if command -v curl >/dev/null 2>&1; then
      if curl -sfSL -o "$FILE" "$u"; then success=1; break; fi
    else
      if wget -q -O "$FILE" "$u"; then success=1; break; fi
    fi
  done

  if [ "$success" -ne 1 ] || [ ! -f "$FILE" ]; then
    echo "Error: Download failed for all URLs:" >&2
    for u in $URLS; do
      echo "  - $u" >&2
    done
    exit 1
  fi

  tar xf "$FILE"

  if [ -n "$INSTALL_DIR" ]; then
    printf '%s\n' "$INSTALL_DIR"
  else
    printf '%s\n' "$TMPD"
  fi
}

# Install NPC (client)
install_npc() {
  SRC=$(download client)
  echo "Install npc..."

  if [ -n "$INSTALL_DIR" ]; then
    echo "npc installed in $INSTALL_DIR"
    return
  fi

  if [ -x "$SRC/npc" ]; then
    if cp -f "$SRC/npc" /usr/bin/npc 2>/dev/null; then
      chmod 755 /usr/bin/npc
    else
      cp -f "$SRC/npc" /usr/local/bin/npc
      chmod 755 /usr/local/bin/npc
    fi
  else
    echo "Error: 'npc' binary not found in $SRC" >&2
    exit 1
  fi

  mkdir -p /etc/nps/conf
  if [ ! -f /etc/nps/conf/npc.conf ]; then
    cp "$SRC/conf/npc.conf" /etc/nps/conf/npc.conf
  else
    cp -f "$SRC/conf/npc.conf" /etc/nps/conf/npc.conf.default
  fi
  if [ ! -f /etc/nps/conf/multi_account.conf ]; then
    cp "$SRC/conf/multi_account.conf" /etc/nps/conf/multi_account.conf
  fi
  echo "npc done"
}

# Install NPS (server)
install_nps() {
  SRC=$(download server)
  echo "Install nps..."

  if [ -n "$INSTALL_DIR" ]; then
    echo "nps installed in $INSTALL_DIR"
    return
  fi

  if [ -x "$SRC/nps" ]; then
    if cp -f "$SRC/nps" /usr/bin/nps 2>/dev/null; then
      chmod 755 /usr/bin/nps
    else
      cp -f "$SRC/nps" /usr/local/bin/nps
      chmod 755 /usr/local/bin/nps
    fi
  else
    echo "Error: 'nps' binary not found in $SRC" >&2
    exit 1
  fi

  mkdir -p /etc/nps/conf /etc/nps/web
  if [ ! -f /etc/nps/conf/nps.conf ]; then
    cp "$SRC/conf/nps.conf" /etc/nps/conf/nps.conf
  else
    cp -f "$SRC/conf/nps.conf" /etc/nps/conf/nps.conf.default
  fi
  cp -rf "$SRC/web/"* /etc/nps/web/
  echo "nps done"
}

# Run installation per mode
case "$INSTALL_MODE" in
  npc) install_npc ;;
  nps) install_nps ;;
  all) install_npc; install_nps ;;
esac

echo "All done"
