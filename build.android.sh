#!/usr/bin/env bash
set -euo pipefail

# ===== Config =====
APP_NAME="npc"
SRC="./cmd/npc/npc.go"
API="${API:-24}"
NDK_VERSION="${NDK_VERSION:-r28c}"
NDK_CACHE_DIR="${NDK_CACHE_DIR:-$HOME}"
TAGS="${TAGS:-netgo,osusergo}"
GCFLAGS="${GCFLAGS:-}"
OUT_ROOT="."
# ===================

host_tag() { echo "$(uname -s | tr '[:upper:]' '[:lower:]')-x86_64"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "need $1"; exit 1; }; }

ensure_ndk() {
  if [[ -n "${NDK:-}" && -d "$NDK" ]]; then
    NDK_ROOT="$NDK"
  elif [[ -n "${ANDROID_NDK_HOME:-}" && -d "$ANDROID_NDK_HOME" ]]; then
    NDK_ROOT="$ANDROID_NDK_HOME"
  else
    local default_dir="$NDK_CACHE_DIR/android-ndk-${NDK_VERSION}"
    if [[ -d "$default_dir" ]]; then
      echo "Using existing NDK: $default_dir"
      NDK_ROOT="$default_dir"
    else
      local url="https://dl.google.com/android/repository/android-ndk-${NDK_VERSION}-linux.zip"
      echo "NDK not found; downloading ${NDK_VERSION} to $NDK_CACHE_DIR ..."
      need curl; need unzip
      tmpzip="$(mktemp -t ndk.XXXXXX.zip)"
      curl -fsSL --retry 5 --retry-delay 2 "$url" -o "$tmpzip"
      (cd "$NDK_CACHE_DIR" && unzip -q "$tmpzip") || true
      rm -f "$tmpzip"
      NDK_ROOT="$default_dir"
      [[ -d "$NDK_ROOT" ]] || { echo "NDK unzip failed: $NDK_ROOT"; exit 1; }
    fi
  fi

  HOST_TAG="$(host_tag)"
  LLVM_BIN="${NDK_ROOT}/toolchains/llvm/prebuilt/${HOST_TAG}/bin"
  SYSROOT="${NDK_ROOT}/toolchains/llvm/prebuilt/${HOST_TAG}/sysroot"
  [[ -d "$LLVM_BIN" && -d "$SYSROOT" ]] || { echo "Invalid NDK: $NDK_ROOT"; exit 1; }

  STRIP_BIN="${LLVM_BIN}/llvm-strip"
  [[ -x "$STRIP_BIN" ]] || { echo "missing $STRIP_BIN"; exit 1; }

  mk_wrap() {
    local wrapper="$1" target="$2"
    mkdir -p "$(dirname "$wrapper")"
    printf '%s\n' "#!/usr/bin/env bash" >"$wrapper"
    printf '%s\n' "exec \"${LLVM_BIN}/clang\" -target ${target} --sysroot=\"${SYSROOT}\" \"\$@\"" >>"$wrapper"
    chmod +x "$wrapper"
  }

  WRAP_DIR="${OUT_ROOT}/.ndkwrap"
  mkdir -p "$WRAP_DIR"

  AARCH64_CLANG="${LLVM_BIN}/aarch64-linux-android${API}-clang"
  X86_64_CLANG="${LLVM_BIN}/x86_64-linux-android${API}-clang"
  ARMV7A_CLANG="${LLVM_BIN}/armv7a-linux-androideabi${API}-clang"
  I686_CLANG="${LLVM_BIN}/i686-linux-android${API}-clang"

  [[ -x "$AARCH64_CLANG" ]] || { AARCH64_CLANG="$WRAP_DIR/aarch64-linux-android${API}-clang"; mk_wrap "$AARCH64_CLANG" "aarch64-linux-android${API}"; }
  [[ -x "$X86_64_CLANG"   ]] || { X86_64_CLANG="$WRAP_DIR/x86_64-linux-android${API}-clang";   mk_wrap "$X86_64_CLANG"   "x86_64-linux-android${API}"; }
  [[ -x "$ARMV7A_CLANG"   ]] || { ARMV7A_CLANG="$WRAP_DIR/armv7a-linux-androideabi${API}-clang"; mk_wrap "$ARMV7A_CLANG" "armv7a-linux-androideabi${API}"; }
  [[ -x "$I686_CLANG"     ]] || { I686_CLANG="$WRAP_DIR/i686-linux-android${API}-clang";       mk_wrap "$I686_CLANG"     "i686-linux-android${API}"; }

  export LLVM_BIN STRIP_BIN SYSROOT
}

build_one() {
  local outdir="$1" goarch="$2" cc="$3" extra_env="${4:-}"
  mkdir -p "$outdir"
  local bin="${outdir}/lib${APP_NAME}.so"
  echo "==> Building ${outdir} (${goarch}) -> ${bin}"

  local LZ_COMMON=""
  if "${LLVM_BIN}/ld.lld" --help 2>/dev/null | grep -q 'common-page-size'; then
    LZ_COMMON="-Wl,-z,common-page-size=16384"
  fi
  local EXTLD="-Wl,-z,max-page-size=16384"
  [[ -n "$LZ_COMMON" ]] && EXTLD+=" ${LZ_COMMON}"

  local LDFLAGS="-s -w -buildid= -linkmode=external -extldflags \"${EXTLD}\""

  local -a ENVV=(CGO_ENABLED=1 GOOS=android GOARCH="$goarch" CC="$cc")
  [[ -n "$extra_env" ]] && ENVV+=("$extra_env")

  env "${ENVV[@]}" \
    go build -trimpath -buildvcs=false -buildmode=pie \
      -tags "$TAGS" -gcflags "$GCFLAGS" \
      -ldflags "$LDFLAGS" \
      -o "$bin" "$SRC"

  "$STRIP_BIN" -s "$bin" || true

  if command -v readelf >/dev/null 2>&1; then
    echo "-- readelf (${outdir}) --"
    readelf -lW "$bin" | awk '/LOAD/ {print $0}' || true
  fi
}

main() {
  ensure_ndk

  build_one "arm64-v8a"    "arm64" "$AARCH64_CLANG"
  build_one "x86_64"       "amd64" "$X86_64_CLANG"
  build_one "armeabi-v7a"  "arm"   "$ARMV7A_CLANG" "GOARM=7"
  build_one "x86"          "386"   "$I686_CLANG"

  echo "OK. Outputs:"
  find "$OUT_ROOT" -maxdepth 2 -type f -name 'lib'"$APP_NAME"'.so' -printf '%P\t%k KB\n' | sort

  tar -czf android_libs_client.tar.gz \
    arm64-v8a/lib${APP_NAME}.so \
    x86_64/lib${APP_NAME}.so \
    armeabi-v7a/lib${APP_NAME}.so \
    x86/lib${APP_NAME}.so

  echo "Packed: android_libs_client.tar.gz"
}

main "$@"
