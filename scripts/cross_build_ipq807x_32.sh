#!/usr/bin/env bash
# Cross-build libchssh for OpenWrt ipq807x_32 (armv7-eabihf musl).
#
# Output: build-ipq807x_32/libchssh.a  (static; lab dialectic without OpenSSL
# unless a target OpenSSL is in the Bootlin sysroot).
#
# Usage:
#   ./scripts/cross_build_ipq807x_32.sh
#   BOOTLIN_TOOLCHAIN=/path/to/tc ./scripts/cross_build_ipq807x_32.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${BUILD_DIR:-${ROOT}/build-ipq807x_32}"
# Prefer netforensics sibling toolchain file when present.
NF_TC="${ROOT}/../netforensics/cmake/toolchains/armv7-eabihf-bootlin.cmake"
if [[ -f "${NF_TC}" ]]; then
  TOOLCHAIN_FILE="${CMAKE_TOOLCHAIN_FILE:-${NF_TC}}"
else
  # Minimal inline toolchain if netforensics not co-located
  TOOLCHAIN_FILE=""
fi

pick_bootlin() {
  local c
  if [[ -n "${BOOTLIN_TOOLCHAIN:-}" && -d "${BOOTLIN_TOOLCHAIN}" ]]; then
    echo "${BOOTLIN_TOOLCHAIN}"
    return 0
  fi
  for c in "${HOME}"/toolchains/armv7-eabihf--musl--*; do
    if [[ -d "$c" && -d "$c/bin" ]]; then
      echo "$c"
      return 0
    fi
  done
  return 1
}

tc=$(pick_bootlin) || {
  echo "error: Bootlin armv7-eabihf musl toolchain not found under ~/toolchains/" >&2
  echo "  (netforensics: ./scripts/fetch_bootlin_armv7.sh)" >&2
  exit 1
}
echo "=== libchssh armv7 (ipq807x_32) ==="
echo "  toolchain: ${tc}"
echo "  build:     ${BUILD}"

rm -rf "${BUILD}/CMakeCache.txt" "${BUILD}/CMakeFiles" 2>/dev/null || true

CMAKE_ARGS=(
  -B "${BUILD}"
  -S "${ROOT}"
  -DCMAKE_BUILD_TYPE=MinSizeRel
  -DBUILD_TESTING=OFF
  -DENABLE_FUZZ=OFF
  -DBOOTLIN_TOOLCHAIN="${tc}"
)

if [[ -n "${TOOLCHAIN_FILE}" && -f "${TOOLCHAIN_FILE}" ]]; then
  CMAKE_ARGS+=(-DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN_FILE}")
  # netforensics toolchain enables CPE_AGENT_STATIC EXE flags; force static archive ok
  CMAKE_ARGS+=(-DCPE_AGENT_STATIC=ON)
else
  # Fallback: set compilers from Bootlin
  cc=$(echo "${tc}"/bin/*-linux-*-gcc | awk '{print $1}')
  [[ -x "$cc" ]] || { echo "error: no gcc in ${tc}/bin" >&2; exit 1; }
  CMAKE_ARGS+=(
    -DCMAKE_SYSTEM_NAME=Linux
    -DCMAKE_SYSTEM_PROCESSOR=arm
    -DCMAKE_C_COMPILER="${cc}"
    -DCMAKE_C_FLAGS="-march=armv7-a -mfpu=neon-vfpv4 -mfloat-abi=hard"
  )
  sysroot=$(echo "${tc}"/arm-buildroot-linux-musleabihf/sysroot)
  if [[ -d "$sysroot" ]]; then
    CMAKE_ARGS+=(-DCMAKE_FIND_ROOT_PATH="${sysroot}")
    CMAKE_ARGS+=(-DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY)
    CMAKE_ARGS+=(-DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY)
    CMAKE_ARGS+=(-DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY)
    CMAKE_ARGS+=(-DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER)
  fi
fi

cmake "${CMAKE_ARGS[@]}"
cmake --build "${BUILD}" -j"$(nproc 2>/dev/null || echo 2)" --target chssh

[[ -f "${BUILD}/libchssh.a" ]] || {
  echo "error: missing ${BUILD}/libchssh.a" >&2
  exit 1
}

echo
file "${BUILD}/libchssh.a"
# Archive members are ELF objects — sample first .o
tmpdir=$(mktemp -d)
(cd "${tmpdir}" && ar x "${BUILD}/libchssh.a" && file ./*.o | head -5)
rm -rf "${tmpdir}"
if command -v readelf >/dev/null 2>&1; then
  ar p "${BUILD}/libchssh.a" chssh.c.o 2>/dev/null | readelf -h - 2>/dev/null \
    | grep -E 'Class|Machine' || \
  (cd /tmp && ar x "${BUILD}/libchssh.a" && readelf -h ./*.o 2>/dev/null | grep -E 'Class|Machine' | head -4; rm -f ./*.o)
fi

echo
echo "OK: ${BUILD}/libchssh.a"
echo "  netforensics cross build will pick this up via build-ipq807x_32/"
