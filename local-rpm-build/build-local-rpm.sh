#!/bin/bash
#
# Build a gcv-opensips RPM from local source.
#
# Usage:
#   ./local-rpm-build/build-local-rpm.sh [output-dir] [package-name] [iteration]
#
# Defaults:
#   output-dir   = ./target
#   package-name = gcv-opensips
#   iteration    = local
#
# The RPM lands in <output-dir>/gcv-opensips-4.0-local.x86_64.rpm (or similar).
#

set -ex

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OPENSIPS_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

OUTPUT_DIR="${1:-${OPENSIPS_ROOT}/target}"
PACKAGE_NAME="${2:-gcv-opensips}"
ITERATION="${3:-local}"

# Ensure output dir exists (absolute path required for docker bind-mount)
mkdir -p "${OUTPUT_DIR}"
if [[ "${OUTPUT_DIR}" != /* ]]; then
  OUTPUT_DIR="$(cd "${OUTPUT_DIR}" && pwd)"
fi

echo "=== Building local OpenSIPS RPM ==="
echo "Source:   ${OPENSIPS_ROOT}"
echo "Output:   ${OUTPUT_DIR}"
echo "Package:  ${PACKAGE_NAME}"
echo "Iteration: ${ITERATION}"
echo ""

# Build the builder image
docker build --rm \
  -t gcv-opensips-local-build \
  -f "${SCRIPT_DIR}/Dockerfile" \
  --network=host \
  "${SCRIPT_DIR}"

# Run the build — bind-mount local source + Makefile.conf + output dir
docker run --rm \
  -v "${OPENSIPS_ROOT}:/opensips-src:ro" \
  -v "${SCRIPT_DIR}:/build-rpm-conf:ro" \
  -v "${OUTPUT_DIR}:/target" \
  -e PACKAGE_NAME="${PACKAGE_NAME}" \
  -e ITERATION="${ITERATION}" \
  --network=host \
  gcv-opensips-local-build

echo ""
echo "=== Done. RPM(s) in ${OUTPUT_DIR}: ==="
ls -lh "${OUTPUT_DIR}"/*.rpm 2>/dev/null || echo "(no RPMs found — check build output above)"

# Auto-copy to sipproxy-v2 if it exists alongside this repo
SIPPROXY_RPM_DIR="${OPENSIPS_ROOT}/../sipproxy-v2/deploy/opensips-rpm"
if [ -d "${SIPPROXY_RPM_DIR}" ]; then
  cp "${OUTPUT_DIR}/gcv-opensips-local.rpm" "${SIPPROXY_RPM_DIR}/gcv-opensips-local.rpm"
  echo ""
  echo "=== Copied gcv-opensips-local.rpm to ${SIPPROXY_RPM_DIR} ==="
fi
