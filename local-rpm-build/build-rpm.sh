#!/bin/bash
#
# Runs INSIDE the Docker builder container.
# Expects:
#   /opensips-src  — bind-mounted local opensips source tree
#   /target        — bind-mounted output directory for the RPM
#   PACKAGE_NAME   — env var, default: gcv-opensips
#   ITERATION      — env var, default: local
#

set -ex

PACKAGE_NAME="${PACKAGE_NAME:-gcv-opensips}"
ITERATION="${ITERATION:-local}"
INSTALL_PREFIX="/usr/local"
TMP_DIR="/tmp"

# ---------- copy source so we don't pollute the bind-mount ----------
cp -a /opensips-src /opensips
cp /build-rpm-conf/Makefile.conf.4.0 /opensips/Makefile.conf

# ---------- extract version from Makefile.defs ----------
MAJOR=$(grep '^VERSION_MAJOR' /opensips/Makefile.defs | head -1 | awk '{print $3}')
MINOR=$(grep '^VERSION_MINOR' /opensips/Makefile.defs | head -1 | awk '{print $3}')
OPENSIPS_VERSION="${MAJOR}.${MINOR}"
echo "Building OpenSIPS ${OPENSIPS_VERSION}"

# ---------- compile ----------
# Build the opensips binary + modules, then install them.
# We skip the 'install-bin' target because it depends on 'opensipsmc' (menuconfig),
# which has a compile bug in 4.0.  Instead we build 'app' + 'modules', run
# 'mk-install-dirs' + 'install-modules', and manually install the binary.
cd /opensips

MAKE_ENV="CFLAGS='-g' \
  LDFLAGS='-pthread -L/usr/local/lib64' \
  LD_EXTRA_OPTS='-Wl,-rpath,/usr/local/lib64' \
  LD_LIBRARY_PATH='/usr/local/lib64' \
  PKG_CONFIG_PATH='/usr/local/lib64/pkgconfig'"

# Compile opensips binary and modules
eval $MAKE_ENV make app modules -I /usr/local/include

# Create install directories and install modules
eval $MAKE_ENV make mk-install-dirs install-modules -I /usr/local/include

# Manually install the opensips binary (what install-bin does, minus opensipsmc)
install -m 755 opensips "${TMP_DIR}${INSTALL_PREFIX}/sbin/opensips"

# Create a stub osipsconfig so bundle-solibs.yml doesn't fail
touch "${TMP_DIR}${INSTALL_PREFIX}/sbin/osipsconfig"
chmod 755 "${TMP_DIR}${INSTALL_PREFIX}/sbin/osipsconfig"

# ---------- packaging artifacts ----------
# GDB init file
mkdir -p "${TMP_DIR}${INSTALL_PREFIX}"
cat > "${TMP_DIR}${INSTALL_PREFIX}/gcv-gdbinit" <<'EOF'
set sysroot ./solibs
set solib-search-path ./solibs
set debug-file-directory ./solibs
symbol-file ./solibs/usr/local/sbin/opensips
EOF
chmod 644 "${TMP_DIR}${INSTALL_PREFIX}/gcv-gdbinit"

# dbtext tables
DBTEXT_DIR="${TMP_DIR}${INSTALL_PREFIX}/etc/dbtext"
mkdir -p "${DBTEXT_DIR}"
for table in version grp re_grp dialplan; do
  cp "/opensips/scripts/dbtext/opensips/${table}" "${DBTEXT_DIR}/${table}"
done
ln -sf "${INSTALL_PREFIX}/etc/dbtext/version" \
       "${DBTEXT_DIR}/version_${OPENSIPS_VERSION//./_}"

# ---------- resolve dependency versions for fpm ----------
JSONC_DEP=$(rpm -q --qf '%{name} = %{epoch}:%{version}-%{release}' 'gcv-jsonc-0.13.1-*')
SSL_DEP=$(rpm -q --qf '%{name} = %{epoch}:%{version}-%{release}' 'gcv-openssl-1.1.1w-*')
HTTPD_DEP=$(rpm -q --qf '%{name} = %{epoch}:%{version}-%{release}' 'gcv-libmicrohttpd-0.9.73-*')
DYNAMO_DEP=$(rpm -q --qf '%{name} = %{epoch}:%{version}-%{release}' 'gcv-dynamodb-sdk-1.11.831-*')

# ---------- build RPM with fpm ----------
cd "${TMP_DIR}"
/usr/local/bin/fpm -s dir \
  -t rpm \
  -v "${OPENSIPS_VERSION}" \
  --iteration "${ITERATION}" \
  -n "${PACKAGE_NAME}" \
  -f \
  -x usr/local/share \
  -m "${MAINTAINER:-gcv-callp-team@genesys.com}" \
  --epoch "${MAJOR}" \
  -d "${JSONC_DEP}" \
  -d postgresql16 -d libcurl -d libuuid -d pcre \
  -d "${SSL_DEP}" \
  -d "${HTTPD_DEP}" \
  -d "${DYNAMO_DEP}" \
  usr

# ---------- copy to output ----------
# Copy the original-named RPM
cp ${TMP_DIR}/${PACKAGE_NAME}*.rpm /target/

# Also create a predictable filename for sipproxy-v2 Dockerfile COPY
RPM_FILE=$(ls ${TMP_DIR}/${PACKAGE_NAME}*.rpm | head -1)
cp "${RPM_FILE}" /target/gcv-opensips-local.rpm

echo ""
echo "=== RPM built ==="
ls -lh /target/${PACKAGE_NAME}*.rpm /target/gcv-opensips-local.rpm
