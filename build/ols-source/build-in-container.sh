#!/bin/sh
# Runs inside the pinned builder image. /build/openlitespeed and /build/third-party are
# prepared (pinned and patched) by build.py; nothing here clones mutable branches.
set -eu
cd /build/openlitespeed
# Upstream build.sh only builds third-party libraries when it cloned them itself;
# replicate that block against the pinned checkout.
# A third-party tree restored from the pinned-input cache carries this marker.
if [ ! -f ../third-party/.olscp-built ]; then
    mkdir -p ../third-party/lib64
    cd ../third-party/script
    sed -i -e "s/unittest-cpp/bcrypt/g" -e "s/psol/ /g" ./build_ols.sh
    cd /build/openlitespeed
fi
# Same EL8+ toolchain that upstream prepareLinux installs; needed before third-party.
dnf -y -q install epel-release >/dev/null
dnf -y -q groupinstall "Development Tools" >/dev/null
dnf -y -q install git cmake libtool autoconf automake wget go clang patch expat-devel \
    libcap-devel libaio-devel which dnf-plugins-core >/dev/null
# Upstream links libstdc++ statically into the server and modules; it lives in CRB.
dnf config-manager --set-enabled crb
dnf -y -q install libstdc++-static >/dev/null
if [ ! -f ../third-party/.olscp-built ]; then
    (cd ../third-party/script && ./build_ols.sh) > /build/out/third-party.log 2>&1
    touch ../third-party/.olscp-built
fi
./build.sh > /build/out/build.log 2>&1
rpm -qa --qf '%{NEVRA}\n' | sort > /build/out/builder-packages.txt
mkdir -p /build/out/dist/bin /build/out/dist/modules /build/out/dist/lsns/bin
cp dist/bin/openlitespeed /build/out/dist/bin/
cp dist/modules/*.so /build/out/dist/modules/
cp dist/lsns/bin/* /build/out/dist/lsns/bin/ 2>/dev/null || true
./build/src/openlitespeed -v > /build/out/version.txt 2>&1 || true
