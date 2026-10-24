#!/bin/sh
# Build an OpenWrt apk (ADB v3) from an already built binary.
#
#   APK=/path/to/apk.static scripts/make-apk.sh \
#       <binary> <openwrt-arch> <pkgver> <output.apk>
#
# Example:
#   APK=/usr/bin/apk scripts/make-apk.sh zig-out/bin/anytls-zig \
#       mipsel_24kc 0.1.0-r1 anytls-zig_0.1.0-r1_mipsel_24kc.apk
#
# Requires apk-tools >= 3.0 (the `mkpkg` applet), e.g. Alpine's
# apk-tools-static. The result is the ADB format used by OpenWrt snapshots and
# 25.x; OpenWrt 24.10 and older use opkg/.ipk instead.
#
# The package is unsigned: install with `apk add --allow-untrusted <file>` or
# sign it with the key trusted by the image. Run as root (or under fakeroot)
# so entries are recorded as root-owned.

set -eu

binary=${1:?usage: make-apk.sh <binary> <arch> <pkgver> <output.apk>}
arch=${2:?usage: make-apk.sh <binary> <arch> <pkgver> <output.apk>}
pkgver=${3:?usage: make-apk.sh <binary> <arch> <pkgver> <output.apk>}
output=${4:?usage: make-apk.sh <binary> <arch> <pkgver> <output.apk>}
APK=${APK:-apk}

[ -f "$binary" ] || {
	echo "missing binary: $binary" >&2
	exit 1
}
command -v "$APK" >/dev/null 2>&1 || {
	echo "apk-tools 3 not found (set APK=/path/to/apk.static)" >&2
	exit 1
}
if [ "$(id -u)" -ne 0 ]; then
	echo "warning: not root; recorded file ownership will not be root" >&2
fi

here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d /tmp/anytls-apk.XXXXXX)
trap 'rm -rf "$tmp"' EXIT INT TERM

mkdir -p "$tmp/usr/bin" "$tmp/etc/init.d" "$tmp/etc/config" "$tmp/etc/rc.d" "$tmp/etc/anytls-zig"
cp "$binary" "$tmp/usr/bin/anytls-zig"
cp "$here/openwrt/files/anytls-zig.init" "$tmp/etc/init.d/anytls-zig"
cp "$here/openwrt/files/anytls-zig.config" "$tmp/etc/config/anytls-zig"
cp "$here/config/anytls-zig.toml" "$tmp/etc/anytls-zig/config.toml.example"
# Enabled out of the box: this is the symlink `service enable` would create,
# so LuCI's System -> Startup shows the service as enabled right after install.
ln -s ../init.d/anytls-zig "$tmp/etc/rc.d/S90anytls-zig"

chmod 755 "$tmp/usr/bin/anytls-zig" "$tmp/etc/init.d/anytls-zig"
chmod 600 "$tmp/etc/config/anytls-zig"
chmod 644 "$tmp/etc/anytls-zig/config.toml.example"
# ADB records mtimes; normalize them so rebuilds are identical.
find "$tmp" -exec touch -h -d @0 {} +

"$APK" mkpkg --no-xattrs \
	-I "name:anytls-zig" \
	-I "version:$pkgver" \
	-I "arch:$arch" \
	-I "description:AnyTLS client (protocol v2, TLS 1.3, static)" \
	-I "license:MIT" \
	-I "origin:anytls-zig" \
	-I "maintainer:anytls-zig contributors" \
	-I "depends:ca-bundle" \
	-F "$tmp" -o "$output"

echo "apk: $output (ADB v3, arch $arch)"
