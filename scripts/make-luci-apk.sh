#!/bin/sh
# Build the arch-independent OpenWrt apk (ADB v3) for the LuCI application.
#
#   APK=/path/to/apk.static scripts/make-luci-apk.sh <pkgver> <output.apk>
#
# The catalog is compiled from po/zh_Hans with scripts/po2lmo.py, which emits
# the same .lmo bytes as LuCI's po2lmo host tool.
#
# Requires apk-tools >= 3.0 (`mkpkg`). Unsigned package: install with
# `apk add --allow-untrusted <file>` or sign it with the key trusted by the
# image. Run as root (or under fakeroot) for root-owned entries.

set -eu

pkgver=${1:?usage: make-luci-apk.sh <pkgver> <output.apk>}
output=${2:?usage: make-luci-apk.sh <pkgver> <output.apk>}
APK=${APK:-apk}

command -v "$APK" >/dev/null 2>&1 || {
	echo "apk-tools 3 not found (set APK=/path/to/apk.static)" >&2
	exit 1
}
if [ "$(id -u)" -ne 0 ]; then
	echo "warning: not root; recorded file ownership will not be root" >&2
fi

here=$(cd "$(dirname "$0")/.." && pwd)
app="$here/openwrt/luci/luci-app-anytls-zig"
tmp=$(mktemp -d /tmp/anytls-luci-apk.XXXXXX)
trap 'rm -rf "$tmp"' EXIT INT TERM

mkdir -p "$tmp/www/luci-static/resources/view/anytls-zig" \
	"$tmp/usr/share/luci/menu.d" \
	"$tmp/usr/share/rpcd/acl.d" \
	"$tmp/usr/lib/lua/luci/i18n"

cp "$app/htdocs/luci-static/resources/view/anytls-zig/settings.js" \
	"$tmp/www/luci-static/resources/view/anytls-zig/settings.js"
cp "$app/root/usr/share/luci/menu.d/luci-app-anytls-zig.json" \
	"$tmp/usr/share/luci/menu.d/luci-app-anytls-zig.json"
cp "$app/root/usr/share/rpcd/acl.d/luci-app-anytls-zig.json" \
	"$tmp/usr/share/rpcd/acl.d/luci-app-anytls-zig.json"
# LuCI loads catalogs with glob *.<lang>.lmo where <lang> is the runtime
# language code (LC alias, "zh-cn"), not the gettext directory name
# ("zh_Hans"). Install under the code the dispatcher looks for.
python3 "$here/scripts/po2lmo.py" "$app/po/zh_Hans/anytls-zig.po" \
	"$tmp/usr/lib/lua/luci/i18n/anytls-zig.zh-cn.lmo"

find "$tmp" -type f -exec chmod 644 {} +
# ADB records mtimes; normalize them so rebuilds are identical.
find "$tmp" -exec touch -h -d @0 {} +

"$APK" mkpkg --no-xattrs \
	-I "name:luci-app-anytls-zig" \
	-I "version:$pkgver" \
	-I "arch:noarch" \
	-I "description:LuCI support for AnyTLS Zig" \
	-I "license:MIT" \
	-I "origin:luci-app-anytls-zig" \
	-I "maintainer:anytls-zig contributors" \
	-I "depends:luci-base anytls-zig" \
	-F "$tmp" -o "$output"

echo "apk: $output (ADB v3, arch noarch)"
