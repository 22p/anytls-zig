# LuCI application for anytls-zig.
#
# Place this directory at feeds/luci/applications/luci-app-anytls-zig/ (or
# package/luci-app-anytls-zig/ and adjust the luci.mk include below).

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for AnyTLS Zig
LUCI_DEPENDS:=+anytls-zig
LUCI_PKGARCH:=all
PKG_NAME:=luci-app-anytls-zig
PKG_VERSION:=0.1.9
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
