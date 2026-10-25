# OpenWrt package for anytls-zig.
#
# Zig is not part of the OpenWrt buildroot, so the compiler must be provided by
# the build host:
#     ZIG=/path/to/zig make package/anytls-zig/compile V=s
#
# The target triple must match the OpenWrt target ABI, not just the CPU:
#   ramips/mt7621 (MT7621, MIPS32r2, little endian, no FPU) -> mipsel-linux-musleabi
#   ath79/mips (big endian, no FPU)                          -> mips-linux-musleabi
#   mediatek/filogic (ARM64)                                 -> aarch64-linux-musl
#     add ZIG_CPU="baseline+aes+sha2" (and optionally ZIG_OPTIMIZE=ReleaseFast)
#     if the SoC has the ARMv8 crypto extensions; see docs/bench-aarch64.md
#
# Use `make info` in the OpenWrt tree to confirm the target, and verify the
# produced ELF with `readelf -h -l` before installing.

include $(TOPDIR)/rules.mk

PKG_NAME:=anytls-zig
PKG_VERSION:=0.1.9
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_PARALLEL:=0

include $(INCLUDE_DIR)/package.mk

ZIG ?= zig
ZIG_OPTIMIZE ?= ReleaseSmall
ZIG_TARGET ?= mipsel-linux-musleabi
ZIG_CPU ?= mips32r2

define Package/anytls-zig
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=AnyTLS client (Zig, TLS 1.3, small static binary)
  DEPENDS:=+ca-bundle
endef

define Package/anytls-zig/description
  Minimal AnyTLS protocol v2 client with a SOCKS5 inbound, written in Zig.
  TLS 1.3 with full certificate chain and hostname verification.
endef

define Package/anytls-zig/conffiles
/etc/config/anytls-zig
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./build.zig $(PKG_BUILD_DIR)/
	$(CP) -r ./src $(PKG_BUILD_DIR)/
	$(CP) -r ./config $(PKG_BUILD_DIR)/
endef

define Build/Compile
	cd $(PKG_BUILD_DIR) && \
		$(ZIG) build \
			-Doptimize=$(ZIG_OPTIMIZE) \
			-Dtarget=$(ZIG_TARGET) \
			-Dcpu=$(ZIG_CPU)
endef

define Package/anytls-zig/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/zig-out/bin/anytls-zig $(1)/usr/bin/anytls-zig
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/anytls-zig.config $(1)/etc/config/anytls-zig
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/anytls-zig.init $(1)/etc/init.d/anytls-zig
	$(INSTALL_DIR) $(1)/etc/anytls-zig
	$(INSTALL_CONF) ./config/anytls-zig.toml $(1)/etc/anytls-zig/config.toml.example
	$(INSTALL_DIR) $(1)/usr/libexec/anytls-zig
	$(INSTALL_BIN) ./files/anytls-zig-pac $(1)/usr/libexec/anytls-zig/pac
	$(INSTALL_DIR) $(1)/usr/share/anytls-zig
	$(INSTALL_DATA) ./files/china-domains.txt $(1)/usr/share/anytls-zig/china-domains.txt
endef

$(eval $(call BuildPackage,anytls-zig))
