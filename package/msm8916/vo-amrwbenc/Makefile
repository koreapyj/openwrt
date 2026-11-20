# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk

PKG_NAME:=vo-amrwbenc
PKG_VERSION:=0.1.3
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=@SF/opencore-amr/$(PKG_NAME)
PKG_HASH:=5652b391e0f0e296417b841b02987d3fd33e6c0af342c69542cbb016a71d9d4e

PKG_MAINTAINER:=Yoonji Park <koreapyj@dcmys.kr>
PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=COPYING NOTICE

PKG_INSTALL:=1
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/libvo-amrwbenc
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=VisualOn AMR-WB encoder library
  URL:=https://opencore-amr.sourceforge.io/
endef

define Package/libvo-amrwbenc/description
  VisualOn Adaptive Multi-Rate wideband (AMR-WB) speech encoder library.
  Portable C build; the ARMv5E and ARMv7 NEON assembler options are 32-bit
  ARM only and are not enabled on aarch64.
endef

CONFIGURE_ARGS += \
	--enable-shared \
	--enable-static \
	--disable-example \
	--disable-armv5e \
	--disable-armv7neon

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include $(1)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/include/vo-amrwbenc $(1)/usr/include/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libvo-amrwbenc.{so*,a} $(1)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/vo-amrwbenc.pc $(1)/usr/lib/pkgconfig/
endef

define Package/libvo-amrwbenc/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libvo-amrwbenc.so* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libvo-amrwbenc))
