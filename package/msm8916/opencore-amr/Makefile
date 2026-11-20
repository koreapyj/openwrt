# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk

PKG_NAME:=opencore-amr
PKG_VERSION:=0.1.6
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=@SF/opencore-amr
PKG_HASH:=483eb4061088e2b34b358e47540b5d495a96cd468e361050fae615b1809dc4a1

PKG_MAINTAINER:=Yoonji Park <koreapyj@dcmys.kr>
PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE

PKG_INSTALL:=1
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/libopencore-amr/Default
  SECTION:=libs
  CATEGORY:=Libraries
  URL:=https://opencore-amr.sourceforge.io/
endef

define Package/libopencore-amrnb
  $(call Package/libopencore-amr/Default)
  TITLE:=OpenCORE AMR-NB codec library (encoder and decoder)
endef

define Package/libopencore-amrwb
  $(call Package/libopencore-amr/Default)
  TITLE:=OpenCORE AMR-WB decoder library
endef

define Package/libopencore-amrnb/description
  Adaptive Multi-Rate narrowband speech codec library from OpenCORE
  (encoder and decoder).
endef

define Package/libopencore-amrwb/description
  Adaptive Multi-Rate wideband speech codec library from OpenCORE
  (decoder only; use libvo-amrwbenc for encoding).
endef

CONFIGURE_ARGS += \
	--enable-shared \
	--enable-static \
	--disable-examples

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include $(1)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/include/opencore-amrnb $(1)/usr/include/
	$(CP) $(PKG_INSTALL_DIR)/usr/include/opencore-amrwb $(1)/usr/include/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libopencore-amr{nb,wb}.{so*,a} $(1)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/opencore-amr{nb,wb}.pc $(1)/usr/lib/pkgconfig/
endef

define Package/libopencore-amrnb/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libopencore-amrnb.so* $(1)/usr/lib/
endef

define Package/libopencore-amrwb/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libopencore-amrwb.so* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libopencore-amrnb))
$(eval $(call BuildPackage,libopencore-amrwb))
