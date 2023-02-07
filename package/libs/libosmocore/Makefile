#
# Copyright (C) 2006-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=libosmocore
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL=https://github.com/osmocom/libosmocore.git
PKG_SOURCE_DATE:=2021-11-21
PKG_SOURCE_VERSION:=a1584d237bab2f1f6637cab1bdee86dad9c63881
PKG_MIRROR_HASH:=pass

PKG_LICENSE:=LGPL-2.1
PKG_MAINTAINER:=Felix Fietkau <nbd@nbd.name>

PKG_FIXUP:=autoreconf
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/libosmocore
	SECTION:=libs
	CATEGORY:=Libraries
	TITLE:=Osmocom core libraries
  	DEPENDS:=+libtalloc +libpcsclite +libgnutls +libsctp +libmnl
endef

define Package/libosmocore/description
 	Osmocom core libraries
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/osmocom $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libosmo*.{la,so*} $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/libosmo*.pc $(1)/usr/lib/pkgconfig/
endef

define Package/libosmocore/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DATA) $(PKG_INSTALL_DIR)/usr/lib/libosmo*.so.* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libosmocore))
