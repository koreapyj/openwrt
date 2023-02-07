#
# Copyright (C) 2017 - 2018 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=qcdiag

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/osmocom/osmo-qcdiag.git
PKG_SOURCE_VERSION:=aea8cb80b8fee779ba33af566d1fd31efc2374bf
PKG_SOURCE_DATE:=2021-11-19
PKG_MIRROR_HASH:=pass
PKG_RELEASE:=0.1

PKG_FIXUP:=autoreconf

PKG_LICENSE:=GPL-2.0
PKG_LICENSE_FILES:=COPYRIGHT.txt LICENSE.txt
PKG_MAINTAINER:=koreapyj <koreapyj@dcmys.kr>

include $(INCLUDE_DIR)/package.mk

define Build/Prepare
	$(call Build/Prepare/Default,)
	$(CP) $(PKG_BUILD_DIR)/src/* $(PKG_BUILD_DIR)/
endef

define Package/$(PKG_NAME)
	SECTION:=utils
	CATEGORY:=Utilities
	URL:=https://github.com/osmocom/osmo-qcdiag.git
	TITLE:=Qualcomm DIAG Support
  	DEPENDS:=+libosmocore +libqmi +glib2
endef

define Package/$(PKG_NAME)/description
 	Qualcomm DIAG Support
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/osmo-qcdiag-log $(1)/usr/bin/qcdiag
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
