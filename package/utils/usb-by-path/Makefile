#
# Copyright (C) 2016 Toke Høiland-Jørgensen
#
# This is free software, licensed under the GNU General Public License v3 or
# later.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=usb-by-path
PKG_VERSION:=1.0.0

PKG_MAINTAINER:=Yoonji Park <koreapyj@dcmys.kr>
PKG_LICENSE:=GPL-3.0
PKG_LICENSE_FILES:=LICENSE.md

include $(INCLUDE_DIR)/package.mk

define Package/usb-by-path
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=USB devices by path
  PKGARCH:=all
endef

define Package/usb-by-path/description
Make link to USB devices by path in /dev/by-path
endef

define Package/usb-by-path/install
	mkdir -p $(1)/etc/hotplug.d/tty $(1)/etc/hotplug.d/usb $(1)/etc/hotplug.d/usbmisc $(1)/etc/hotplug.d/wwan

	$(INSTALL_DIR) $(1)/etc/hotplug.d
	$(INSTALL_BIN) ./files/usb-by-path.hotplug $(1)/etc/hotplug.d/usb-by-path.sh
	$(INSTALL_BIN) ./files/usb-by-path-alsa.hotplug $(1)/etc/hotplug.d/usb/30-usb-by-path-alsa

	$(LN) ../usb-by-path.sh $(1)/etc/hotplug.d/tty/00-usb-by-path
	$(LN) ../usb-by-path.sh $(1)/etc/hotplug.d/usb/00-usb-by-path
	$(LN) ../usb-by-path.sh $(1)/etc/hotplug.d/usbmisc/00-usb-by-path
	$(LN) ../usb-by-path.sh $(1)/etc/hotplug.d/wwan/00-usb-by-path
endef

define Build/Configure
endef

define Build/Compile
endef

$(eval $(call BuildPackage,usb-by-path))
