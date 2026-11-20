include $(TOPDIR)/rules.mk

PKG_NAME:=uqmi
PKG_RELEASE:=45

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL=$(PROJECT_GIT)/project/uqmi.git
PKG_SOURCE_DATE:=2025-07-30
PKG_SOURCE_VERSION:=7914da43cddaaf6cfba116260c81e6e9adffd5ab
PKG_MIRROR_HASH:=5972a5f90bd60d34b5c7a8cec14ae98f13dbb6ea5b35d845ce5da7a8a3b0e59c
PKG_MAINTAINER:=Matti Laakso <malaakso@elisanet.fi>

PKG_LICENSE:=GPL-2.0
PKG_LICENSE_FILES:=

PKG_FLAGS:=nonshared
PKG_BUILD_FLAGS:=gc-sections

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/uqmi
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=WWAN
  DEPENDS:=+libubox +libblobmsg-json +libubus +kmod-usb-net +kmod-usb-net-qmi-wwan +wwan
  TITLE:=Control utility for mobile broadband modems
endef

define Package/uqmid
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=WWAN
  DEPENDS:=+libubox +libblobmsg-json +libubus +libtalloc +ubus +jsonfilter +netifd
  TITLE:=QMI modem management daemon
endef

define Package/uqmi/description
  uqmi is a command line tool for controlling mobile broadband modems using
  the QMI-protocol.
endef

define Package/uqmid/description
  uqmid is a daemon that owns the QMI modem device and exposes it over ubus.
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include \
	-Wno-error=maybe-uninitialized

CMAKE_OPTIONS += \
	-DDEBUG=1 \
	-DBUILD_UQMID=ON

define Package/uqmi/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/uqmi/uqmi $(1)/sbin/
	$(CP) ./files/* $(1)/
endef

define Package/uqmid/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/uqmid/uqmid $(1)/sbin/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files-uqmid/usr/sbin/uqmid-wrapper $(1)/usr/sbin/
	$(INSTALL_BIN) ./files-uqmid/usr/sbin/uqmid-monitor $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/usr/share/uqmid
	$(INSTALL_DATA) ./files-uqmid/usr/share/uqmid/uqmid.common $(1)/usr/share/uqmid/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files-uqmid/etc/init.d/uqmid $(1)/etc/init.d/
	$(INSTALL_DIR) $(1)/etc/hotplug.d/wwan
	$(INSTALL_DATA) ./files-uqmid/etc/hotplug.d/wwan/25-uqmid $(1)/etc/hotplug.d/wwan/
	$(INSTALL_DIR) $(1)/lib/netifd/proto
	$(INSTALL_BIN) ./files-uqmid/lib/netifd/proto/uqmid.sh $(1)/lib/netifd/proto/
	$(INSTALL_DIR) $(1)/etc/hotplug.d/usbmisc
	$(INSTALL_DATA) ./files-uqmid/etc/hotplug.d/usbmisc/25-uqmid $(1)/etc/hotplug.d/usbmisc/
endef

$(eval $(call BuildPackage,uqmi))
$(eval $(call BuildPackage,uqmid))
