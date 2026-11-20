# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk

PKG_NAME:=msm-diag-bridge
PKG_RELEASE:=3

PKG_MAINTAINER:=Yoonji Park <koreapyj@dcmys.kr>
PKG_LICENSE:=GPL-2.0-only
PKG_LICENSE_FILES:=

PKG_BUILD_FLAGS:=gc-sections

include $(INCLUDE_DIR)/package.mk

define Package/msm-diag-bridge
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Bridge MSM modem DIAG rpmsg channel to USB ACM gadget tty
  DEPENDS:=@TARGET_msm89xx
endef

define Package/msm-diag-bridge/description
  Connects the modem DIAG SMD channel (rpmsg, remoteproc0 smd-edge) to the
  USB ACM gadget serial port /dev/ttyGS1 for QPST/QXDM. Not enabled by
  default: select the bundled usbgadget preset to expose the port:
    uci set usbgadget.@preset[0].name=msm8916-diag; uci commit usbgadget
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_CPPFLAGS) -Wall -Wextra \
		$(TARGET_LDFLAGS) -o $(PKG_BUILD_DIR)/msm-diag-bridge \
		$(PKG_BUILD_DIR)/msm-diag-bridge.c
endef

define Package/msm-diag-bridge/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/usr/share/usbgadget
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/msm-diag-bridge $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/msm-diag-bridge.init $(1)/etc/init.d/msm-diag-bridge
	$(INSTALL_DATA) ./files/msm8916-diag.preset $(1)/usr/share/usbgadget/msm8916-diag
endef

$(eval $(call BuildPackage,msm-diag-bridge))
