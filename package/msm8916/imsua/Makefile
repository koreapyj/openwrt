# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk

PKG_NAME:=imsua
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=Yoonji Park <koreapyj@dcmys.kr>

PKG_BUILD_FLAGS:=gc-sections

include $(INCLUDE_DIR)/package.mk

define Package/imsua
  SECTION:=net
  CATEGORY:=Network
  TITLE:=AP side IMS/VoLTE user agent (proof of concept)
  DEPENDS:=@TARGET_msm89xx +libubox +libubus +ip-full +kmod-ipsec +kmod-ipsec6 \
	+kmod-crypto-hmac +kmod-crypto-md5 +kmod-crypto-null
endef

define Package/imsua/description
  IMS AKA + sec-agree IPsec (TS 33.203) REGISTER, a short test call and RTP
  capture over the IMS PDN. ISIM AKA is done through the uqmid ubus methods
  uim_channel_open / uim_apdu_send. Calls are hard limited to 18 s.
  Proof of concept, not for production use.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) $(TARGET_CPPFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		imsua
endef

define Package/imsua/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/imsua $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,imsua))
