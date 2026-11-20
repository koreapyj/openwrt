# SPDX-License-Identifier: GPL-2.0-or-later

include $(TOPDIR)/rules.mk

PKG_NAME:=imsd
PKG_RELEASE:=16

PKG_LICENSE:=GPL-2.0-or-later
# NOTICE: the vendored public-domain G.722 (src/media/g722, SpanDSP / CMU lineage) and where it is switched off
PKG_LICENSE_FILES:=NOTICE media/g722/LICENSE
PKG_MAINTAINER:=Yoonji Park <koreapyj@dcmys.kr>

PKG_BUILD_FLAGS:=gc-sections
PKG_CONFIG_DEPENDS:=CONFIG_IMSD_WITH_G722

include $(INCLUDE_DIR)/package.mk

define Package/imsd
  SECTION:=net
  CATEGORY:=Network
  TITLE:=AP side IMS stack daemon (voice and SMS for LAN SIP clients)
  DEPENDS:=@TARGET_msm89xx +libubox +libubus +libmnl \
	+libuci +kmod-ipsec +kmod-ipsec4 +kmod-ipsec6 +kmod-nft-xfrm \
	+kmod-crypto-hmac +kmod-crypto-md5 +kmod-crypto-sha1 +kmod-crypto-null \
	+libopus +libopencore-amrnb +libopencore-amrwb +libvo-amrwbenc +libpthread \
	+kmod-sound-soc-qdsp6-rtproxy +nftables-json
endef

define Package/imsd/config
	config IMSD_WITH_G722
		bool "Include the G.722 codec (vendored public-domain spandsp/CMU code)"
		depends on PACKAGE_imsd
		default y
		help
		  Wideband G.722 towards LAN SIP devices. Say n to build without the
		  vendored source (src/media/g722); the LAN side then offers Opus and G.711 only.
endef

define Package/imsd/description
  Single-process IMS user agent for the MSM8916 dongle: modem handling over
  uqmid (ISIM identity, IMS bearer, netdev), 3GPP Gm registration with
  sec-agree IPsec (TS 33.203), SIP transactions, voice calls, SMS and MMS reception between
  the network and the LAN SIP clients (softphones, ATAs: SIP registrar, call
  B2BUA, SMS relay, a persistent message store with per-device redelivery), the media engine (AMR-NB/WB, Opus, G.722, G.711 A-law
  transcoding), MMS over the IMS PDN or an on-demand MMS data bearer with a traffic guard (nftables), and a ubus control / status object. Disabled by default (uci imsd.main.enabled).
endef

define Package/imsd/conffiles
/etc/config/imsd
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
		VERSION="0.1-r$(PKG_RELEASE)" \
		OUT="$(PKG_BUILD_DIR)/obj" \
		IMSD_WITH_G722=$(if $(CONFIG_IMSD_WITH_G722),1,0) \
		imsd
endef

define Package/imsd/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config \
		$(1)/usr/share/nftables.d/chain-pre/input $(1)/lib/upgrade/keep.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/obj/imsd $(1)/usr/sbin/
	$(INSTALL_DATA) ./files/30-imsd.nft $(1)/usr/share/nftables.d/chain-pre/input/30-imsd.nft
	$(INSTALL_BIN) ./files/imsd.init $(1)/etc/init.d/imsd
	$(INSTALL_CONF) ./files/imsd.config $(1)/etc/config/imsd
	$(INSTALL_DATA) ./files/imsd.keep $(1)/lib/upgrade/keep.d/imsd
endef

$(eval $(call BuildPackage,imsd))
