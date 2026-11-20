# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk

PKG_NAME:=qrtr
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/linux-msm/qrtr.git
PKG_SOURCE_DATE:=2026-09-15
PKG_SOURCE_VERSION:=29e36ae164389580a0f8ea7a7fdb728140ae978d
PKG_MIRROR_HASH:=skip

PKG_MAINTAINER:=Yoonji Park <koreapyj@dcmys.kr>
PKG_LICENSE:=BSD-3-Clause
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_FLAGS:=gc-sections

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/meson.mk

define Package/libqrtr
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=Qualcomm IPC Router (QRTR) userspace library
  URL:=https://github.com/linux-msm/qrtr
endef

define Package/libqrtr/description
  Userspace library for the Qualcomm IPC Router (AF_QIPCRTR) sockets,
  including QMI helpers. The name service is provided by the kernel.
endef

define Package/qrtr-tools
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Qualcomm IPC Router tools (qrtr-cfg, qrtr-lookup)
  URL:=https://github.com/linux-msm/qrtr
  DEPENDS:=+libqrtr
endef

define Package/qrtr-tools/description
  qrtr-cfg and qrtr-lookup. The userspace qrtr-ns name service is not
  built or installed; the in-kernel name service is used instead.
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(INSTALL_DATA) $(PKG_INSTALL_DIR)/usr/include/libqrtr.h $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libqrtr.so* $(1)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/qrtr.pc $(1)/usr/lib/pkgconfig/
endef

define Package/libqrtr/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libqrtr.so* $(1)/usr/lib/
endef

define Package/qrtr-tools/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/qrtr-cfg $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/qrtr-lookup $(1)/usr/bin/
endef

$(eval $(call BuildPackage,libqrtr))
$(eval $(call BuildPackage,qrtr-tools))
