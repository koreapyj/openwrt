# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk

PKG_NAME:=rmtfs
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/linux-msm/rmtfs.git
PKG_SOURCE_DATE:=2026-06-23
PKG_SOURCE_VERSION:=b30a3eb38f9af283f18dbd3c7755653efc52c094
PKG_MIRROR_HASH:=skip

PKG_MAINTAINER:=Yoonji Park <koreapyj@dcmys.kr>
PKG_LICENSE:=BSD-3-Clause
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_FLAGS:=gc-sections

include $(INCLUDE_DIR)/package.mk

define Package/rmtfs
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Qualcomm remote filesystem service (modem EFS)
  URL:=https://github.com/linux-msm/rmtfs
  DEPENDS:=@TARGET_msm89xx +libqrtr
endef

define Package/rmtfs/description
  Serves the modem's remote storage (EFS: modemst1/modemst2/fsc/fsg)
  over QRTR. Built without libudev: the sysfs-only shared memory path
  is used, and the init script creates /dev/disk/by-partlabel links.
endef

# qmi_rmtfs.c is checked in; make sure make does not try to regenerate it
# from qmi_rmtfs.qmi with qmic because of checkout timestamps.
# -DANDROID selects the udev-free sysfs code path (/sys/class/rmtfs/...).
define Build/Prepare
	$(call Build/Prepare/Default)
	touch $(PKG_BUILD_DIR)/qmi_rmtfs.c
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) $(TARGET_CPPFLAGS) -DANDROID -Wall" \
		LDFLAGS="$(TARGET_LDFLAGS) -lqrtr -lpthread" \
		rmtfs
endef

define Package/rmtfs/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/rmtfs $(1)/usr/bin/
	$(INSTALL_BIN) ./files/rmtfs.init $(1)/etc/init.d/rmtfs
endef

$(eval $(call BuildPackage,rmtfs))
