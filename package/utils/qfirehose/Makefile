include $(TOPDIR)/rules.mk

PKG_NAME:=qfirehose
# PKG_VERSION:=1.2
PKG_RELEASE:=1

# PKG_SOURCE:=LTE5G_QFirehose_LinuxAndroid_V1.2.zip
# PKG_SOURCE_URL:=https://www.quectel.com/wp-content/uploads/2021/03/
# PKG_HASH:=ff71e0d8ba187813f64ad177f70ac456f1fe1ae7885c72b32d0fad50bf3c17d8
# PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
# PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_SOURCE_SUBDIR)
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL=https://github.com/pmsourcedump/qfirehose.git
PKG_SOURCE_DATE:=2020-11-12
PKG_SOURCE_VERSION:=2fed877d027af59ada44b82fe616bba1288296b3
PKG_MIRROR_HASH:=pass

PKG_MAINTAINER:=koreapyj <koreapyj@dcmys.kr>

# include $(INCLUDE_DIR)/unpack.mk
# UNPACK_CMD:=unzip -q -d $(PKG_BUILD_DIR) $(DL_DIR)/$(PKG_SOURCE); mv $(PKG_BUILD_DIR)/L*/* $(PKG_BUILD_DIR)

include $(INCLUDE_DIR)/package.mk

ifeq ($(CONFIG_BIG_ENDIAN),y)
TARGET_CFLAGS+= -DHAVE_BIG_ENDIAN=1
endif
TARGET_CFLAGS+= -D_GNU_SOURCE

define Package/qfirehose
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=Quectel QFirehose Utility
	URL:=https://www.quectel.com/download-zone
  	DEPENDS:=+libpthread
endef

define Package/qfirehose/description
  	Quectel module firmware update utility
endef

define Package/qfirehose/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/QFirehose $(1)/usr/bin/qfirehose
endef

$(eval $(call BuildPackage,qfirehose))
