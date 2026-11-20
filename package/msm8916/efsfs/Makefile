# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk

PKG_NAME:=efsfs
PKG_RELEASE:=1

PKG_MAINTAINER:=Yoonji Park <koreapyj@dcmys.kr>
PKG_LICENSE:=GPL-2.0-only

PKG_BUILD_FLAGS:=gc-sections

include $(INCLUDE_DIR)/package.mk

define Package/efsfs
  SECTION:=utils
  CATEGORY:=Utilities
  SUBMENU:=Filesystem
  TITLE:=Read-only FUSE view of the MSM8916 modem EFS and NV items
  DEPENDS:=@TARGET_msm89xx +libfuse3 +kmod-fuse
endef

define Package/efsfs/description
  Mounts the modem EFS2 (and NV items as /nv/<decimal>) read-only over the
  modem DIAG rpmsg channel. Usage: efsfs /mnt/efs. The DIAG channel is only
  held during each file operation.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_CPPFLAGS) -Wall -Wextra \
		-D_FILE_OFFSET_BITS=64 $(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/efsfs $(PKG_BUILD_DIR)/efsfs.c -lfuse3 -lpthread
endef

define Package/efsfs/conffiles
/etc/config/efsfs
endef

define Package/efsfs/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/efsfs $(1)/usr/sbin/
	$(LN) efsfs $(1)/usr/sbin/mount.fuse.efsfs
	$(INSTALL_BIN) ./files/efsfs.init $(1)/etc/init.d/efsfs
	$(INSTALL_CONF) ./files/efsfs.config $(1)/etc/config/efsfs
endef

$(eval $(call BuildPackage,efsfs))
