# SPDX-License-Identifier: GPL-2.0-only
#
# qtestsign: wraps ELF firmware in the Qualcomm MBN format with a dummy
# ("test") certificate chain. Only useful on devices with firmware secure
# boot disabled. Host tool for qhypstub and U-Boot.

include $(TOPDIR)/rules.mk

PKG_NAME:=qtestsign
PKG_VERSION:=2026.04.05
PKG_RELEASE:=1

PKG_SOURCE_VERSION:=0eef3b552b1ada848f22bad38ab2e40407307c5b
PKG_SOURCE:=$(PKG_NAME)-$(PKG_SOURCE_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/msm8916-mainline/qtestsign/tar.gz/$(PKG_SOURCE_VERSION)?
PKG_HASH:=db7f184dc65c19790f091eccd2291fff14145b3a7c0dd35a88309d08f9418527

PKG_LICENSE:=GPL-2.0-only
PKG_LICENSE_FILES:=COPYING
PKG_HOST_ONLY:=1

HOST_BUILD_DIR:=$(BUILD_DIR_HOST)/$(PKG_NAME)-$(PKG_SOURCE_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/host-build.mk

define Package/qtestsign
  SECTION:=boot
  CATEGORY:=Boot Loaders
  TITLE:=Qualcomm MBN test signing tool
  URL:=https://github.com/msm8916-mainline/qtestsign
  BUILDONLY:=1
endef

$(eval $(call TestHostCommand,python3-cryptography, \
  Please install the Python3 cryptography module, \
  $(STAGING_DIR_HOST)/bin/python3 -c 'import cryptography'))

define Host/Compile
endef

define Host/Install
	$(INSTALL_DIR) $(STAGING_DIR_HOST)/lib/qtestsign/mbn $(STAGING_DIR_HOST)/bin
	$(INSTALL_DATA) $(HOST_BUILD_DIR)/qtestsign.py $(STAGING_DIR_HOST)/lib/qtestsign/
	$(INSTALL_DATA) $(HOST_BUILD_DIR)/mbn/*.py $(STAGING_DIR_HOST)/lib/qtestsign/mbn/
	( echo '#!/bin/sh'; \
	  echo 'exec $(STAGING_DIR_HOST)/bin/python3 $(STAGING_DIR_HOST)/lib/qtestsign/qtestsign.py "$$$$@"' \
	) > $(STAGING_DIR_HOST)/bin/qtestsign
	chmod 755 $(STAGING_DIR_HOST)/bin/qtestsign
endef

define Host/Clean
	rm -rf $(STAGING_DIR_HOST)/lib/qtestsign $(STAGING_DIR_HOST)/bin/qtestsign
endef

$(eval $(call BuildPackage,qtestsign))
$(eval $(call HostBuild))
