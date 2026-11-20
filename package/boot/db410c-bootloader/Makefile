# SPDX-License-Identifier: GPL-2.0-only
#
# Qualcomm boot firmware (tz, sbl1, rpm) from the Linaro DragonBoard 410c
# bootloader release. Redistributable in binary form only, under the license
# in the archive; the license text must accompany every redistribution (it is
# packed into the EDL installer next to the blobs).

include $(TOPDIR)/rules.mk

PKG_NAME:=db410c-bootloader
PKG_VERSION:=176
PKG_RELEASE:=1

PKG_SOURCE:=dragonboard-410c-bootloader-emmc-linux-$(PKG_VERSION).zip
# Linaro's own servers are gone; boardport/linaro-releases archives the original file
PKG_SOURCE_URL:=https://github.com/boardport/linaro-releases/releases/download/db410c-rescue-21.12/
PKG_HASH:=a37c4e82a970ae2350fcfc7180559caf1dc3928e7c169316fe4ab899b7d305ad

PKG_LICENSE:=Proprietary
PKG_LICENSE_FILES:=LICENSE

# the archive carries its own top-level directory
PKG_BUILD_DIR:=$(BUILD_DIR)/dragonboard-410c-bootloader-emmc-linux-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

MSM8916_BOOT_DEVICES:=generic_ufi-esim yiming_uz801-v3

define Package/db410c-bootloader
  SECTION:=boot
  CATEGORY:=Boot Loaders
  TITLE:=Qualcomm MSM8916 tz, sbl1 and rpm firmware (DragonBoard 410c release 176)
  URL:=https://www.96boards.org/documentation/consumer/dragonboard/dragonboard410c/
  DEPENDS:=@TARGET_msm89xx
  DEFAULT:=y if (TARGET_msm89xx_msm8916_Default \
	$(patsubst %,|| TARGET_msm89xx_msm8916_DEVICE_%,$(MSM8916_BOOT_DEVICES)) \
	$(patsubst %,|| TARGET_DEVICE_msm89xx_msm8916_DEVICE_%,$(MSM8916_BOOT_DEVICES)))
endef

define Package/db410c-bootloader/description
 TZ.BF.3.0 trustzone, BOOT.BF.3.0 sbl1 and RPM.BF.2.0 rpm images. Only handed
 to the image build (staging_dir/image); nothing is installed on the device.
endef

define Build/Compile
endef

define Package/db410c-bootloader/install
	$(INSTALL_DIR) $(STAGING_DIR_IMAGE)
	$(foreach f,tz sbl1 rpm, \
		$(INSTALL_DATA) $(PKG_BUILD_DIR)/$(f).mbn \
			$(STAGING_DIR_IMAGE)/db410c-$(f).mbn;)
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/LICENSE \
		$(STAGING_DIR_IMAGE)/db410c-LICENSE.txt
endef

$(eval $(call BuildPackage,db410c-bootloader))
