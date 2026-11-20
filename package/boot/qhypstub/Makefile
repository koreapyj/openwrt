# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk

PKG_NAME:=qhypstub
PKG_VERSION:=2022.10.15
PKG_RELEASE:=1

PKG_SOURCE_VERSION:=fca3c513b6fb5e5b8fabae21dac1f4a5c0b51bc6
PKG_SOURCE:=$(PKG_NAME)-$(PKG_SOURCE_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/msm8916-mainline/qhypstub/tar.gz/$(PKG_SOURCE_VERSION)?
PKG_HASH:=74714184809686ed31bd8e2232fa7889d30c39fce5ee623a9d563814065c54d2

PKG_LICENSE:=GPL-2.0-only
PKG_LICENSE_FILES:=COPYING

PKG_BUILD_DEPENDS:=qtestsign/host
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_SOURCE_VERSION)
PKG_FLAGS:=nonshared

include $(INCLUDE_DIR)/package.mk

MSM8916_BOOT_DEVICES:=generic_ufi-esim

define Package/qhypstub
  SECTION:=boot
  CATEGORY:=Boot Loaders
  TITLE:=Minimal hypervisor stub for MSM8916 (test-signed hyp image)
  URL:=https://github.com/msm8916-mainline/qhypstub
  DEPENDS:=@TARGET_msm89xx
  DEFAULT:=y if (TARGET_msm89xx_msm8916_Default \
	$(patsubst %,|| TARGET_msm89xx_msm8916_DEVICE_%,$(MSM8916_BOOT_DEVICES)) \
	$(patsubst %,|| TARGET_DEVICE_msm89xx_msm8916_DEVICE_%,$(MSM8916_BOOT_DEVICES)))
endef

define Package/qhypstub/description
 Replaces the Qualcomm hypervisor on MSM8916 so that the 64-bit kernel can be
 started in EL2. The image is only test-signed and works on devices with
 firmware secure boot disabled. It is not installed on the device by the
 firmware image; it is written to the hyp partition by the EDL installer.
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		AS="$(TARGET_CROSS)as" LD="$(TARGET_CROSS)ld" OBJCOPY="$(TARGET_CROSS)objcopy" \
		qhypstub.elf
	$(STAGING_DIR_HOST)/bin/qtestsign hyp -o $(PKG_BUILD_DIR)/qhypstub.mbn \
		$(PKG_BUILD_DIR)/qhypstub.elf
endef

define Package/qhypstub/install
	$(INSTALL_DIR) $(STAGING_DIR_IMAGE)
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/qhypstub.mbn $(STAGING_DIR_IMAGE)/qhypstub.mbn
endef

$(eval $(call BuildPackage,qhypstub))
