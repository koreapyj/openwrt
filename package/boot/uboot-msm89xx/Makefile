# SPDX-License-Identifier: GPL-2.0-only
#
# Mainline U-Boot as the aboot for the MSM8916 4G modem sticks.
#
# It lives in the aboot partition: SBL loads the 64-bit ELF, tz
# starts it and qhypstub (the hyp replacement) hands over in EL2, so the kernel
# is started in EL2 as well. U-Boot boots a FIT image (kernel + DTB) from the
# "boot" partition (see the built-in environment). Based on the
# dragonboard410c port (aboot ELF, test-signed with qtestsign), same as the
# upstream doc/board/qualcomm/dragonboard410c.rst.
#
# The signed image is only handed to the image build (staging_dir/image) as
# u-boot-<device>.mbn, nothing is installed on the device.

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_VERSION:=2025.10
PKG_HASH:=b4f032848e56cc8f213ad59f9132c084dbbb632bc29176d024e58220e0efdf4a
PKG_BUILD_DEPENDS:=qtestsign/host

include $(INCLUDE_DIR)/u-boot.mk
include $(INCLUDE_DIR)/package.mk

define U-Boot/Default
  BUILD_TARGET:=msm89xx
  BUILD_SUBTARGET:=msm8916
  UBOOT_IMAGE:=u-boot.elf
endef

# dragonboard410c_defconfig + the common msm89xx-openwrt.config fragment + a
# per-device fragment (default devicetree), all in configs/ via patches
define U-Boot/generic_ufi-esim
  NAME:=UFI 4G Modem Stick (eSIM)
  BUILD_DEVICES:=generic_ufi-esim
  UBOOT_CONFIG:=dragonboard410c msm89xx-openwrt msm89xx-ufi-esim
endef

define U-Boot/yiming_uz801-v3
  NAME:=Yiming UZ801 v3
  BUILD_DEVICES:=yiming_uz801-v3
  UBOOT_CONFIG:=dragonboard410c msm89xx-openwrt msm89xx-yiming-uz801-v3
endef

UBOOT_TARGETS := \
	generic_ufi-esim \
	yiming_uz801-v3

UBOOT_CUSTOMIZE_CONFIG := \
	--disable TOOLS_KWBIMAGE \
	--disable TOOLS_LIBCRYPTO \
	--disable TOOLS_MKEFICAPSULE

# The ELF is wrapped in the Qualcomm MBN format with a dummy certificate chain,
# the firmware refuses a bare ELF in aboot. Only useful on devices with
# firmware secure boot disabled (same prerequisite as qhypstub).
define Build/Compile
	$(call Build/Compile/U-Boot)
	$(STAGING_DIR_HOST)/bin/qtestsign aboot -o $(PKG_BUILD_DIR)/u-boot.mbn \
		$(PKG_BUILD_DIR)/u-boot.elf
endef

# nothing is installed on the device
define Package/u-boot/install
endef

define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR_IMAGE)
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/u-boot.mbn \
		$(STAGING_DIR_IMAGE)/u-boot-$(BUILD_VARIANT).mbn
endef

$(eval $(call BuildPackage/U-Boot))
