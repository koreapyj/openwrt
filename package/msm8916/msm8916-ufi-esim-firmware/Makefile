# SPDX-License-Identifier: GPL-2.0-only
#
# Proprietary Qualcomm modem/WiFi firmware for the MSM8916 "UFI eSIM" LTE stick.
# The files are taken from the device's own stock firmware and are NOT part of
# this tree; they are read from $(MSM8916_FIRMWARE_DIR) at build time and must
# never be committed or redistributed.

include $(TOPDIR)/rules.mk

PKG_NAME:=msm8916-ufi-esim-firmware
PKG_RELEASE:=1
PKG_LICENSE:=Proprietary

include $(INCLUDE_DIR)/package.mk

MSM8916_FIRMWARE_DIR ?= $(HOME)/msm8916-firmware

define Package/msm8916-ufi-esim-firmware
  SECTION:=firmware
  CATEGORY:=Firmware
  TITLE:=MSM8916 UFI eSIM modem (MPSS) and WCNSS firmware (local, proprietary)
  DEPENDS:=@TARGET_msm89xx
endef

define Package/msm8916-ufi-esim-firmware/description
 Modem (mba/modem.*), WCNSS (wcnss.*) and WCNSS NV calibration for the
 MSM8916 UFI eSIM stick, copied from the device's stock firmware at build time.
endef

define Build/Prepare
	@[ -f "$(MSM8916_FIRMWARE_DIR)/modem.mdt" ] || { \
		echo "ERROR: firmware not found in $(MSM8916_FIRMWARE_DIR)"; exit 1; }
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Compile
endef

define Package/msm8916-ufi-esim-firmware/install
	$(INSTALL_DIR) $(1)/lib/firmware $(1)/lib/firmware/wlan/prima
	$(INSTALL_DATA) $(MSM8916_FIRMWARE_DIR)/mba.mbn $(1)/lib/firmware/
	$(INSTALL_DATA) $(MSM8916_FIRMWARE_DIR)/modem.mdt $(MSM8916_FIRMWARE_DIR)/modem.b* $(1)/lib/firmware/
	$(INSTALL_DATA) $(MSM8916_FIRMWARE_DIR)/wcnss.mdt $(MSM8916_FIRMWARE_DIR)/wcnss.b* $(1)/lib/firmware/
	$(INSTALL_DATA) $(MSM8916_FIRMWARE_DIR)/wlan/prima/WCNSS_qcom_wlan_nv.bin $(1)/lib/firmware/wlan/prima/
endef

$(eval $(call BuildPackage,msm8916-ufi-esim-firmware))
