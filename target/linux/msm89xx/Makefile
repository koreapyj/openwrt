# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk

ARCH:=aarch64
BOARD:=msm89xx
BOARDNAME:=Qualcomm MSM89xx
FEATURES:=squashfs ext4 emmc fpu ramdisk rtc usb usbgadget
KERNELNAME:=Image
CPU_TYPE:=cortex-a53
SUBTARGETS:=msm8916

KERNEL_PATCHVER:=6.12

include $(INCLUDE_DIR)/target.mk

DEFAULT_PACKAGES += \
	kmod-leds-gpio kmod-gpio-button-hotplug \
	e2fsprogs kmod-fs-ext4 losetup \
	mkf2fs kmod-fs-f2fs

$(eval $(call BuildTarget))
