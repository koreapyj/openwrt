# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/image.mk

# per-device values used inside Build/* recipes (otherwise the last device's value leaks into all)
DEVICE_VARS += EDL_SECTOR_SIZE EDL_DISK_SECTORS EDL_GPT EDL_SBL1 EDL_RPM

# EDL (firehose) installer for a device that still runs the stock firmware:
# GPT (generated from the per-device layout in gpt/, primary + backup), tz, hyp, aboot,
# optionally sbl1 + rpm, boot.itb, recovery.itb (OpenWrt initramfs), userdata.img and a
# rawprogram0.xml / empty patch0.xml.
# Per-device values: EDL_GPT (layout file in gpt/), EDL_DISK_SECTORS, EDL_SECTOR_SIZE
# (default 512), and EDL_SBL1/EDL_RPM (file names in $(STAGING_DIR_IMAGE); leave unset to
# keep the stock sbl1/rpm). Blobs come from the db410c-bootloader, qhypstub and
# uboot-msm89xx packages (aboot = u-boot-$(DEVICE_NAME).mbn). $@ is the userdata image (rootfs,
# padded, + 1M zero tail) when this step runs.
EDL_SECTOR_SIZE_ = $(if $(EDL_SECTOR_SIZE),$(EDL_SECTOR_SIZE),512)

define Build/edl-package
	$(if $(EDL_GPT),,$(error $(DEVICE_NAME): EDL_GPT not set))
	$(if $(EDL_DISK_SECTORS),,$(error $(DEVICE_NAME): EDL_DISK_SECTORS not set))
	rm -rf $@.edl; mkdir -p $@.edl
	$(PYTHON) $(TOPDIR)/target/linux/$(BOARD)/image/edl-gpt.py \
		$(TOPDIR)/target/linux/$(BOARD)/image/gpt/$(EDL_GPT) $(EDL_DISK_SECTORS) $@.edl
	$(CP) $(STAGING_DIR_IMAGE)/db410c-tz.mbn $@.edl/tz.mbn
	$(CP) $(STAGING_DIR_IMAGE)/qhypstub.mbn $@.edl/hyp.mbn
	$(CP) $(STAGING_DIR_IMAGE)/u-boot-$(DEVICE_NAME).mbn $@.edl/aboot.mbn
	$(CP) $(STAGING_DIR_IMAGE)/db410c-LICENSE.txt $@.edl/LICENSE.db410c-bootloader.txt
	$(if $(EDL_SBL1),$(CP) $(STAGING_DIR_IMAGE)/$(EDL_SBL1) $@.edl/sbl1.mbn)
	$(if $(EDL_RPM),$(CP) $(STAGING_DIR_IMAGE)/$(EDL_RPM) $@.edl/rpm.mbn)
	cp $(IMAGE_KERNEL) $@.edl/boot.itb
	cp $(BIN_DIR)/$(KERNEL_INITRAMFS_IMAGE) $@.edl/recovery.itb
	cp $@ $@.edl/userdata.img
	sh $(TOPDIR)/target/linux/$(BOARD)/image/edl-rawprogram.sh $@.edl $(EDL_SECTOR_SIZE_) \
		$(TOPDIR)/target/linux/$(BOARD)/image/gpt/$(EDL_GPT) $(EDL_DISK_SECTORS) \
		$(if $(EDL_SBL1),sbl1.mbn sbl1) $(if $(EDL_RPM),rpm.mbn rpm) \
		tz.mbn tz hyp.mbn hyp aboot.mbn aboot boot.itb boot recovery.itb recovery userdata.img userdata
	tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@$(SOURCE_DATE_EPOCH) \
		-C $@.edl -cf - $(if $(EDL_SBL1),sbl1.mbn) $(if $(EDL_RPM),rpm.mbn) \
		tz.mbn hyp.mbn aboot.mbn boot.itb recovery.itb userdata.img gpt_primary.bin gpt_backup.bin \
		LICENSE.db410c-bootloader.txt rawprogram0.xml patch0.xml | gzip -n -9 > $@.tgz
	mv $@.tgz $@
	rm -rf $@.edl
endef

define Device/Default
	PROFILES := Default
	DEVICE_DTS_DIR := $(DTS_DIR)/qcom
	KERNEL_NAME := Image
	# FIT images booted by U-Boot (package/boot/uboot-msm89xx): gzip kernel + DTB, kernel at
	# 0x80080000, command line set by the U-Boot environment. boot (production) lives in the
	# GPT partition labelled boot, rootfs (squashfs + overlay) in the one labelled userdata.
	# recovery: the initramfs kernel (rootfs built in) in the GPT partition labelled recovery
	# that U-Boot boots on a button press or after a panic; both partitions are 16 MiB.
	KERNEL_LOADADDR := 0x80080000
	KERNEL_SUFFIX := -boot.itb
	KERNEL = kernel-bin | libdeflate-gzip | \
		fit gzip $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb | pad-to 4k | check-size 16m
	KERNEL_INITRAMFS_SUFFIX := -recovery.itb
	KERNEL_INITRAMFS = kernel-bin | libdeflate-gzip | \
		fit gzip $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb | pad-to 4k | check-size 16m
	IMAGES := boot.itb rootfs.img sysupgrade.bin
	IMAGE/boot.itb := append-kernel
	IMAGE/rootfs.img := append-rootfs | pad-to 64k | pad-extra 1M
	IMAGE/sysupgrade.bin := append-rootfs | pad-to 64k | sysupgrade-tar rootfs=$$$$@ | append-metadata
	IMAGE/edl.tar.gz := append-rootfs | pad-to 64k | pad-extra 1M | edl-package
endef

include $(SUBTARGET).mk

$(eval $(call BuildImage))
