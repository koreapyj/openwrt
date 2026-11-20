# SPDX-License-Identifier: GPL-2.0-only

define Device/generic_ufi-esim
	DEVICE_VENDOR := Generic
	DEVICE_MODEL := UFI 4G Modem Stick
	DEVICE_VARIANT := eSIM
	SOC := msm8916
	DEVICE_DTS := msm8916-ufi-esim
	# stock partition layout is kept (tz grown over tzbak); rootfs (squashfs + overlay) lives in
	# the stock userdata partition (p28). Stock sbl1/rpm are kept (no EDL_SBL1/EDL_RPM).
	EDL_GPT := generic_ufi-esim.gpt
	EDL_DISK_SECTORS := 7634944
	IMAGES += edl.tar.gz
	DEVICE_PACKAGES := \
		rmtfs qrtr-tools kmod-qcom-apr kmod-sound-soc-qdsp6 kmod-sound-soc-qdsp6-voice kmod-sound-soc-qdsp6-rtproxy \
		uqmi uqmid luci-proto-qmi kmod-wcn36xx kmod-btqcomsmd wpad-basic-mbedtls \
		usbgadget kmod-usb-gadget-ncm kmod-usb-gadget-serial \
		uboot-envtools
endef
TARGET_DEVICES += generic_ufi-esim
