KERNEL_LOADADDR := 0x40008000

define Device/mediatek_mt7629-rfb
  DEVICE_VENDOR := MediaTek
  DEVICE_MODEL := MT7629 rfb AP
  DEVICE_DTS := mt7629-rfb
  DEVICE_PACKAGES := swconfig
endef
TARGET_DEVICES += mediatek_mt7629-rfb

define Device/iptime_a6004mx
  DEVICE_VENDOR := ipTIME
  DEVICE_MODEL := A6004MX
  DEVICE_DTS := mt7629-iptime-a6004mx
  DEVICE_DTS_DIR := $(DTS_DIR)/mediatek
  SUPPORTED_DEVICES := iptime,a6004mx
  UBINIZE_OPTS := -E 5
  KERNEL_LOADADDR := 0x40008000
  BLOCKSIZE := 128k
  PAGESIZE := 2048
  KERNEL_SIZE := 4096k
  IMAGE_SIZE := 32768k
  IMAGES += factory.bin
  IMAGE/sysupgrade.bin := sysupgrade-tar | append-metadata
  IMAGE/factory.bin := append-kernel | pad-to $$$$(KERNEL_SIZE) | append-ubi | \
	check-size | iptime-crc32 a6004mx
  DEVICE_PACKAGES := kmod-usb-ohci kmod-usb2 kmod-usb3 swconfig
endef
TARGET_DEVICES += iptime_a6004mx
