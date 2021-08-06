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
  DEVICE_PACKAGES := swconfig
endef
TARGET_DEVICES += iptime_a6004mx
