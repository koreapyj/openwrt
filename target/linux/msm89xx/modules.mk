define KernelPackage/btqcomsmd
  SUBMENU:=$(BLUETOOTH_MENU)
  TITLE:=Qualcomm WCNSS SMD Bluetooth HCI support
  DEPENDS:=@TARGET_msm89xx +kmod-bluetooth
  KCONFIG:=CONFIG_BT_QCOMSMD CONFIG_BT_QCA
  FILES:= \
	$(LINUX_DIR)/drivers/bluetooth/btqca.ko \
	$(LINUX_DIR)/drivers/bluetooth/btqcomsmd.ko
  AUTOLOAD:=$(call AutoProbe,btqca btqcomsmd)
endef

define KernelPackage/btqcomsmd/description
 Kernel support for the Bluetooth controller of Qualcomm WCNSS (WCN36xx)
 on MSM8916/MSM8909 class SoCs, attached through SMD channels
endef

$(eval $(call KernelPackage,btqcomsmd))

define KernelPackage/qcom-apr
  TITLE:=Qualcomm APR (Asynchronous Packet Router) bus
  DEPENDS:=@TARGET_msm89xx +kmod-qrtr
  KCONFIG:= \
	CONFIG_QCOM_APR \
	CONFIG_QCOM_PDR_HELPERS
  FILES:= \
	$(LINUX_DIR)/drivers/soc/qcom/apr.ko \
	$(LINUX_DIR)/drivers/soc/qcom/qcom_pdr_msg.ko \
	$(LINUX_DIR)/drivers/soc/qcom/pdr_interface.ko
  AUTOLOAD:=$(call AutoProbe,qcom_pdr_msg pdr_interface apr)
endef

define KernelPackage/qcom-apr/description
 APR bus between the application processor and the QDSP6 (modem
 firmware on MSM8916) over the SMD "apr_audio_svc" channel
endef

$(eval $(call KernelPackage,qcom-apr))

define KernelPackage/sound-soc-qdsp6
  SUBMENU:=$(SOUND_MENU)
  TITLE:=Qualcomm QDSP6 (q6core/q6afe/...) ASoC drivers
  DEPENDS:=@TARGET_msm89xx +kmod-qcom-apr +kmod-sound-soc-core
  KCONFIG:= \
	CONFIG_SND_SOC_QCOM \
	CONFIG_SND_SOC_QDSP6
  FILES:= \
	$(LINUX_DIR)/sound/soc/qcom/qdsp6/snd-q6dsp-common.ko \
	$(LINUX_DIR)/sound/soc/qcom/qdsp6/q6core.ko \
	$(LINUX_DIR)/sound/soc/qcom/qdsp6/q6afe.ko \
	$(LINUX_DIR)/sound/soc/qcom/qdsp6/q6afe-dai.ko \
	$(LINUX_DIR)/sound/soc/qcom/qdsp6/q6afe-clocks.ko
  AUTOLOAD:=$(call AutoProbe,snd-q6dsp-common q6core q6afe q6afe-dai q6afe-clocks)
endef

define KernelPackage/sound-soc-qdsp6/description
 Qualcomm QDSP6 audio services (APR core and AFE) used to reach the
 modem DSP; no sound card is registered by these modules
endef

$(eval $(call KernelPackage,sound-soc-qdsp6))

define KernelPackage/sound-soc-qdsp6-voice
  SUBMENU:=$(SOUND_MENU)
  TITLE:=Qualcomm QDSP6 voice (q6mvm/q6cvs/q6cvp/q6voice) ASoC drivers
  DEPENDS:=@TARGET_msm89xx +kmod-sound-soc-qdsp6
  KCONFIG:= \
	CONFIG_SND_SOC_QDSP6_Q6VOICE \
	CONFIG_SND_SOC_QDSP6_Q6VOICE_DAI
  FILES:= \
	$(LINUX_DIR)/sound/soc/qcom/qdsp6/q6voice-common.ko \
	$(LINUX_DIR)/sound/soc/qcom/qdsp6/q6mvm.ko \
	$(LINUX_DIR)/sound/soc/qcom/qdsp6/q6cvs.ko \
	$(LINUX_DIR)/sound/soc/qcom/qdsp6/q6cvp.ko \
	$(LINUX_DIR)/sound/soc/qcom/qdsp6/q6voice.ko \
	$(LINUX_DIR)/sound/soc/qcom/qdsp6/q6voice-dai.ko
  AUTOLOAD:=$(call AutoProbe,q6voice-common q6mvm q6cvs q6cvp q6voice q6voice-dai)
endef

define KernelPackage/sound-soc-qdsp6-voice/description
 Qualcomm QDSP6 voice call services (MVM, CVS, CVP) and the q6voice
 session manager with selectable AFE ports. Binding sends no DSP
 command; voice sessions are created only on request.
endef

$(eval $(call KernelPackage,sound-soc-qdsp6-voice))

define KernelPackage/sound-soc-qdsp6-rtproxy
  SUBMENU:=$(SOUND_MENU)
  TITLE:=Qualcomm QDSP6 CS voice call audio sound card (AFE RT proxy ports)
  DEPENDS:=@TARGET_msm89xx +kmod-sound-soc-qdsp6 +kmod-sound-soc-qdsp6-voice
  KCONFIG:=CONFIG_SND_SOC_QDSP6_AFE_RTPROXY_PCM
  FILES:= \
	$(LINUX_DIR)/sound/soc/qcom/qdsp6/q6afe-rtproxy-pcm.ko \
	$(LINUX_DIR)/sound/soc/qcom/qdsp6/q6afe-rtproxy-card.ko
  AUTOLOAD:=$(call AutoProbe,q6afe-rtproxy-pcm q6afe-rtproxy-card)
endef

define KernelPackage/sound-soc-qdsp6-rtproxy/description
 ALSA sound card "MSM8916 Voice" for circuit switched voice calls: capture
 is the call downlink, playback the call uplink, carried by the QDSP6 AFE
 real-time proxy ports (no codec/LPASS hardware). The call path is started
 while a PCM stream is open.
endef

$(eval $(call KernelPackage,sound-soc-qdsp6-rtproxy))
