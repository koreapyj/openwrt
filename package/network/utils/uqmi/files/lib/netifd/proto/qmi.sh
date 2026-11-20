#!/bin/sh

[ -n "$INCLUDE_ONLY" ] || {
	. /lib/functions.sh
	. ../netifd-proto.sh
	init_proto "$@"
}

proto_qmi_init_config() {
	available=1
	no_device=1
	proto_config_add_string "device:device"
	proto_config_add_string apn
	proto_config_add_string v6apn
	proto_config_add_string auth
	proto_config_add_string username
	proto_config_add_string password
	proto_config_add_string pincode
	proto_config_add_int delay
	proto_config_add_string modes
	proto_config_add_string pdptype
	proto_config_add_int profile
	proto_config_add_int v6profile
	proto_config_add_string devpath
	proto_config_add_string netdev
	proto_config_add_string dataport
	proto_config_add_boolean dhcp
	proto_config_add_boolean dhcpv6
	proto_config_add_boolean sourcefilter
	proto_config_add_boolean delegate
	proto_config_add_boolean autoconnect
	proto_config_add_int plmn
	proto_config_add_boolean allow_roaming
	proto_config_add_int timeout
	proto_config_add_int mtu
	proto_config_add_defaults
}

proto_qmi_setup() {
	local interface="$1"

	local connstat dataformat mcc mnc plmn_mode
	local cid_4 cid_6 pdh_4 pdh_6
	local dns1_6 dns2_6 gateway_6 ip_6 ip_prefix_length
	local profile_pdptype

	local delegate ip4table ip6table mtu sourcefilter $PROTO_DEFAULT_OPTIONS
	json_get_vars delegate ip4table ip6table mtu sourcefilter $PROTO_DEFAULT_OPTIONS

	local apn auth delay device modes password pdptype pincode username v6apn
	json_get_vars apn auth delay device modes password pdptype pincode username v6apn

	local profile v6profile devpath netdev dataport dhcp dhcpv6 autoconnect plmn timeout allow_roaming
	json_get_vars profile v6profile devpath netdev dataport dhcp dhcpv6 autoconnect plmn timeout allow_roaming

	[ "$timeout" = "" ] && timeout="10"

	[ "$metric" = "" ] && metric="0"

	[ -n "$ctl_device" ] && device=$ctl_device

	if [ -n "$devpath" ]; then
		local usbmisc_or_wwan_path
		# For usbmisc:
		# /sys/devices/platform/1e1c0000.xhci/usb1/1-2/1-2:1.4/usbmisc/cdc-wdm0
		# Numbers after ":" are the configuration and interface number
		# of the connected modem. There can be multiple interfaces but
		# there will only be a single interface that provides the
		# control channel device. Therefore, check also /*/usbmisc to
		# allow specifying the USB port number the modem is directly
		# connected to.
		# For wwan:
		# /sys/devices/platform/soc/11280000.pcie/pci0003:00/0003:00:00.0/0003:01:00.0/wwan/wwan0/wwan0qmi0
		# /sys/devices/platform/soc/11280000.pcie/pci0003:00/0003:00:00.0/0003:01:00.0/mhi0/wwan/wwan0/wwan0qmi0
		for usbmisc_or_wwan_path in \
		    "$devpath"/usbmisc/cdc-wdm* \
		    "$devpath"/*/usbmisc/cdc-wdm* \
		    "$devpath"/*/wwan[0-9]*/wwan[0-9]*qmi* \
		    "$devpath"/*/*/wwan[0-9]*/wwan[0-9]*qmi*; do
			[ ! -e "$usbmisc_or_wwan_path" ] && continue
			device="/dev/${usbmisc_or_wwan_path##*/}"
			break
		done
	fi

	[ -n "$device" ] || {
		echo "No control device specified"
		proto_notify_error "$interface" NO_DEVICE
		proto_set_available "$interface" 0
		return 1
	}

	[ -n "$delay" ] && sleep "$delay"

	device="$(readlink -f $device)"
	[ -c "$device" ] || {
		echo "The specified control device does not exist"
		proto_notify_error "$interface" NO_DEVICE
		proto_set_available "$interface" 0
		return 1
	}

	devname="$(basename "$device")"
	if [ -n "$netdev" ]; then
		ifname="$netdev"
	elif [ -e "/sys/class/usbmisc/$devname" ]; then
		devpath="$(readlink -f /sys/class/usbmisc/$devname/device/)"
		ifname="$( ls "$devpath"/net )"
	elif [ -e "/sys/class/wwan/$devname" ]; then
		# WWAN subsystem port (e.g. SoC-integrated modems): the data
		# netdevs are not children of the port, but live below the
		# same parent device as the wwan device the port belongs to.
		# Prefer the first data channel (dev_port 0).
		local wwanparent net first
		wwanparent="$(readlink -f "/sys/class/wwan/$devname/../device")"
		for net in /sys/class/net/*; do
			case "$(readlink -f "$net/device" 2>/dev/null)/" in
			"$wwanparent"/*)
				[ "$(cat "$net/dev_port" 2>/dev/null)" = "0" ] && {
					ifname="${net##*/}"
					break
				}
				: "${first:=${net##*/}}"
				;;
			esac
		done
		: "${ifname:=$first}"
	fi
	[ -n "$ifname" ] && [ -e "/sys/class/net/$ifname" ] || {
		echo "The interface could not be found."
		proto_notify_error "$interface" NO_IFACE
		proto_set_available "$interface" 0
		return 1
	}

	# BAM-DMUX (SoC-integrated modems): one netdev per channel, the
	# channel index is exposed as dev_port. WDS clients must be bound
	# to the matching SIO data port (A2 MUX RMNET<n>).
	[ -z "$dataport" ] &&
	[ "$(basename "$(readlink -f "/sys/class/net/$ifname/device/driver")")" = "bam-dmux" ] &&
		dataport="a2-mux-rmnet$(cat "/sys/class/net/$ifname/dev_port")"
	[ "$dataport" = "none" ] && dataport=

	[ -n "$mtu" ] && {
		echo "Setting MTU to $mtu"
		/sbin/ip link set dev $ifname mtu $mtu
	}

	echo "Waiting for SIM initialization"
	local uninitialized_timeout=0
	# timeout 3s for first call to avoid hanging uqmi
	uqmi -d "$device" -t 3000 --get-pin-status > /dev/null 2>&1
	while uqmi -s -d "$device" -t 1000 --get-pin-status | grep '"UIM uninitialized"' > /dev/null; do
		[ -e "$device" ] || return 1
		if [ "$uninitialized_timeout" -lt "$timeout" -o "$timeout" = "0" ]; then
			let uninitialized_timeout++
			sleep 1;
		else
			echo "SIM not initialized"
			proto_notify_error "$interface" SIM_NOT_INITIALIZED
			proto_block_restart "$interface"
			return 1
		fi
	done

	# Check if UIM application is stuck in illegal state
	local uim_state_timeout=0
	while true; do
		json_load "$(uqmi -s -d "$device" -t 2000 --uim-get-sim-state)"
		json_get_var card_application_state card_application_state

		# SIM card is either completely absent or state is labeled as illegal
		# Try to power-cycle the SIM card to recover from this state
		if [ -z "$card_application_state" -o "$card_application_state" = "illegal" ]; then
			echo "SIM in illegal state - Power-cycling SIM"

			# Try to reset SIM application
			# uqmi reads --uim-slot when the action is queued, so it must come first
			uqmi -d "$device" -t 1000 --uim-slot 1 --uim-power-off
			sleep 3
			uqmi -d "$device" -t 1000 --uim-slot 1 --uim-power-on

			if [ "$uim_state_timeout" -lt "$timeout" ] || [ "$timeout" = "0" ]; then
				let uim_state_timeout++
				sleep 5
				continue
			fi

			# Recovery failed
			proto_notify_error "$interface" SIM_ILLEGAL_STATE
			proto_block_restart "$interface"
			return 1
		else
			break
		fi
	done

	if uqmi -s -d "$device" -t 1000 --uim-get-sim-state | grep -q '"Not supported"\|"Invalid QMI command"' &&
	   uqmi -s -d "$device" -t 1000 --get-pin-status | grep -q '"Not supported"\|"Invalid QMI command"' ; then
		[ -n "$pincode" ] && {
			uqmi -s -d "$device" -t 1000 --verify-pin1 "$pincode" > /dev/null || uqmi -s -d "$device" -t 1000 --uim-verify-pin1 "$pincode" > /dev/null || {
				echo "Unable to verify PIN"
				proto_notify_error "$interface" PIN_FAILED
				proto_block_restart "$interface"
				return 1
			}
		}
	else
		json_load "$(uqmi -s -d "$device" -t 1000 --get-pin-status)"
		json_get_var pin1_status pin1_status
		if [ -z "$pin1_status" ]; then
			json_load "$(uqmi -s -d "$device" -t 1000 --uim-get-sim-state)"
			json_get_var pin1_status pin1_status
		fi
		json_get_var pin1_verify_tries pin1_verify_tries

		case "$pin1_status" in
			disabled)
				echo "PIN verification is disabled"
				;;
			blocked)
				echo "SIM locked PUK required"
				proto_notify_error "$interface" PUK_NEEDED
				proto_block_restart "$interface"
				return 1
				;;
			not_verified)
				[ "$pin1_verify_tries" -lt "3" ] && {
					echo "PIN verify count value is $pin1_verify_tries this is below the limit of 3"
					proto_notify_error "$interface" PIN_TRIES_BELOW_LIMIT
					proto_block_restart "$interface"
					return 1
				}
				if [ -n "$pincode" ]; then
					uqmi -s -d "$device" -t 1000 --verify-pin1 "$pincode" > /dev/null 2>&1 || uqmi -s -d "$device" -t 1000 --uim-verify-pin1 "$pincode" > /dev/null 2>&1 || {
						echo "Unable to verify PIN"
						proto_notify_error "$interface" PIN_FAILED
						proto_block_restart "$interface"
						return 1
					}
				else
					echo "PIN not specified but required"
					proto_notify_error "$interface" PIN_NOT_SPECIFIED
					proto_block_restart "$interface"
					return 1
				fi
				;;
			verified)
				echo "PIN already verified"
				;;
			*)
				echo "PIN status failed (${pin1_status:-sim_not_present})"
				proto_notify_error "$interface" PIN_STATUS_FAILED
				proto_block_restart "$interface"
				return 1
			;;
		esac
		json_cleanup
	fi

	if [ -n "$plmn" ]; then
		json_load "$(uqmi -s -d "$device" -t 1000 --get-plmn)"
		json_get_var plmn_mode mode
		json_get_vars mcc mnc || {
			mcc=0
			mnc=0
		}

		if [ "$plmn" = "0" ]; then
			if [ "$plmn_mode" != "automatic" ]; then
				mcc=0
				mnc=0
				echo "Setting PLMN to auto"
			fi
		elif [ "$mcc" -ne "${plmn:0:3}" -o "$mnc" -ne "${plmn:3}" ]; then
			mcc=${plmn:0:3}
			mnc=${plmn:3}
			echo "Setting PLMN to $plmn"
		else
			mcc=""
			mnc=""
		fi
	fi

	# Cleanup current state if any
	uqmi -s -d "$device" -t 1000 --stop-network 0xffffffff --autoconnect > /dev/null 2>&1
	uqmi -s -d "$device" -t 1000 --set-ip-family ipv6 --stop-network 0xffffffff --autoconnect > /dev/null 2>&1

	pdptype="$(echo "$pdptype" | awk '{print tolower($0)}')"

	[ "$pdptype" = "ip" -o "$pdptype" = "ipv6" -o "$pdptype" = "ipv4v6" ] || pdptype="ip"

	# Configure PDP type and APN for profile 1 before registering: on LTE
	# the modem attaches with it, so a stale APN (e.g. left by another SIM)
	# gets the attach rejected and registration never completes.
	# In case GGSN rejects IPv4v6 PDP, modem might not be able to
	# establish a non-LTE data session.
	profile_pdptype="$pdptype"
	[ "$profile_pdptype" = "ip" ] && profile_pdptype="ipv4"
	local profile_settings
	profile_settings="$(uqmi -s -d "$device" -t 1000 --get-profile-settings "3gpp,1")"
	if [ "$(echo "$profile_settings" | jsonfilter -e '@.apn')" != "$apn" ] ||
	   [ "$(echo "$profile_settings" | jsonfilter -e '@["pdp-type"]')" != "$profile_pdptype" ]; then
		echo "Setting APN '$apn' and PDP type $profile_pdptype for the attach profile"
		uqmi -s -d "$device" -t 1000 --modify-profile "3gpp,1" --apn "$apn" --pdp-type "$profile_pdptype" > /dev/null 2>&1
		# attach again with the new settings
		uqmi -s -d "$device" -t 1000 --set-device-operating-mode low_power > /dev/null 2>&1
		sleep 3
	fi

	# Go online
	uqmi -s -d "$device" -t 1000 --set-device-operating-mode online > /dev/null 2>&1

	# Set IP format
	if [ "$(cat /sys/class/net/$ifname/type 2>/dev/null)" = "519" ] &&
	   [ ! -d "/sys/class/net/$ifname/qmi" ]; then
		# ARPHRD_RAWIP netdev not driven by qmi_wwan (e.g. BAM-DMUX):
		# the data path only carries raw IP packets and there is no
		# driver attribute to switch. Modems without WDA service are
		# switched through CTL.
		local ctl_ok=0
		uqmi -s -d "$device" -t 1000 --set-data-format raw-ip > /dev/null 2>&1 && ctl_ok=1
		uqmi -s -d "$device" -t 1000 --wda-set-data-format raw-ip > /dev/null 2>&1
		json_load "$(uqmi -s -d "$device" -t 1000 --wda-get-data-format)"
		json_get_var dataformat link-layer-protocol
		# The CTL setting is what counts for BAM-DMUX, ignore WDA then
		[ "$ctl_ok" = 1 ] || [ "$dataformat" = "raw-ip" ] || [ "$dataformat" = "" ] || {
			echo "Modem did not accept raw-ip data format (got $dataformat)"
			proto_notify_error "$interface" DATA_FORMAT_FAILED
			proto_block_restart "$interface"
			return 1
		}
		dataformat=
	else
		uqmi -s -d "$device" -t 1000 --wda-set-data-format 802.3 > /dev/null 2>&1
		json_load "$(uqmi -s -d "$device" -t 1000 --wda-get-data-format)"
		json_get_var dataformat link-layer-protocol
	fi

	if [ "$dataformat" = "raw-ip" ]; then

		[ -f /sys/class/net/$ifname/qmi/raw_ip ] || {
			echo "Device only supports raw-ip mode but is missing this required driver attribute: /sys/class/net/$ifname/qmi/raw_ip"
			proto_notify_error "$interface" RAW_IP_UNSUPPORTED
			proto_block_restart "$interface"
			return 1
		}

		echo "Device does not support 802.3 mode. Informing driver of raw-ip only for $ifname .."
		echo "Y" > /sys/class/net/$ifname/qmi/raw_ip
	fi

	uqmi -s -d "$device" -t 1000 --sync > /dev/null 2>&1

	uqmi -s -d "$device" -t 20000 --network-register > /dev/null 2>&1

	# PLMN selection must happen after the call to network-register
	if [ -n "$mcc" -a -n "$mnc" ]; then
		uqmi -s -d "$device" -t 1000 --set-plmn --mcc "$mcc" --mnc "$mnc" > /dev/null 2>&1 || {
			echo "Unable to set PLMN"
			proto_notify_error "$interface" PLMN_FAILED
			proto_block_restart "$interface"
			return 1
		}
	fi

	[ -n "$modes" ] && {
		uqmi -s -d "$device" -t 1000 --set-network-modes "$modes" > /dev/null 2>&1
		sleep 3
		# Scan network to not rely on registration-timeout after RAT change
		uqmi -s -d "$device" -t 30000 --network-scan > /dev/null 2>&1
	}

	echo "Waiting for network registration"
	sleep 5
	local registration_timeout=0
	local serving_system=""
	local registration_state=""
	while true; do
		serving_system="$(uqmi -s -d "$device" -t 1000 --get-serving-system 2>/dev/null)"
		registration_state=$(echo "$serving_system" | jsonfilter -e "@.registration" 2>/dev/null)

		[ "$serving_system" = "\"Invalid QMI command\"" ] && break
		[ "$registration_state" = "registered" ] && break

		# A rejected attach (e.g. right after the attach profile changed or
		# the modem re-registered) is often retried successfully by the
		# modem, so keep waiting for it like for 'searching'.
		if [ "$registration_state" = "searching" ] || [ "$registration_state" = "not_registered" ] ||
		   [ "$registration_state" = "registering_denied" ]; then
			if [ "$registration_timeout" -lt "$timeout" ] || [ "$timeout" = "0" ]; then
				[ "$registration_state" = "searching" ] || [ "$registration_state" = "registering_denied" ] || {
					echo "Device stopped network registration. Restart network registration"
					uqmi -s -d "$device" -t 20000 --network-register > /dev/null 2>&1
				}
				let registration_timeout++
				sleep 1
				continue
			fi
			echo "Network registration failed, registration timeout reached"
		else
			# registration_state is 'registration_denied' or 'unknown' or ''
			echo "Network registration failed (reason: '$registration_state')"
		fi

		proto_notify_error "$interface" NETWORK_REGISTRATION_FAILED
		return 1
	done

	# allow_roaming defaults to allowed; only an explicit 0 denies it
	if [ "$allow_roaming" = "0" ] &&
	   [ "$(echo "$serving_system" | jsonfilter -e "@.roaming" 2>/dev/null)" = "true" ]; then
		echo "Registered in roaming mode but roaming is not allowed"
		proto_notify_error "$interface" ROAMING_NOT_ALLOWED
		return 1
	fi

	echo "Starting network $interface"

	if [ "$pdptype" = "ip" ]; then
		[ -z "$autoconnect" ] && autoconnect=1
		[ "$autoconnect" = 0 ] && autoconnect=""
	else
		[ "$autoconnect" = 1 ] || autoconnect=""
	fi

	[ "$pdptype" = "ip" -o "$pdptype" = "ipv4v6" ] && {
		cid_4=$(uqmi -s -d "$device" -t 1000 --get-client-id wds)
		if ! [ "$cid_4" -eq "$cid_4" ] 2> /dev/null; then
			echo "Unable to obtain client ID"
			proto_notify_error "$interface" NO_CID
			return 1
		fi

		qmi_wds_bind "$cid_4" || {
			proto_notify_error "$interface" BIND_FAILED
			return 1
		}

		uqmi -s -d "$device" -t 1000 --set-client-id wds,"$cid_4" --set-ip-family ipv4 > /dev/null 2>&1

		pdh_4=$(uqmi -s -d "$device" -t 5000 --set-client-id wds,"$cid_4" \
			--start-network \
			${apn:+--apn $apn} \
			${profile:+--profile $profile} \
			${auth:+--auth-type $auth} \
			${username:+--username $username} \
			${password:+--password $password} \
			${autoconnect:+--autoconnect})

		# pdh_4 is a numeric value on success
		if ! [ "$pdh_4" -eq "$pdh_4" ] 2> /dev/null; then
			echo "Unable to connect IPv4"
			uqmi -s -d "$device" -t 1000 --set-client-id wds,"$cid_4" --release-client-id wds > /dev/null 2>&1
			pdh_4=""
			cid_4=""
		fi

		# Check data connection state
		[ -n "$pdh_4" ] && {
			connstat=$(uqmi -s -d "$device" -t 1000 --set-client-id wds,"$cid_4" --get-data-status)
			[ "$connstat" == '"connected"' ] || {
				echo "No data link!"
				uqmi -s -d "$device" -t 1000 --set-client-id wds,"$cid_4" --release-client-id wds > /dev/null 2>&1
				pdh_4=""
				cid_4=""
			}
		}
	}

	[ "$pdptype" = "ipv6" -o "$pdptype" = "ipv4v6" ] && {
		cid_6=$(uqmi -s -d "$device" -t 1000 --get-client-id wds)
		if ! [ "$cid_6" -eq "$cid_6" ] 2> /dev/null; then
			echo "Unable to obtain client ID"
			proto_notify_error "$interface" NO_CID
			return 1
		fi

		qmi_wds_bind "$cid_6" || {
			proto_notify_error "$interface" BIND_FAILED
			return 1
		}

		uqmi -s -d "$device" -t 1000 --set-client-id wds,"$cid_6" --set-ip-family ipv6 > /dev/null 2>&1

		: "${v6apn:=${apn}}"
		: "${v6profile:=${profile}}"

		pdh_6=$(uqmi -s -d "$device" -t 5000 --set-client-id wds,"$cid_6" \
			--start-network \
			${v6apn:+--apn $v6apn} \
			${v6profile:+--profile $v6profile} \
			${auth:+--auth-type $auth} \
			${username:+--username $username} \
			${password:+--password $password} \
			${autoconnect:+--autoconnect})

		# pdh_6 is a numeric value on success
		if ! [ "$pdh_6" -eq "$pdh_6" ] 2> /dev/null; then
			echo "Unable to connect IPv6"
			uqmi -s -d "$device" -t 1000 --set-client-id wds,"$cid_6" --release-client-id wds > /dev/null 2>&1
			pdh_6=""
			cid_6=""
		fi

		# Check data connection state
		[ -n "$pdh_6" ] && {
			connstat=$(uqmi -s -d "$device" -t 1000 --set-client-id wds,"$cid_6" --set-ip-family ipv6 --get-data-status)
			[ "$connstat" == '"connected"' ] || {
				echo "No data link!"
				uqmi -s -d "$device" -t 1000 --set-client-id wds,"$cid_6" --release-client-id wds > /dev/null 2>&1
				pdh_6=""
				cid_6=""
			}
		}
	}

	# fail only if no requested family came up (e.g. IPv6 may be rejected by the network)
	[ -n "$pdh_4" -o -n "$pdh_6" ] || {
		proto_notify_error "$interface" CALL_FAILED
		return 1
	}

	echo "Setting up $ifname"
	proto_init_update "$ifname" 1
	proto_set_keep 1
	proto_add_data
	[ -n "$pdh_4" ] && {
		json_add_string "cid_4" "$cid_4"
		json_add_string "pdh_4" "$pdh_4"
	}
	[ -n "$pdh_6" ] && {
		json_add_string "cid_6" "$cid_6"
		json_add_string "pdh_6" "$pdh_6"
	}
	proto_close_data
	proto_send_update "$interface"

	local zone="$(fw3 -q network "$interface" 2>/dev/null)"

	[ -n "$pdh_6" ] && {
		if [ -z "$dhcpv6" -o "$dhcpv6" = 0 ]; then
			json_load "$(uqmi -s -d $device -t 1000 --set-client-id wds,$cid_6 --get-current-settings)"
			json_select ipv6
			json_get_var ip_6 ip
			json_get_var gateway_6 gateway
			json_get_var dns1_6 dns1
			json_get_var dns2_6 dns2
			json_get_var ip_prefix_length ip-prefix-length

			proto_init_update "$ifname" 1
			proto_set_keep 1
			proto_add_ipv6_address "$ip_6" "128"
			proto_add_ipv6_prefix "${ip_6}/${ip_prefix_length}"
			proto_add_ipv6_route "$gateway_6" "128"
			[ "$defaultroute" = 0 ] || proto_add_ipv6_route "::0" 0 "$gateway_6" "" "" "${ip_6}/${ip_prefix_length}"
			proto_add_dns_server "$dns1_6"
			proto_add_dns_server "$dns2_6"
			[ -n "$zone" ] && {
				proto_add_data
				json_add_string zone "$zone"
				proto_close_data
			}
			proto_send_update "$interface"
		else
			json_init
			json_add_string name "${interface}_6"
			json_add_string ifname "@$interface"
			[ "$pdptype" = "ipv4v6" ] && json_add_string iface_464xlat "0"
			json_add_string proto "dhcpv6"
			[ -n "$ip6table" ] && json_add_string ip6table "$ip6table"
			proto_add_dynamic_defaults
			# RFC 7278: Extend an IPv6 /64 Prefix to LAN
			json_add_string extendprefix 1
			[ "$delegate" = "0" ] && json_add_boolean delegate "0"
			[ "$sourcefilter" = "0" ] && json_add_boolean sourcefilter "0"
			[ -n "$zone" ] && json_add_string zone "$zone"
			json_close_object
			ubus call network add_dynamic "$(json_dump)"
		fi
	}

	[ -n "$pdh_4" ] && {
		if [ "$dhcp" = 0 ]; then
			json_load "$(uqmi -s -d $device -t 1000 --set-client-id wds,$cid_4 --get-current-settings)"
			json_select ipv4
			json_get_var ip_4 ip
			json_get_var gateway_4 gateway
			json_get_var dns1_4 dns1
			json_get_var dns2_4 dns2
			json_get_var subnet_4 subnet

			proto_init_update "$ifname" 1
			proto_set_keep 1
			proto_add_ipv4_address "$ip_4" "$subnet_4"
			proto_add_ipv4_route "$gateway_4" "128"
			[ "$defaultroute" = 0 ] || proto_add_ipv4_route "0.0.0.0" 0 "$gateway_4"
			proto_add_dns_server "$dns1_4"
			proto_add_dns_server "$dns2_4"
			[ -n "$zone" ] && {
				proto_add_data
				json_add_string zone "$zone"
				proto_close_data
			}
			proto_send_update "$interface"
		else
			json_init
			json_add_string name "${interface}_4"
			json_add_string ifname "@$interface"
			json_add_string proto "dhcp"
			[ -n "$ip4table" ] && json_add_string ip4table "$ip4table"
			proto_add_dynamic_defaults
			[ -n "$zone" ] && json_add_string zone "$zone"
			json_close_object
			ubus call network add_dynamic "$(json_dump)"
		fi
	}
}

qmi_wds_bind() {
	local cid="$1"

	[ -n "$dataport" ] || return 0

	uqmi -s -d "$device" -t 1000 --set-client-id wds,"$cid" \
		--bind-data-port "$dataport" > /dev/null 2>&1 && return 0

	echo "Unable to bind data port $dataport"
	uqmi -s -d "$device" -t 1000 --set-client-id wds,"$cid" \
		--release-client-id wds > /dev/null 2>&1
	return 1
}

qmi_wds_stop() {
	local cid="$1"
	local pdh="$2"

	[ -n "$cid" ] || return

	uqmi -s -d "$device" -t 1000 --set-client-id wds,"$cid" \
		--stop-network 0xffffffff \
		--autoconnect > /dev/null 2>&1

	[ -n "$pdh" ] && {
		uqmi -s -d "$device" -t 1000 --set-client-id wds,"$cid" \
			--stop-network "$pdh" > /dev/null 2>&1
	}

	uqmi -s -d "$device" -t 1000 --set-client-id wds,"$cid" \
		--release-client-id wds > /dev/null 2>&1
}

proto_qmi_teardown() {
	local interface="$1"

	local device devpath cid_4 pdh_4 cid_6 pdh_6
	json_get_vars device devpath

	[ -n "$ctl_device" ] && device=$ctl_device

	if [ -n "$devpath" ]; then
		local usbmisc_or_wwan_path
		for usbmisc_or_wwan_path in \
		    "$devpath"/usbmisc/cdc-wdm* \
		    "$devpath"/*/usbmisc/cdc-wdm* \
		    "$devpath"/*/wwan[0-9]*/wwan[0-9]*qmi* \
		    "$devpath"/*/*/wwan[0-9]*/wwan[0-9]*qmi*; do
			device="/dev/${usbmisc_or_wwan_path##*/}"
		done
	fi

	echo "Stopping network $interface"

	json_load "$(ubus call network.interface.$interface status)"
	json_select data
	json_get_vars cid_4 pdh_4 cid_6 pdh_6

	qmi_wds_stop "$cid_4" "$pdh_4"
	qmi_wds_stop "$cid_6" "$pdh_6"

	proto_init_update "*" 0
	proto_send_update "$interface"
}

[ -n "$INCLUDE_ONLY" ] || {
	add_protocol qmi
}
