#!/bin/sh

[ -n "$INCLUDE_ONLY" ] || {
	. /lib/functions.sh
	. ../netifd-proto.sh
	init_proto "$@"
}
#DBG=-v

proto_mbim_init_config() {
	available=1
	no_device=1
	proto_config_add_string "device:device"
	proto_config_add_string apn
	proto_config_add_string pincode
	proto_config_add_string delay
	proto_config_add_string auth
	proto_config_add_string username
	proto_config_add_string password
	proto_config_add_string pdptype
	proto_config_add_defaults
}

_proto_mbim_setup() {
	local interface="$1"
	local tid=2
	local ret

	local device apn pincode delay auth username password pdptype  $PROTO_DEFAULT_OPTIONS
	local ip4table ip6table
	json_get_vars device apn pincode delay auth username password pdptype ip4table ip6table $PROTO_DEFAULT_OPTIONS

	[ -n "$ctl_device" ] && device=$ctl_device

	[ -n "$device" ] || {
		echo "mbim[$$]" "No control device specified"
		proto_notify_error "$interface" NO_DEVICE
		proto_set_available "$interface" 0
		return 1
	}
	[ -c "$device" ] || {
		echo "mbim[$$]" "The specified control device does not exist"
		proto_notify_error "$interface" NO_DEVICE
		proto_set_available "$interface" 0
		return 1
	}

	devname="$(basename "$device")"
	devpath="$(readlink -f /sys/class/usbmisc/$devname/device/)"
	ifname="$( ls "$devpath"/net )"

	[ -n "$ifname" ] || {
		echo "mbim[$$]" "Failed to find matching interface"
		proto_notify_error "$interface" NO_IFNAME
		proto_set_available "$interface" 0
		return 1
	}

	[ -n "$apn" ] || {
		echo "mbim[$$]" "No APN specified"
		proto_notify_error "$interface" NO_APN
		return 1
	}

	[ -n "$delay" ] && sleep "$delay"

	echo "mbim[$$]" "Reading capabilities"
	umbim $DBG -n -d $device caps || {
		echo "mbim[$$]" "Failed to read modem caps"
		proto_notify_error "$interface" PIN_FAILED
		return 1
	}
	tid=$((tid + 1))

	[ "$pincode" ] && {
		echo "mbim[$$]" "Sending pin"
		umbim $DBG -n -t $tid -d $device unlock "$pincode" || {
			echo "mbim[$$]" "Unable to verify PIN"
			proto_notify_error "$interface" PIN_FAILED
			proto_block_restart "$interface"
			return 1
		}
	}
	tid=$((tid + 1))

	echo "mbim[$$]" "Checking pin"
	pin_status=`umbim $DBG -n -t $tid -d $device pinstate 2>&1 | head -n1 | sed 's/required pin:\s*\([[:digit:]]*\).*/\1/g'`
	case "$pin_status" in
		""|\
		"Pin Unlocked"|\
		"3")
			;;
		*)
			echo "mbim[$$]" "PIN required"
			echo "$pin_status"
			proto_notify_error "$interface" PIN_FAILED
			proto_block_restart "$interface"
			return 1
			;;
	esac
	tid=$((tid + 1))

	echo "mbim[$$]" "Checking subscriber"
 	umbim $DBG -n -t $tid -d $device subscriber || {
		echo "mbim[$$]" "Subscriber init failed"
		proto_notify_error "$interface" NO_SUBSCRIBER
		return 1
	}
	tid=$((tid + 1))

	echo "mbim[$$]" "Register with network"
  	umbim $DBG -n -t $tid -d $device registration || {
		echo "mbim[$$]" "Subscriber registration failed"
		proto_notify_error "$interface" NO_REGISTRATION
		return 1
	}
	tid=$((tid + 1))

	echo "mbim[$$]" "Attach to network"
   	umbim $DBG -n -t $tid -d $device attach || {
		echo "mbim[$$]" "Failed to attach to network"
		proto_notify_error "$interface" ATTACH_FAILED
		return 1
	}
	tid=$((tid + 1))
 
	echo "mbim[$$]" "Connect to network"
	while : ; do
		connect_result=$(umbim $DBG -n -t $tid -d $device connect "$apn" "$auth" "$username" "$password")
		printf "$connect_result\n"
		activation_state=$(echo $connect_result | sed 's/.*activationstate:\s*\([[:digit:]]*\).*/\1/g')
		[ $activation_state != "0001" ] || break
		case "$activation_state" in
			"0001")
				break
				;;
			"0000"|\
			"0002"|\
			"0004")
				;;
			*)
				echo "Unable to connect, check APN and authentication"
				proto_notify_error "$interface" NO_PDH
				proto_block_restart "$interface"
				return 1
				;;
		esac
		tid=$((tid + 1))
		sleep 1;
	done
	tid=$((tid + 1))

	local pdh_4=0
	local pdh_6=0
	case "$pdptype" in
		"ipv4")
			pdh_4=1
			;;
		"ipv6")
			pdh_6=1
			;;
		"ipv4v6")
		*)
			pdh_4=1
			pdh_6=1
			;;
	esac

	uci_set_state network $interface tid "$tid"

	echo "mbim[$$]" "Connected($iptype), starting DHCP"
	proto_init_update "$ifname" 1
	proto_send_update "$interface"

	local zone="$(fw3 -q network "$interface" 2>/dev/null)"

	if [ "$pdh_4" -ne "0" ]; then
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

	if [ "$pdh_6" -ne "0" ]; then
		json_init
		json_add_string name "${interface}_6"
		json_add_string ifname "@$interface"
		json_add_string proto "dhcpv6"
		[ -n "$ip6table" ] && json_add_string ip6table "$ip6table"
		proto_add_dynamic_defaults
		json_add_string extendprefix 1
		[ -n "$zone" ] && json_add_string zone "$zone"
		json_close_object
		ubus call network add_dynamic "$(json_dump)"
	fi
}

proto_mbim_setup() {
	local ret

	_proto_mbim_setup $@
	ret=$?

	[ "$ret" = 0 ] || {
		logger "mbim bringup failed, retry in 15s"
		sleep 15
	}

	return $ret
}

proto_mbim_teardown() {
	local interface="$1"

	local device
	json_get_vars device
	local tid=$(uci_get_state network $interface tid)

	[ -n "$ctl_device" ] && device=$ctl_device

	echo "mbim[$$]" "Stopping network"
	[ -n "$tid" ] && {
		umbim $DBG -t$tid -d "$device" disconnect
		uci_revert_state network $interface tid
	}

	proto_init_update "*" 0
	proto_send_update "$interface"
}

[ -n "$INCLUDE_ONLY" ] || add_protocol mbim
