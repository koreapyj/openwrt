#!/bin/sh
# netifd protocol of uqmid, modeled on OpenWrt's modemmanager.sh.
# All modem operations go through the ubus API of uqmid (see uqmid/README.md).

[ -x /sbin/uqmid ] || exit 0

[ -n "$INCLUDE_ONLY" ] || {
	. /lib/functions.sh
	. /usr/share/libubox/jshn.sh
	. ../netifd-proto.sh
	init_proto "$@"
}

cdr2mask ()
{
	# Number of args to shift, 255..255, first non-255 byte, zeroes
	set -- $(( 5 - ($1 / 8) )) 255 255 255 255 $(( (255 << (8 - ($1 % 8))) & 255 )) 0 0 0
	if [ "$1" -gt 1 ]
	then
		shift "$1"
	else
		shift
	fi
	echo "${1-0}"."${2-0}"."${3-0}"."${4-0}"
}

# ubus call with a timeout (global $timeout, seconds); the reply is printed
uqmid_call() {
	local object="$1" method="$2" args="$3"

	[ -n "$args" ] || args='{}'
	ubus -t "${timeout:-120}" call "$object" "$method" "$args"
}

# print the value of the jsonfilter expression $2 in the json $1
uqmid_field() {
	jsonfilter -s "$1" -e "$2" 2>/dev/null
}

# netifd only publishes proto data after a successful link-up update. Keep modem
# ownership on disk too, so teardown can release a modem while setup is still
# waiting for registration or bearer setup.
uqmid_enabled_marker_path() {
	case "$1" in
		""|*[!A-Za-z0-9_.-]*) return 1 ;;
	esac
	printf '/var/run/uqmid/%s.enabled' "$1"
}

uqmid_write_enabled_marker() {
	local marker="$1" modem="$2" tmp
	tmp="${marker}.$$"
	mkdir -p "${marker%/*}" || return 1
	printf '%s\n' "$modem" > "$tmp" && mv -f "$tmp" "$marker"
}

# Atomically claim the per-interface marker. Only one of setup failure and
# teardown may release the modem. Print the modem path stored by setup.
uqmid_take_enabled_marker() {
	local marker="$1" claim modem
	claim="${marker}.release.$$"
	[ -f "$marker" ] || return 1
	mv "$marker" "$claim" 2>/dev/null || return 1
	modem=$(cat "$claim" 2>/dev/null)
	rm -f "$claim"
	printf '%s' "$modem"
	return 0
}

# Find the uqmid modem of a device option: the /dev node, the port name or the
# physical device (sysfs path). Prints the ubus object path.
uqmid_find_modem() {
	local device="$1"

	local list n i path node port physdev
	[ -n "$device" ] || return 1
	list=$(ubus -t 5 call uqmid list 2>/dev/null) || return 1

	n=$(uqmid_field "$list" '@.modems[*].path' | wc -l)
	i=0
	while [ "$i" -lt "$n" ]; do
		path=$(uqmid_field "$list" "@.modems[$i].path")
		node=$(uqmid_field "$list" "@.modems[$i].device")
		port=$(uqmid_field "$list" "@.modems[$i].port")
		physdev=$(uqmid_field "$list" "@.modems[$i].physdev")
		if [ "$device" = "$node" ] || [ "$device" = "$port" ] || [ "${device##*/}" = "$port" ] ||
		   [ "$device" = "${node##*/}" ] || { [ -n "$physdev" ] && [ "$device" = "$physdev" ]; }; then
			echo "$path"
			return 0
		fi
		i=$((i + 1))
	done
	return 1
}

# json objects of the call arguments; print the json
uqmid_bearer_args() {
	local apn="$1" iptype="$2" allowedauth="$3" username="$4" password="$5" allow_roaming="$6" plmn="$7" profile="$8"
	local auth

	json_init
	# the APN is always given, even if empty (network default), like the MM proto
	json_add_string apn "$apn"
	[ -n "$iptype" ] && json_add_string ip_type "$iptype"
	[ -n "$allowedauth" ] && {
		json_add_array allowed_auth
		for auth in $allowedauth; do
			json_add_string "" "$auth"
		done
		json_close_array
	}
	[ -n "$username" ] && json_add_string user "$username"
	[ -n "$password" ] && json_add_string password "$password"
	[ -n "$allow_roaming" ] && json_add_boolean allow_roaming "$allow_roaming"
	[ -n "$plmn" ] && json_add_string operator_id "$plmn"
	[ -n "$profile" ] && json_add_int profile_id "$profile"
	json_dump
}

# Used by the first/last steps of the setup: disconnect and delete the bearers
# owned by this interface. Bearers made by other clients (e.g. an IMS bearer
# created with create_bearer) are left alone. A bearer is owned if
#  - it is the one this interface stored as proto data (uqmid_bearer; $4), or
#  - its properties are those this interface connects with: the same apn and the
#    same profile_id (none if no profile is configured), i.e. the bearer which
#    simple_connect would reuse for this interface.
uqmid_cleanup_connection() {
	local modem="$1" apn="$2" profile="$3" stored="$4"

	local status bearers bearer props bearer_apn bearer_profile
	status=$(uqmid_call "$modem" get 2>/dev/null) || return 0
	bearers=$(uqmid_field "$status" '@.bearers[*]')

	for bearer in $bearers; do
		if [ -z "$stored" ] || [ "$bearer" != "$stored" ]; then
			props=$(uqmid_call "$bearer" get 2>/dev/null) || continue
			bearer_apn=$(uqmid_field "$props" '@.properties.apn')
			bearer_profile=$(uqmid_field "$props" '@.properties.profile_id')
			[ "$bearer_apn" = "$apn" ] && [ "$bearer_profile" = "$profile" ] || continue
		fi
		# explicitly disconnect just in case, then remove the bearer object
		uqmid_call "$modem" simple_disconnect "{\"bearer\":\"$bearer\"}" >/dev/null 2>&1
		uqmid_call "$modem" delete_bearer "{\"path\":\"$bearer\"}" >/dev/null 2>&1
	done
}

# disable/lowpower, like the end of the MM teardown. Only if this interface
# enabled the modem; a modem enabled by someone else is never touched.
uqmid_release_modem() {
	local interface="$1" modem="$2" lowpower="$3"

	local disable
	# Variable is set to '1' if modem should be disabled on ifdown,
	# otherwise it stays enabled.
	disable="$(uci_get network "$interface" disable_modem "1")"
	if [ "${disable}" -eq 0 ]; then
		echo "Skipping modem disable"
	else
		uqmid_call "$modem" enable '{"enable":false}' >/dev/null 2>&1
	fi

	# low power, only if requested
	[ "${lowpower:-0}" -lt 1 ] ||
		uqmid_call "$modem" set_power_state '{"state":"low"}' >/dev/null 2>&1
}

# the proto data of the update: what teardown has to know (the data is only
# delivered together with a link-up update)
uqmid_proto_data() {
	proto_add_data
	json_add_string uqmid_enabled_by_iface "${uqmid_enabled_by_iface:-0}"
	json_add_string uqmid_bearer "${uqmid_bearer}"
	proto_close_data
}

uqmid_connected_method_dhcp_ipv4() {
	local interface="$1"
	local wwan="$2"
	local metric="$3"

	proto_init_update "${wwan}" 1
	proto_set_keep 1
	uqmid_proto_data
	proto_send_update "${interface}"

	json_init
	json_add_string name "${interface}_4"
	json_add_string ifname "@${interface}"
	json_add_string proto "dhcp"
	proto_add_dynamic_defaults
	[ -n "$metric" ] && json_add_int metric "${metric}"
	json_close_object
	ubus call network add_dynamic "$(json_dump)"
}

uqmid_connected_method_static_ipv4() {
	local interface="$1"
	local wwan="$2"
	local address="$3"
	local prefix="$4"
	local gateway="$5"
	local mtu="$6"
	local dns1="$7"
	local dns2="$8"
	local metric="$9"

	local mask=""

	[ -n "${address}" ] || {
		proto_notify_error "${interface}" ADDRESS_MISSING
		return 1
	}

	[ -n "${prefix}" ] || {
		proto_notify_error "${interface}" PREFIX_MISSING
		return 1
	}
	mask=$(cdr2mask "${prefix}")

	[ -n "${mtu}" ] && /sbin/ip link set dev "${wwan}" mtu "${mtu}"

	proto_init_update "${wwan}" 1
	proto_set_keep 1
	uqmid_proto_data
	echo "adding IPv4 address ${address}, netmask ${mask}"
	proto_add_ipv4_address "${address}" "${mask}"
	[ -n "${gateway}" ] && {
		echo "adding default IPv4 route via ${gateway}"
		proto_add_ipv4_route "0.0.0.0" "0" "${gateway}" "${address}"
	}
	[ -n "${dns1}" ] && {
		echo "adding primary DNS at ${dns1}"
		proto_add_dns_server "${dns1}"
	}
	[ -n "${dns2}" ] && {
		echo "adding secondary DNS at ${dns2}"
		proto_add_dns_server "${dns2}"
	}
	[ -n "$metric" ] && json_add_int metric "${metric}"
	proto_send_update "${interface}"
}

uqmid_connected_method_dhcp_ipv6() {
	local interface="$1"
	local wwan="$2"
	local metric="$3"

	proto_init_update "${wwan}" 1
	proto_set_keep 1
	uqmid_proto_data
	proto_send_update "${interface}"

	json_init
	json_add_string name "${interface}_6"
	json_add_string ifname "@${interface}"
	json_add_string proto "dhcpv6"
	proto_add_dynamic_defaults
	json_add_string extendprefix 1 # RFC 7278: Extend an IPv6 /64 Prefix to LAN
	[ "$sourcefilter" = "0" ] && json_add_boolean sourcefilter "0"
	[ -n "$metric" ] && json_add_int metric "${metric}"
	json_close_object
	ubus call network add_dynamic "$(json_dump)"
}

uqmid_connected_method_static_ipv6() {
	local interface="$1"
	local wwan="$2"
	local address="$3"
	local prefix="$4"
	local gateway="$5"
	local mtu="$6"
	local dns1="$7"
	local dns2="$8"
	local metric="$9"

	[ -n "${address}" ] || {
		proto_notify_error "${interface}" ADDRESS_MISSING
		return 1
	}

	[ -n "${prefix}" ] || {
		proto_notify_error "${interface}" PREFIX_MISSING
		return 1
	}

	[ -n "${mtu}" ] && /sbin/ip link set dev "${wwan}" mtu "${mtu}"

	proto_init_update "${wwan}" 1
	proto_set_keep 1
	uqmid_proto_data
	echo "adding IPv6 address ${address}, prefix ${prefix}"
	proto_add_ipv6_address "${address}" "128"
	proto_add_ipv6_prefix "${address}/${prefix}"
	[ -n "${gateway}" ] && {
		echo "adding default IPv6 route via ${gateway}"
		proto_add_ipv6_route "${gateway}" "128"
		[ "$sourcefilter" = "0" ] && {
			proto_add_ipv6_route "::0" "0" "${gateway}"
		} || {
			proto_add_ipv6_route "::0" "0" "${gateway}" "" "" "${address}/${prefix}"
		}
	}
	[ -n "${dns1}" ] && {
		echo "adding primary DNS at ${dns1}"
		proto_add_dns_server "${dns1}"
	}
	[ -n "${dns2}" ] && {
		echo "adding secondary DNS at ${dns2}"
		proto_add_dns_server "${dns2}"
	}
	[ -n "$metric" ] && json_add_int metric "${metric}"
	proto_send_update "${interface}"
}

proto_uqmid_init_config() {
	available=1
	no_device=1
	proto_config_add_string device
	proto_config_add_string apn
	proto_config_add_string 'allowedauth:list(string)'
	proto_config_add_string username
	proto_config_add_string password
	proto_config_add_string pincode
	proto_config_add_string iptype
	proto_config_add_boolean sourcefilter
	proto_config_add_string plmn
	proto_config_add_int signalrate
	proto_config_add_boolean lowpower
	proto_config_add_boolean allow_roaming
	proto_config_add_boolean force_connection
	proto_config_add_int timeout
	proto_config_add_int delay
	proto_config_add_int profile
	proto_config_add_string init_epsbearer
	proto_config_add_string init_iptype
	proto_config_add_string 'init_allowedauth:list(string)'
	proto_config_add_string init_password
	proto_config_add_string init_username
	proto_config_add_string init_apn
	proto_config_add_defaults
}

# retryable (force_connection) or permanent failure of a call, like MM
uqmid_fail_retry_or_block() {
	local interface="$1" force_connection="$2" retry_error="$3" block_error="$4"

	if [ -n "${force_connection}" ] && [ "${force_connection}" -eq 1 ]; then
		echo "${block_error} -> attempting restart"
		proto_notify_error "${interface}" "${retry_error}"
	else
		proto_notify_error "${interface}" "${block_error}"
		proto_block_restart "${interface}"
	fi
}

uqmid_check_state_failed() {
	local interface="$1"
	local modemstatus="$2"

	local reason

	reason="$(uqmid_field "${modemstatus}" '@.state_failed_reason')"

	case "$reason" in
		"sim-missing")
			echo "SIM missing"
			proto_notify_error "${interface}" UQMID_FAILED_REASON_SIM_MISSING
			proto_block_restart "${interface}"
			return 1
			;;
		"sim-error")
			echo "SIM failure"
			proto_notify_error "${interface}" UQMID_FAILED_REASON_SIM_ERROR
			proto_block_restart "${interface}"
			return 1
			;;
		*)
			proto_notify_error "${interface}" UQMID_FAILED_REASON_UNKNOWN
			proto_block_restart "${interface}"
			return 1
			;;
	esac
}

uqmid_check_state_locked() {
	local modem="$1"
	local interface="$2"
	local modemstatus="$3"
	local pincode="$4"

	local unlock_required unlock_value sim_path

	if [ -z "$pincode" ]; then
		echo "PIN required"
		proto_notify_error "${interface}" UQMID_PINCODE_REQUIRED
		proto_block_restart "${interface}"
		return 1
	fi

	unlock_required="$(uqmid_field "${modemstatus}" '@.unlock_required')"
	case "$unlock_required" in
		"sim-pin")
			unlock_value="$(uqmid_field "${modemstatus}" '@.unlock_retries["sim-pin"]')"
			# do not use up the last attempts with a possibly wrong PIN
			[ -z "$unlock_value" ] || [ "$unlock_value" -ge 2 ] || {
				echo "please check PIN (remaining attempts: ${unlock_value})"
				proto_notify_error "${interface}" UQMID_CHECK_UNLOCK_PIN
				proto_block_restart "${interface}"
				return 1
			}
			;;
		"sim-puk")
			unlock_value="$(uqmid_field "${modemstatus}" '@.unlock_retries["sim-puk"]')"
			echo "unlock with PUK required (remaining attempts: ${unlock_value})"
			proto_notify_error "${interface}" UQMID_CHECK_UNLOCK_PIN
			proto_block_restart "${interface}"
			return 1
			;;
		*)
			echo "unable to check PIN/PUK attempts"
			proto_notify_error "${interface}" UQMID_CHECK_UNLOCK_UNKNOWN
			proto_block_restart "${interface}"
			return 1
			;;
	esac

	sim_path="$(uqmid_field "${modemstatus}" '@.sim')"
	[ -n "${sim_path}" ] && [ "${sim_path}" != "/" ] || {
		proto_notify_error "${interface}" UQMID_FAILED_REASON_SIM_MISSING
		proto_block_restart "${interface}"
		return 1
	}
	uqmid_call "${sim_path}" send_pin "{\"pin\":\"${pincode}\"}" >/dev/null 2>&1 || {
		proto_notify_error "${interface}" UQMID_PINCODE_WRONG
		proto_block_restart "${interface}"
		return 1
	}

	# Give the modem time to change to the initializing state after
	# unlocking
	sleep 1

	return 0
}

# On success $modemstatus is the current status
uqmid_check_pin_state() {
	local modem="$1"
	local interface="$2"
	local pincode="$3"

	local state

	local timeout_s=20
	local count=0

	modemstatus=$(uqmid_call "${modem}" get) || {
		proto_notify_error "${interface}" DEVICE_NOT_MANAGED
		return 1
	}
	state="$(uqmid_field "${modemstatus}" '@.state')"

	case "$state" in
		"failed")
			uqmid_check_state_failed "$interface" "$modemstatus"
			[ "$?" -ne "0" ] && return 1
			;;
		"locked")
			uqmid_check_state_locked "$modem" "$interface" "$modemstatus" "$pincode"
			[ "$?" -ne "0" ] && return 1
			;;
	esac

	# After the SIM has been successfully unlocked, it is initialized.
	# This can take longer on some modems, so we must wait until the
	# modem is ready to execute the next commands.
	while [ $count -lt "$timeout_s" ]; do
		modemstatus=$(uqmid_call "${modem}" get) || return 1
		state="$(uqmid_field "${modemstatus}" '@.state')"

		case "$state" in
			"initializing"|"unknown")
				count=$((count + 1))
				echo "waiting for SIM initializing (${count}s)"
				sleep 1
				;;
			"failed")
				uqmid_check_state_failed "$interface" "$modemstatus"
				return 1
				;;
			"locked")
				echo "PIN required"
				proto_notify_error "${interface}" UQMID_CHECK_UNLOCK_PIN
				proto_block_restart "${interface}"
				return 1
				;;
			*)
				return 0
				;;
		esac
	done

	echo "modem initialization timed out"
	proto_notify_error "${interface}" UQMID_INIT_TIMEOUT
	return 1
}

uqmid_init_epsbearer() {
	local eps="$1"
	local modem="$2"
	local args="$3"
	local apn="$4"

	if [ "$eps" = "network" ]; then
		echo "Setting network-assigned initial EPS bearer"
	else
		echo "Setting '$eps' initial EPS bearer apn to '$apn'"
	fi

	uqmid_call "${modem}" set_initial_eps_bearer_settings "${args}" >/dev/null || {
		proto_notify_error "${interface}" UQMID_INIT_EPS_BEARER_SET_FAILED
		proto_block_restart "${interface}"
		return 1
	}

	# Wait here so that the modem can set the init EPS bearer
	# for registration
	sleep 2
}

# the setup steps after the modem was enabled (or found enabled); on failure
# the caller releases the modem
uqmid_setup_connect() {
	local interface="$1"
	local modem="$2"

	local connectargs bearerstatus beareriface
	local bearermethod_ipv4 bearermethod_ipv6
	local connectreply operatorname operatorid registration accesstech signalquality modemstatus
	local address prefix gateway mtu dns1 dns2

	# set initial eps bearer settings
	case "${init_epsbearer:-modem}" in
		"modem"|"none")
			echo "Using initial EPS bearer stored on the modem"
			;;
		"network")
			uqmid_init_epsbearer "network" "$modem" '{}' ""
			;;
		"connection"|"default")
			connectargs=$(uqmid_bearer_args "$apn" "$iptype" "$allowedauth" "$username" "$password")
			uqmid_init_epsbearer "connection" "$modem" "${connectargs}" "$apn"
			;;
		"custom")
			connectargs=$(uqmid_bearer_args "$init_apn" "$init_iptype" "$init_allowedauth" "$init_username" "$init_password")
			uqmid_init_epsbearer "custom" "$modem" "${connectargs}" "$init_apn"
			;;
		*)
			echo "Unknown init_epsbearer '${init_epsbearer}'," \
				"using initial EPS bearer stored on the modem"
			;;
	esac
	# check error for init_epsbearer function call
	[ "$?" -ne "0" ] && return 1

	if [ -z "${plmn}" ]; then
		echo "starting automatic network registration"
		connectargs='{}'
	else
		echo "starting network registration with plmn '${plmn}'"
		connectargs="{\"operator_id\":\"${plmn}\"}"
	fi
	uqmid_call "$modem" register "${connectargs}" >/dev/null || {
		uqmid_fail_retry_or_block "$interface" "$force_connection" \
			UQMID_INTERFACE_RESTART UQMID_3GPP_OPERATOR_REGISTRATION_FAILED
		return 1
	}

	# setup connect args
	echo "starting connection with apn '${apn}'"

	# setup allow-roaming parameter
	if [ -n "${allow_roaming}" ] && [ "${allow_roaming}" -eq 0 ]; then
		allow_roaming=0
	else
		# allowed unless a user set the opposite
		allow_roaming=1
	fi

	connectargs=$(uqmid_bearer_args "$apn" "$iptype" "$allowedauth" "$username" "$password" "$allow_roaming" "$plmn" "$profile")
	connectreply=$(uqmid_call "$modem" simple_connect "${connectargs}") || {
		uqmid_fail_retry_or_block "$interface" "$force_connection" \
			UQMID_INTERFACE_RESTART UQMID_CONNECT_FAILED
		return 1
	}
	uqmid_bearer="$(uqmid_field "${connectreply}" '@.bearer')"

	# check if Signal refresh rate is set
	[ -n "${signalrate}" ] &&
		echo "signal refresh rate is not supported by uqmid (ignored)"

	# log additional useful information
	modemstatus=$(uqmid_call "$modem" get)
	operatorname=$(uqmid_field "${modemstatus}" '@.operator_name')
	[ -n "${operatorname}" ] && echo "network operator name: ${operatorname}"
	operatorid=$(uqmid_field "${modemstatus}" '@.operator_code')
	[ -n "${operatorid}" ] && echo "network operator MCCMNC: ${operatorid}"
	registration=$(uqmid_field "${modemstatus}" '@.registration_state')
	[ -n "${registration}" ] && echo "registration type: ${registration}"
	accesstech=$(uqmid_field "${modemstatus}" '@.access_technologies[*]' | tr '\n' ' ')
	[ -n "${accesstech}" ] && echo "access technology: ${accesstech}"
	signalquality=$(uqmid_field "${modemstatus}" '@.signal_quality.value')
	[ -n "${signalquality}" ] && echo "signal quality: ${signalquality}%"

	[ -n "${uqmid_bearer}" ] || {
		proto_notify_error "${interface}" INVALID_BEARER_LIST
		return 1
	}

	# load connected bearer information
	bearerstatus=$(uqmid_call "${uqmid_bearer}" get) || {
		proto_notify_error "${interface}" INVALID_BEARER_LIST
		return 1
	}

	# load network interface and method information
	beareriface=$(uqmid_field "${bearerstatus}" '@.interface')
	bearermethod_ipv4=$(uqmid_field "${bearerstatus}" '@.ip4_config.method')
	bearermethod_ipv6=$(uqmid_field "${bearerstatus}" '@.ip6_config.method')

	[ -n "${beareriface}" ] && { [ -n "${bearermethod_ipv4}" ] || [ -n "${bearermethod_ipv6}" ]; } || {
		proto_notify_error "${interface}" NO_IP_CONFIG
		return 1
	}

	# setup IPv4
	[ -n "${bearermethod_ipv4}" ] && {
		echo "IPv4 connection setup required in interface ${interface}: ${bearermethod_ipv4}"
		case "${bearermethod_ipv4}" in
		"dhcp")
			uqmid_connected_method_dhcp_ipv4 "${interface}" "${beareriface}" "${metric}"
			;;
		"static")
			address=$(uqmid_field "${bearerstatus}" '@.ip4_config.address')
			prefix=$(uqmid_field "${bearerstatus}" '@.ip4_config.prefix')
			gateway=$(uqmid_field "${bearerstatus}" '@.ip4_config.gateway')
			mtu=$(uqmid_field "${bearerstatus}" '@.ip4_config.mtu')
			dns1=$(uqmid_field "${bearerstatus}" '@.ip4_config.dns1')
			dns2=$(uqmid_field "${bearerstatus}" '@.ip4_config.dns2')
			uqmid_connected_method_static_ipv4 "${interface}" "${beareriface}" "${address}" "${prefix}" "${gateway}" "${mtu}" "${dns1}" "${dns2}" "${metric}" || return 1
			;;
		*)
			proto_notify_error "${interface}" UNKNOWN_METHOD
			return 1
			;;
		esac
	}

	# setup IPv6
	# note: if using ipv4v6, both IPv4 and IPv6 settings will have the same MTU and metric values reported
	[ -n "${bearermethod_ipv6}" ] && {
		echo "IPv6 connection setup required in interface ${interface}: ${bearermethod_ipv6}"
		case "${bearermethod_ipv6}" in
		"dhcp")
			uqmid_connected_method_dhcp_ipv6 "${interface}" "${beareriface}" "${metric}"
			;;
		"static")
			address=$(uqmid_field "${bearerstatus}" '@.ip6_config.address')
			prefix=$(uqmid_field "${bearerstatus}" '@.ip6_config.prefix')
			gateway=$(uqmid_field "${bearerstatus}" '@.ip6_config.gateway')
			mtu=$(uqmid_field "${bearerstatus}" '@.ip6_config.mtu')
			dns1=$(uqmid_field "${bearerstatus}" '@.ip6_config.dns1')
			dns2=$(uqmid_field "${bearerstatus}" '@.ip6_config.dns2')
			uqmid_connected_method_static_ipv6 "${interface}" "${beareriface}" "${address}" "${prefix}" "${gateway}" "${mtu}" "${dns1}" "${dns2}" "${metric}" || return 1
			;;
		*)
			proto_notify_error "${interface}" UNKNOWN_METHOD
			return 1
			;;
		esac
	}

	return 0
}

proto_uqmid_setup() {
	local interface="$1"

	local modem modemstatus state enabled_marker marker_modem

	local device apn allowedauth username password pincode
	local iptype plmn metric signalrate allow_roaming
	local force_connection lowpower
	local sourcefilter timeout delay profile
	json_get_vars device apn allowedauth username password pincode
	json_get_vars iptype plmn metric signalrate allow_roaming
	json_get_vars force_connection lowpower
	json_get_vars sourcefilter timeout delay profile

	local init_epsbearer
	local init_iptype init_allowedauth
	local init_password init_username init_apn
	json_get_vars init_epsbearer
	json_get_vars init_iptype init_allowedauth
	json_get_vars init_password init_username init_apn

	# state of this setup, also read by uqmid_proto_data()
	local uqmid_enabled_by_iface=0 uqmid_bearer=""

	enabled_marker=$(uqmid_enabled_marker_path "$interface") || {
		echo "Invalid interface name for modem ownership marker"
		proto_notify_error "${interface}" INVALID_INTERFACE
		return 1
	}

	[ -n "$delay" ] && sleep "$delay"

	# validate the device given in config
	[ -n "${device}" ] || {
		echo "No device specified"
		proto_notify_error "${interface}" NO_DEVICE
		proto_set_available "${interface}" 0
		return 1
	}

	# validate that uqmid is handling the modem
	modem=$(uqmid_find_modem "${device}")
	[ -n "${modem}" ] || {
		echo "Device not managed by uqmid"
		proto_notify_error "${interface}" DEVICE_NOT_MANAGED
		proto_set_available "${interface}" 0
		return 1
	}
	echo "modem available at ${modem}"

	# Reuse ownership on a restarted setup for this same netifd interface.
	if [ -f "$enabled_marker" ]; then
		marker_modem=$(cat "$enabled_marker" 2>/dev/null)
		if [ "$marker_modem" = "$modem" ]; then
			uqmid_enabled_by_iface=1
		else
			rm -f "$enabled_marker"
		fi
	fi

	[ -z "${timeout}" ] && timeout="120"
	echo "setting command timeout to '${timeout}'"

	uqmid_check_pin_state "$modem" "$interface" "$pincode"
	[ "$?" -ne "0" ] && return 1

	# always cleanup before attempting a new connection, just in case: only what
	# this interface owns (the bearer of a previous run, if netifd still has its
	# data, and the bearer with this interface's properties)
	uqmid_cleanup_connection "${modem}" "${apn}" "${profile}" \
		"$(uqmid_field "$(ubus call "network.interface.${interface}" status 2>/dev/null)" '@.data.uqmid_bearer')"

	# Enable the modem unless somebody else did already: the modem is
	# released again only by the one who enabled it.
	state="$(uqmid_field "${modemstatus}" '@.state')"
	case "$state" in
		"disabled")
			uqmid_call "$modem" enable '{"enable":true}' >/dev/null || {
				proto_notify_error "${interface}" UQMID_MODEM_DISABLED
				return 1
			}
			uqmid_enabled_by_iface=1
			# Publish ownership immediately; teardown cannot see proto data until link-up.
			uqmid_write_enabled_marker "$enabled_marker" "$modem" || {
				uqmid_release_modem "$interface" "$modem" "$lowpower"
				proto_notify_error "${interface}" UQMID_OWNERSHIP_STATE_FAILED
				return 1
			}
			;;
		*)
			echo "modem already enabled (${state}), not touching its power"
			;;
	esac

	uqmid_setup_connect "$interface" "$modem" || {
		# teardown only gets the proto data of a successful setup
		uqmid_cleanup_connection "$modem" "$apn" "$profile" "$uqmid_bearer"
		if [ "$uqmid_enabled_by_iface" = "1" ]; then
			marker_modem=$(uqmid_take_enabled_marker "$enabled_marker")
			if [ "$?" -eq 0 ]; then
				[ -n "$marker_modem" ] && modem="$marker_modem"
				uqmid_release_modem "$interface" "$modem" "$lowpower"
			fi
		fi
		return 1
	}

	return 0
}

proto_uqmid_teardown() {
	local interface="$1"

	local modem status bearer enabled_by_iface enabled_marker marker_modem

	local device lowpower timeout
	json_get_vars device lowpower timeout

	[ -z "${timeout}" ] && timeout="120"

	echo "stopping network"

	# what the setup recorded in the interface data (available only after link-up)
	status=$(ubus call "network.interface.${interface}" status 2>/dev/null)
	bearer=$(uqmid_field "$status" '@.data.uqmid_bearer')
	enabled_by_iface=$(uqmid_field "$status" '@.data.uqmid_enabled_by_iface')

	enabled_marker=$(uqmid_enabled_marker_path "$interface") || enabled_marker=""
	if [ -n "$enabled_marker" ]; then
		marker_modem=$(uqmid_take_enabled_marker "$enabled_marker")
		if [ "$?" -eq 0 ]; then
			enabled_by_iface=1
			[ -n "$marker_modem" ] && modem="$marker_modem"
		fi
	fi

	[ -n "$modem" ] || modem=$(uqmid_find_modem "${device}")
	[ -n "${modem}" ] || {
		echo "modem not found: nothing to do"
		return
	}

	# disconnect only the bearer of this interface
	if [ -n "${bearer}" ]; then
		uqmid_call "$modem" simple_disconnect "{\"bearer\":\"${bearer}\"}" >/dev/null ||
			proto_notify_error "${interface}" DISCONNECT_FAILED
		uqmid_call "$modem" delete_bearer "{\"path\":\"${bearer}\"}" >/dev/null 2>&1
	else
		echo "couldn't load bearer path: nothing to disconnect"
	fi

	# only the one who enabled the modem disables it
	if [ "${enabled_by_iface}" = "1" ]; then
		uqmid_release_modem "$interface" "$modem" "$lowpower"
	else
		echo "modem was not enabled by this interface: skipping modem disable"
	fi
}

[ -n "$INCLUDE_ONLY" ] || {
	add_protocol uqmid
}
