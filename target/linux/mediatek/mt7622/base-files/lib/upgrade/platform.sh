platform_do_upgrade() {
	local board=$(board_name)

	case "$board" in
	bananapi,bpi-r64)
		export_bootdevice
		export_partdevice rootdev 0
		case "$rootdev" in
		mmc*)
			CI_ROOTDEV="$rootdev"
			CI_KERNPART="production"
			emmc_do_upgrade "$1"
			;;
		*)
			CI_KERNPART="fit"
			nand_do_upgrade "$1"
			;;
		esac
		;;
	bananapi,bpi-r64-rootdisk)
		#2097152=0x200000 is the offset in bytes from the start
		#of eMMC and to the location of the kernel
		get_image "$1" | dd of=/dev/mmcblk0 bs=2097152 seek=1 conv=fsync
		;;
	iptime,ax8004m|\
	mediatek,mt7622,ubi)
		nand_do_upgrade "$1"
		;;
	*)
		default_do_upgrade "$1"
		;;
	esac
}

PART_NAME=firmware

platform_check_image() {
	local board=$(board_name)
	local magic="$(get_magic_long "$1")"

	[ "$#" -gt 1 ] && return 1

	case "$board" in
	*)
		[ "$magic" != "d00dfeed" ] && {
			echo "Invalid image type."
			return 1
		}
		return 0
		;;
	esac

	return 0
}

platform_copy_config_emmc() {
	mkdir -p /recovery
	mount -o rw,noatime /dev/mmcblk0p6 /recovery
	cp -af "$UPGRADE_BACKUP" "/recovery/$BACKUP_FILE"
	sync
	umount /recovery
}

platform_copy_config() {
	case "$(board_name)" in
	bananapi,bpi-r64-rootdisk)
		platform_copy_config_emmc
		;;
	esac
}
