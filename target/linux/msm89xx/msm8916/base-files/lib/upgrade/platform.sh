PART_NAME=firmware
REQUIRE_IMAGE_METADATA=1

platform_check_image() {
	return 0
}

platform_do_upgrade() {
	case "$(board_name)" in
	generic,ufi-esim|\
	yiming,uz801-v3)
		CI_KERNPART="boot"
		CI_ROOTPART="userdata"
		emmc_do_upgrade "$1"
		;;
	*)
		default_do_upgrade "$1"
		;;
	esac
}

platform_copy_config() {
	case "$(board_name)" in
	generic,ufi-esim|\
	yiming,uz801-v3)
		emmc_copy_config
		;;
	esac
}
