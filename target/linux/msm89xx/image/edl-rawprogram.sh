#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Generate rawprogram0.xml / patch0.xml for an EDL installer. Start sector and size
# of each partition come from the GPT layout description, and every image is checked
# to fit. The GPT images (written last, so the old table stays valid until all
# partitions are in place) are appended automatically.
# usage: edl-rawprogram.sh <dir> <sector-size> <layout> <disk-sectors> {<file> <label>}...
set -e
dir=$1; ss=$2; layout=$3; disk=$4; shift 4
out=$dir/rawprogram0.xml

prog() { # file label start sectors partofsingleimage
	printf '  <program SECTOR_SIZE_IN_BYTES="%s" file_sector_offset="0" filename="%s" label="%s" num_partition_sectors="%s" partofsingleimage="%s" physical_partition_number="0" readbackverify="false" size_in_KB="%s" sparse="false" start_byte_hex="0x%x" start_sector="%s"/>\n' \
		"$ss" "$1" "$2" "$4" "$5" "$(awk -v c="$4" -v s="$ss" 'BEGIN{printf "%.1f", c*s/1024}')" $(( $3 * ss )) "$3"
}

{
	echo '<?xml version="1.0" ?>'
	echo '<data>'
	while [ $# -ge 2 ]; do
		f=$1; label=$2; shift 2
		read -r start psz <<EOF
$(awk -v n="$label" '$1 ~ /^[0-9]+$/ && $2 == n {print $3, $4}' "$layout")
EOF
		[ -n "$start" ] || { echo "EDL: no partition '$label' in $layout" >&2; exit 1; }
		size=$(stat -c %s "$dir/$f")
		cnt=$(( (size + ss - 1) / ss ))
		if [ "$cnt" -gt "$psz" ]; then
			echo "EDL: $f needs $cnt sectors, partition '$label' has only $psz" >&2
			exit 1
		fi
		prog "$f" "$label" "$start" "$cnt" false
	done
	prog gpt_backup.bin BackupGPT $(( disk - 33 )) 33 true
	prog gpt_primary.bin PrimaryGPT 0 34 true
	echo '</data>'
} > "$out"
cat > "$dir/patch0.xml" <<'X'
<?xml version="1.0" ?>
<patches>
</patches>
X
