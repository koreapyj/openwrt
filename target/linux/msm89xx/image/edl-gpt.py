#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Generate the GPT for the EDL installer from a layout description.

usage: edl-gpt.py <layout> <disk-sectors> <out-dir>
outputs: gpt_primary.bin (34 sectors: protective MBR, header, entry array)
         gpt_backup.bin  (33 sectors: entry array, header) for LBA disk-33 .. disk-1

Layout lines: "index name first-lba sectors type-guid attributes", plus
"disk-guid <guid>" and "entries <n>" (size of the entry array). Partition
GUIDs are derived from the disk GUID and the name so the output is reproducible.
"""
import os, struct, sys, uuid, zlib

SEC = 512
ESZ = 128

def main():
    layout, disk, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    disk_guid, nent, parts = None, 128, []
    for line in open(layout):
        line = line.split('#')[0].split()
        if not line:
            continue
        if line[0] == 'disk-guid':
            disk_guid = uuid.UUID(line[1])
        elif line[0] == 'entries':
            nent = int(line[1])
        else:
            parts.append((int(line[0]), line[1], int(line[2]), int(line[3]),
                          uuid.UUID(line[4]), int(line[5], 16)))
    assert disk_guid is not None
    assert nent * ESZ <= 32 * SEC
    ents = bytearray(32 * SEC)
    last_usable = disk - 34
    for idx, name, first, cnt, tguid, attr in parts:
        assert 1 <= idx <= nent and first >= 34 and first + cnt - 1 <= last_usable, name
        e = struct.pack('<16s16sQQQ72s', tguid.bytes_le,
                        uuid.uuid5(disk_guid, name).bytes_le,
                        first, first + cnt - 1, attr, name.encode('utf-16le'))
        ents[(idx - 1) * ESZ:idx * ESZ] = e
    ecrc = zlib.crc32(bytes(ents[:nent * ESZ]))

    def header(cur, alt, ent_lba):
        h = bytearray(struct.pack('<8sIIIIQQQQ16sQIII', b'EFI PART', 0x10000, 92, 0, 0,
                                  cur, alt, 34, last_usable, disk_guid.bytes_le,
                                  ent_lba, nent, ESZ, ecrc))
        struct.pack_into('<I', h, 16, zlib.crc32(bytes(h)))
        return bytes(h).ljust(SEC, b'\0')

    mbr = bytearray(SEC)
    mbr[446:462] = bytes.fromhex('00000100eeffffff01000000ffffffff')
    mbr[510:512] = b'\x55\xaa'
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, 'gpt_primary.bin'), 'wb') as f:
        f.write(mbr + header(1, disk - 1, 2) + ents)
    with open(os.path.join(out, 'gpt_backup.bin'), 'wb') as f:
        f.write(ents + header(disk - 1, 1, disk - 33))

main()
