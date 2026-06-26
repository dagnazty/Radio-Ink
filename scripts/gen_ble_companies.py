# Generates a sorted, binary-searchable BLE company-ID -> vendor database for the
# SD card from the committed Bluetooth SIG snapshot at data/ble/company_ids.csv.
#
# Output: data/ble/ble_companies.bin  (copy to the SD card at /.radioink/ble_companies.bin).
#
# The firmware (ra::bleCompanyById in RadioAuditActivity.cpp) binary-searches this
# file by seeking -- it is NOT compiled into flash, keeping the table off the app
# partition (same approach as oui.bin). If the file is absent, BLE vendor lookups
# fall back to the small built-in set (graceful).
#
# Format (all little-endian):
#   magic   'B','L','E','C'        (4 bytes)
#   count   uint32                 (4 bytes)
#   records count x 32 bytes, sorted ascending by id:
#     id    uint16  (SIG company identifier)
#     pad   uint16  (0, keeps the name 4-byte aligned)
#     name  28 bytes, NUL-padded (truncated to 27 chars)

import os
import struct

ROOT = os.getcwd()
SRC = os.path.join(ROOT, "data", "ble", "company_ids.csv")
OUT = os.path.join(ROOT, "data", "ble", "ble_companies.bin")

NAME_FIELD = 28               # bytes per name (27 chars + NUL)
RECORD_SIZE = 4 + NAME_FIELD  # uint16 id + uint16 pad + name = 32 bytes
MAGIC = b"BLEC"


def main():
    rows = []  # (id_int, name_bytes)
    with open(SRC, encoding="ascii") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            hex4, _, name = line.partition(",")
            hex4 = hex4.strip()
            if not hex4:
                continue
            try:
                cid = int(hex4, 16)
            except ValueError:
                continue
            if cid > 0xFFFF:
                continue
            name_bytes = name.encode("ascii", "ignore")[: NAME_FIELD - 1]
            rows.append((cid, name_bytes))

    rows.sort(key=lambda r: r[0])

    with open(OUT, "wb") as out:
        out.write(MAGIC)
        out.write(struct.pack("<I", len(rows)))
        for cid, name in rows:
            out.write(struct.pack("<HH", cid, 0))
            out.write(name + b"\x00" * (NAME_FIELD - len(name)))

    size = os.path.getsize(OUT)
    print("Wrote %s: %d companies, %d bytes (%.1f KB)" % (OUT, len(rows), size, size / 1024.0))
    print("Copy it to the SD card at /.radioink/ble_companies.bin")


if __name__ == "__main__":
    main()
