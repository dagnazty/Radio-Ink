# Generates a sorted, binary-searchable OUI -> vendor database for the SD card
# from the committed IEEE registry snapshot at data/oui/oui.min.csv.
#
# Output: data/oui/oui.bin  (copy to the SD card at /.radioink/oui.bin).
#
# The firmware (ra::macVendor in RadioAuditActivity.cpp) binary-searches this
# file by seeking -- it is NOT compiled into flash, keeping the ~660 KB table
# off the app partition. If the file is absent, vendor lookups simply return ""
# (graceful: same as an unknown OUI).
#
# Format (all little-endian):
#   magic   'O','U','I','B'        (4 bytes)
#   count   uint32                 (4 bytes)
#   records count x 32 bytes, sorted ascending by oui:
#     oui   uint32  (first 3 MAC octets in the low 24 bits)
#     name  28 bytes, NUL-padded (truncated to 27 chars)

import os
import struct

ROOT = os.getcwd()
SRC = os.path.join(ROOT, "data", "oui", "oui.min.csv")
OUT = os.path.join(ROOT, "data", "oui", "oui.bin")

NAME_FIELD = 28          # bytes per name (27 chars + NUL)
RECORD_SIZE = 4 + NAME_FIELD  # 32 bytes/record
MAGIC = b"OUIB"


def main():
    rows = []  # (oui_int, name_bytes)
    with open(SRC, encoding="ascii") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            hex6, _, name = line.partition(",")
            if len(hex6) != 6:
                continue
            name_bytes = name.encode("ascii", "ignore")[: NAME_FIELD - 1]
            rows.append((int(hex6, 16), name_bytes))

    rows.sort(key=lambda r: r[0])

    with open(OUT, "wb") as out:
        out.write(MAGIC)
        out.write(struct.pack("<I", len(rows)))
        for oui, name in rows:
            out.write(struct.pack("<I", oui))
            out.write(name + b"\x00" * (NAME_FIELD - len(name)))

    size = os.path.getsize(OUT)
    print("Wrote %s: %d OUIs, %d bytes (%.2f MB)" % (OUT, len(rows), size, size / 1048576.0))
    print("Copy it to the SD card at /.radioink/oui.bin")


if __name__ == "__main__":
    main()
