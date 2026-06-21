#!/bin/bash
# Capture the device screen over USB serial -> /tmp/device_screen.png
# Usage: scripts/screenshot.sh [port]
set -e
cd "$(dirname "$0")/.."
PORT="${1:-/dev/cu.usbmodem11401}"

for i in 1 2 3 4 5 6; do
  out=$(.venv/bin/python scripts/grab_screen.py "$PORT" 2>&1 || true)
  got=$(echo "$out" | awk '{print $1}'); want=$(echo "$out" | awk '{print $2}')
  echo "  capture $i: $out"
  [ "$got" = "$want" ] && [ -n "$got" ] && break
done

/usr/bin/python3 - <<'PY'
from PIL import Image
data=bytearray(open("/tmp/fb.bin","rb").read())
TARGET=52272
if len(data)<TARGET: data += bytes([0xFF])*(TARGET-len(data))
data=data[:TARGET]
W,H=792,528; wb=W//8
img=Image.new("1",(W,H)); px=img.load()
for y in range(H):
    b=y*wb
    for x in range(W): px[x,y]=(data[b+(x>>3)]>>(7-(x&7)))&1
img.rotate(-90,expand=True).save("/tmp/device_screen.png")
print("  -> /tmp/device_screen.png")
PY
