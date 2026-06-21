#!/usr/bin/env python3
"""Capture the device framebuffer over USB serial via CMD:SCREENSHOT.
Writes raw bytes to /tmp/fb.bin and prints the byte count. Decode separately."""
import re
import sys
import time

import serial

PORT = sys.argv[1] if len(sys.argv) > 1 else "/dev/cu.usbmodem11401"

ser = serial.Serial(PORT, 115200, timeout=2)
time.sleep(0.3)
ser.reset_input_buffer()
ser.write(b"CMD:SCREENSHOT\n")
ser.flush()

size = None
deadline = time.time() + 8
while time.time() < deadline and size is None:
    m = re.search(rb"SCREENSHOT_START:(\d+)", ser.readline())
    if m:
        size = int(m.group(1))
if size is None:
    print("ERROR: no SCREENSHOT_START marker")
    sys.exit(1)

data = b""
deadline = time.time() + 20
while len(data) < size and time.time() < deadline:
    chunk = ser.read(size - len(data))
    if chunk:
        data += chunk
ser.close()

with open("/tmp/fb.bin", "wb") as f:
    f.write(data)
print(f"{len(data)} {size}")
