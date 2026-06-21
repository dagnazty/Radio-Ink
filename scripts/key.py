#!/usr/bin/env python3
"""Inject button taps over serial. Usage: key.py DOWN DOWN SELECT [--port /dev/...]"""
import sys
import time

import serial

args = [a for a in sys.argv[1:] if not a.startswith("--")]
port = "/dev/cu.usbmodem11401"
if "--port" in sys.argv:
    port = sys.argv[sys.argv.index("--port") + 1]

ser = serial.Serial(port, 115200, timeout=1)
time.sleep(0.3)
ser.reset_input_buffer()
for k in args:
    ser.write(f"CMD:KEY:{k.upper()}\n".encode())
    ser.flush()
    time.sleep(0.9)  # let the e-ink redraw between taps
ser.close()
print("sent:", " ".join(a.upper() for a in args))
