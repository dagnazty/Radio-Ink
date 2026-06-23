#!/usr/bin/env python3
"""Convert a video / GIF into a Radio Ink ".rivid" 1-bit frame pack for the
on-device flipbook player (MoviePlayerActivity).

This is an OFF-DEVICE tool. Real conversion needs `ffmpeg`/`ffprobe` on PATH and
the `Pillow` Python package (for fast Floyd-Steinberg dithering):
    brew install ffmpeg          # or: apt install ffmpeg
    pip install Pillow

Usage:
    python3 scripts/gen_video.py shrek.gif shrek.rivid --width 320 --fps 3
    python3 scripts/gen_video.py --test-pattern 320x180 --frames 120 --fps 6 test.rivid

Then copy the .rivid to the SD card under /.radioink/movies/ and pick it in the
Movies menu.

The X4 is an 800x480 monochrome e-ink panel refreshing at a few fps, so keep
--width small (240-400) and --fps low (2-6). Full color becomes 1-bit dithered;
high-contrast sources (silhouettes, line art) look far better than live action.

.rivid format (all little-endian):
    0  4  magic 'R','I','V','D'
    4  1  version (1)
    5  1  flags (0)
    6  2  width  uint16
    8  2  height uint16
    10 1  fps    uint8
    11 1  reserved
    12 4  frameCount uint32
    16 .. frames: frameCount * stride bytes, stride = ((width+7)//8) * height
           each frame row-major, each row ceil(width/8) bytes, MSB-first,
           bit = 1 means a black (ink) pixel.
"""

import argparse
import struct
import subprocess
import sys

HEADER_SIZE = 16
MAGIC = b"RIVD"


def write_header(f, width, height, fps, frame_count):
    f.seek(0)
    f.write(MAGIC)
    f.write(struct.pack("<BBHHBBI", 1, 0, width, height, fps, 0, frame_count))


def stride_for(width):
    return (width + 7) // 8


def probe_height(path, width):
    """Scale `width` to the source aspect, returning an even height."""
    out = subprocess.check_output(
        ["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries",
         "stream=width,height", "-of", "csv=p=0", path]
    ).decode().strip()
    in_w, in_h = (int(x) for x in out.split(",")[:2])
    h = round(width * in_h / in_w)
    return h + (h & 1)  # make even (ffmpeg-friendly)


def convert(input_path, output_path, width, fps):
    try:
        from PIL import Image, ImageOps
    except ImportError:
        sys.exit("error: Pillow not installed. Run: pip install Pillow")
    try:
        height = probe_height(input_path, width)
    except (OSError, subprocess.CalledProcessError):
        sys.exit("error: ffprobe failed (is ffmpeg installed and on PATH?)")

    stride = stride_for(width)
    frame_bytes = width * height  # 8-bit gray from ffmpeg
    cmd = ["ffmpeg", "-v", "error", "-i", input_path, "-vf",
           "fps=%d,scale=%d:%d:flags=area,format=gray" % (fps, width, height),
           "-f", "rawvideo", "-pix_fmt", "gray", "pipe:1"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)

    count = 0
    with open(output_path, "wb") as out:
        out.write(b"\x00" * HEADER_SIZE)  # placeholder, rewritten at the end
        while True:
            raw = proc.stdout.read(frame_bytes)
            if len(raw) < frame_bytes:
                break
            # Invert so dark pixels become ink, then dither to 1-bit. Pillow packs
            # mode '1' MSB-first with rows padded to a byte -- matches our stride.
            im = ImageOps.invert(Image.frombytes("L", (width, height), raw))
            packed = im.convert("1").tobytes()
            assert len(packed) == stride * height, (len(packed), stride * height)
            out.write(packed)
            count += 1
        write_header(out, width, height, fps, count)
    proc.wait()
    report(output_path, width, height, fps, count, stride)


def test_pattern(output_path, width, height, frames, fps):
    """Pure-stdlib synthetic clip (a bouncing ink box) to verify the player
    without ffmpeg/Pillow or any source video."""
    stride = stride_for(width)
    box = max(8, min(width, height) // 4)
    with open(output_path, "wb") as out:
        out.write(b"\x00" * HEADER_SIZE)
        for n in range(frames):
            # Bounce the box across the frame.
            t = n / max(1, frames - 1)
            bx = int((width - box) * abs(1 - 2 * ((n / 20.0) % 1)))
            by = int((height - box) * t)
            frame = bytearray(stride * height)
            for y in range(by, by + box):
                row = y * stride
                for x in range(bx, bx + box):
                    frame[row + (x >> 3)] |= 0x80 >> (x & 7)  # bit=1 -> ink
            out.write(frame)
        write_header(out, width, height, fps, frames)
    report(output_path, width, height, fps, frames, stride)


def report(path, w, h, fps, count, stride):
    import os
    size = os.path.getsize(path)
    print("Wrote %s: %dx%d, %d fps, %d frames, %d bytes (%.1f MB)"
          % (path, w, h, fps, count, size, size / 1048576.0))
    print("Copy it to the SD card at /.radioink/movies/")


def main():
    ap = argparse.ArgumentParser(description="Build a .rivid flipbook for Radio Ink")
    ap.add_argument("input", nargs="?", help="source video/GIF (omit with --test-pattern)")
    ap.add_argument("output", help="output .rivid path")
    ap.add_argument("--width", type=int, default=320, help="frame width (240-400 recommended)")
    ap.add_argument("--fps", type=int, default=3, help="playback fps (2-6 recommended)")
    ap.add_argument("--test-pattern", metavar="WxH",
                    help="generate a synthetic clip instead of converting (e.g. 320x180)")
    ap.add_argument("--frames", type=int, default=120, help="frame count for --test-pattern")
    args = ap.parse_args()

    if args.width < 8 or args.width > 800:
        sys.exit("error: --width must be 8..800")
    if args.fps < 1 or args.fps > 30:
        sys.exit("error: --fps must be 1..30")

    if args.test_pattern:
        try:
            w, h = (int(x) for x in args.test_pattern.lower().split("x"))
        except ValueError:
            sys.exit("error: --test-pattern must look like 320x180")
        test_pattern(args.output, w, h, args.frames, args.fps)
    else:
        if not args.input:
            sys.exit("error: provide an input file (or use --test-pattern)")
        convert(args.input, args.output, args.width, args.fps)


if __name__ == "__main__":
    main()
