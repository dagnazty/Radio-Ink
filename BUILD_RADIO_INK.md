# Building Radio Ink Firmware

This repo stores the Radio Ink build artifacts. The CrossPoint source checkout used for the build is currently:

```bash
/private/tmp/crosspoint-reader
```

The local PlatformIO executable is:

```bash
/Users/dag/Documents/GitHub/Radio_Ink/.venv/bin/pio
```

## Build

From the CrossPoint checkout:

```bash
cd /private/tmp/crosspoint-reader
/Users/dag/Documents/GitHub/Radio_Ink/.venv/bin/pio run -e default
```

The built firmware is created at:

```bash
/private/tmp/crosspoint-reader/.pio/build/default/firmware.bin
```

## Copy Firmware To Radio_Ink

After a successful build, copy the firmware into this repo under the Radio Ink artifact name:

```bash
cp /private/tmp/crosspoint-reader/.pio/build/default/firmware.bin \
  /Users/dag/Documents/GitHub/Radio_Ink/crosspoint-radio-ink-firmware.bin
```

We also refresh the older alias filename so nobody accidentally flashes a stale build:

```bash
cp /private/tmp/crosspoint-reader/.pio/build/default/firmware.bin \
  /Users/dag/Documents/GitHub/Radio_Ink/crosspoint-radio-audit-firmware.bin
```

## Export The Patch

From the CrossPoint checkout:

```bash
cd /private/tmp/crosspoint-reader
git diff --binary --output=/Users/dag/Documents/GitHub/Radio_Ink/crosspoint-radio-ink.patch
```

Refresh the older alias patch too:

```bash
cp /Users/dag/Documents/GitHub/Radio_Ink/crosspoint-radio-ink.patch \
  /Users/dag/Documents/GitHub/Radio_Ink/crosspoint-radio-audit.patch
```

## Verify

Check that the copied firmware matches the PlatformIO output:

```bash
shasum -a 256 \
  /private/tmp/crosspoint-reader/.pio/build/default/firmware.bin \
  /Users/dag/Documents/GitHub/Radio_Ink/crosspoint-radio-ink-firmware.bin \
  /Users/dag/Documents/GitHub/Radio_Ink/crosspoint-radio-audit-firmware.bin
```

All three hashes should match.

Check file sizes:

```bash
ls -lh \
  /Users/dag/Documents/GitHub/Radio_Ink/crosspoint-radio-ink-firmware.bin \
  /Users/dag/Documents/GitHub/Radio_Ink/crosspoint-radio-ink.patch \
  /Users/dag/Documents/GitHub/Radio_Ink/crosspoint-radio-audit-firmware.bin \
  /Users/dag/Documents/GitHub/Radio_Ink/crosspoint-radio-audit.patch
```

## One-Shot Refresh

After editing CrossPoint, this is the normal refresh flow:

```bash
cd /private/tmp/crosspoint-reader
/Users/dag/Documents/GitHub/Radio_Ink/.venv/bin/pio run -e default
cp .pio/build/default/firmware.bin /Users/dag/Documents/GitHub/Radio_Ink/crosspoint-radio-ink-firmware.bin
git diff --binary --output=/Users/dag/Documents/GitHub/Radio_Ink/crosspoint-radio-ink.patch
cp /Users/dag/Documents/GitHub/Radio_Ink/crosspoint-radio-ink-firmware.bin /Users/dag/Documents/GitHub/Radio_Ink/crosspoint-radio-audit-firmware.bin
cp /Users/dag/Documents/GitHub/Radio_Ink/crosspoint-radio-ink.patch /Users/dag/Documents/GitHub/Radio_Ink/crosspoint-radio-audit.patch
```

