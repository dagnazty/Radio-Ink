# Radio Ink

Open-source RF-audit firmware for the **Xteink X3** (ESP32-C3 e-reader), forked from the
CrossPoint reader. It keeps the full e-reader (EPUB/TXT/XTC, OPDS, file transfer, KOReader sync)
and adds a **Wi-Fi / BLE auditing tool**, a custom **hacker-hiphop theme**, and a serial-driven
**dev rig** that lets a developer drive and screenshot the device over USB.

---

## 1. Hardware & platform

- **MCU:** ESP32-C3 (single-core RISC-V, ~400 KB SRAM, **no PSRAM**).
- **Display:** 792×528 e-ink, 1-bit, single framebuffer (52 272 bytes). Slow full refresh;
  fast/partial refresh leaves ghosting in the single buffer (see dev rig notes).
- **RTC:** DS3231 (I²C `0x68`) — battery-backed, X3-only. Tracks **time-of-day only** (no date);
  synced from NTP on first WiFi connect.
- **Battery:** `powerManager.getBatteryPercentage()`.
- **Flash:** ~84 % used. No room for large lookup tables (e.g. a full OUI DB).

## 2. Repo, build, flash

The firmware **lives in this repo** (`/Users/dag/Documents/GitHub/Radio_Ink`, a git repo with the
upstream CrossPoint history). It was relocated here from the old ephemeral `/private/tmp` checkout.

```bash
# build
.venv/bin/pio run -e default                      # -> .pio/build/default/firmware.bin
# flash
.venv/bin/pio run -e default -t upload --upload-port /dev/cu.usbmodemXXXX
# keep a named artifact
cp .pio/build/default/firmware.bin radioink-firmware.bin
```

The old standalone serial module was archived under `archive/standalone-module/`.

## 3. Dev rig — drive & screenshot over USB  ⭐

The main loop parses `CMD:` lines on USB serial. Two commands make visual iteration possible
without photos or WiFi:

- **`CMD:SCREENSHOT`** — dumps the raw 52 272-byte framebuffer between `SCREENSHOT_START:<n>` and
  `SCREENSHOT_END`. It takes a `RenderLock` (no torn frames) and writes in flushed 512-byte chunks
  (the USB-CDC TX buffer would otherwise overflow and drop bytes).
- **`CMD:KEY:<UP|DOWN|SELECT|BACK|LEFT|RIGHT|POWER>`** — injects a synthetic button tap. Implemented
  in `HalGPIO` as a one-shot state machine (press frame → release frame) OR'd into
  `wasPressed`/`wasReleased`/`isPressed`, so it satisfies both press- and release-driven activities.

Host scripts:

| Script | Purpose |
|---|---|
| `scripts/grab_screen.py` | capture the framebuffer to `/tmp/fb.bin` (venv pyserial) |
| `scripts/screenshot.sh`  | capture + decode → `/tmp/device_screen.png` (system PIL) |
| `scripts/key.py UP DOWN SELECT` | inject a sequence of taps |

**Clean captures:** entering an activity does a full refresh, so navigate *into* a screen, then
capture. Screens that re-render asynchronously (Home loads book covers, Settings rebuilds its list)
ghost the single buffer after entry — capture them right after a full refresh.

```bash
scripts/key.py DOWN DOWN DOWN DOWN SELECT   # Home -> Radio Ink
scripts/screenshot.sh                       # -> /tmp/device_screen.png
```

## 4. Radio Ink audit tool

`src/activities/util/RadioAuditActivity.{h,cpp}` — reachable from Home → **Radio Ink**. The action
menu is grouped into **submenu categories**:

- **Scan:** Quick Scan, Deep Scan, Client Recon (probes)
- **Results:** Audit Findings, View WiFi results, View BLE results, Channel usage
- **Export:** Save text / CSV / JSON

### Scanning
- **Quick/Deep Scan** — multi-pass WiFi (`WiFi.scanNetworks`) + BLE (passive, WiFi off first to
  avoid coexistence OOM). Deep = 3 passes; merges findings, averages RSSI, tracks seen-count.
- **Per-target deep scan** — Select a WiFi/BLE row in the results list to drill in.
  - *WiFi:* locks to the AP channel in **promiscuous mode** (`esp_wifi_set_promiscuous`) and parses
    802.11 frames for: associated **client MACs**, RSSI avg/min/max, beacon/data/mgmt counts,
    **deauth/disassoc** frames (attack/evil-twin signal), and security posture from beacons
    (Privacy / PMF / WPS) + randomized-BSSID detection.
  - *BLE:* focused multi-pass scan of one address → RSSI profile, company ID, services, TX power,
    random-address detection.
- **Client Recon** — channel-hops 1–13 in promiscuous mode capturing **probe requests**: client
  MACs + the SSIDs their devices are searching for.

### Intelligence
- **BLE advertiser decoding** — iBeacon (UUID + major/minor), Eddystone (UID/URL/TLM), Apple
  Continuity incl. **AirTag/FindMy**, AirPods, Swift Pair, Fast Pair — decoded from the manufacturer
  / service data already captured.
- **Vendor lookup** — curated OUI→vendor table (Espressif, Apple, Raspberry Pi, Samsung, …) for
  AP/client/BLE MACs; flags locally-administered ("randomized") MACs.
- **Auto findings** — WPS, missing PMF, open/WEP, close BLE, **possible tracker** (AirTag),
  deauth activity, etc. Findings are selectable → jump to the related target's deep scan.
- **Watchlist** — drop `/.radioink/watchlist.txt` (one MAC/prefix per line); matches raise a HIGH
  "Watchlist hit".
- **Scan-to-scan diff** — each scan compares against the previous snapshot
  (`/.radioink/last_scan.txt`) and flags **NEW / GONE** devices.
- **Channel usage** — bar chart of APs per channel from the last scan.
- **RSSI locator** — from a deep-scan detail, "Locate" gives a live signal meter + warmer/colder to
  physically find the target.

### Output
- **Reports** — text / CSV / JSON saved under `/.radioink/`, stamped with the RTC time of scan.

## 5. Theme — `RadioInkTheme` (hacker × hiphop)

`src/components/themes/radioink/RadioInkTheme.{h,cpp}` — extends `LyraTheme`, reuses `LyraMetrics`.
Registered as `RadioInkSettings::UI_THEME::RADIO_INK` and set as the default (one-time migration
in `main.cpp` switches existing devices).

| Override | What it does |
|---|---|
| `drawHeader` | bracketed brand/title `[ … ]` top-left, bold; heavy 3px rule; keeps clock+battery; header band tightened (60px) |
| `drawButtonMenu` | inverted black selection bar, white bold text, `> ` prompt marker (Home menu) |
| `drawList` | same inverted `> ` selection for Settings / Radio Ink / browser lists; white value on the bar |
| `drawButtonHints` | stamps the **skull logo** bottom-right on every page |

**Logo on every page:** drawn in `drawButtonHints` (the last call before `displayBuffer`, so body
content never covers it). Books are excluded automatically (the reader uses `drawStatusBar`, no
button hints). Data/log views opt out via `UITheme::suppressBrandLogoOnce()`. Skull bitmaps are
compiled-in 1-bpp headers (`src/images/RadioInkSkull.h`), pre-rotated 90° because `drawImage` does
not rotate bits for the portrait panel.

## 6. Device-wide header (clock + battery)

`drawHeader` in **all** themes now reads the same Status Bar settings the reader uses
(`statusBarClock`, `statusBarBattery`, `clockFormat`, `clockUtcOffsetQ`) so the toggles control the
**whole device**, not just books. "Customise Status Bar" was moved from Settings → Reader to
**Settings → Display**. `statusBarClock` defaults on, with a one-time migration so existing devices
get the header clock.

## 7. CrossPoint → Radio Ink rename

Deep rename across source, `lib`, build system, translations, and 8 renamed files. The on-disk data
dir moved `/.crosspoint → /.radioink` with a one-time migration in `main.cpp`. **Preserved**
(external resources we don't own): the OTA + font GitHub URLs (`crosspoint-reader/*`) and the
Calibre "CrossPoint Reader" plugin name.

## 8. One-time migrations (in `main.cpp`, sentinel files under `/.radioink/`)

| Marker | Effect |
|---|---|
| `/.crosspoint` → `/.radioink` rename | preserve existing settings/books/exports |
| `.hdrclk_migrated` | enable the device header clock once |
| `.theme_migrated`  | switch to the Radio Ink theme once |

## 9. Key files

```
src/activities/util/RadioAuditActivity.{h,cpp}     audit tool
src/components/themes/radioink/RadioInkTheme.{h,cpp} theme
src/components/themes/lyra/LyraTheme.*              base theme + metrics
src/images/RadioInkSkull.h                          logo bitmap (128px)
src/main.cpp                                        loop, CMD: handlers, migrations
lib/hal/HalGPIO.{h,cpp}                             button input + tap injection
scripts/grab_screen.py, key.py, screenshot.sh       dev rig
```
