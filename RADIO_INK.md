# Radio Ink

Open-source RF-audit firmware for the **Xteink X3 / X4** (ESP32-C3 e-ink devices), forked from the
[CrossPoint Reader](https://github.com/crosspoint-reader/crosspoint-reader). It keeps the full
e-reader (EPUB/TXT/XTC, OPDS, file transfer, KOReader sync) and adds a **Wi-Fi / BLE auditing
toolkit**, a custom **hacker-hiphop theme**, and a serial-driven **dev rig** that lets a developer
drive and screenshot the device over USB.

- **Author:** dag nazty — <https://dagnazty.dev>
- **Version:** `1.3.0` base (`RADIOINK_VERSION` adds branch + short SHA; shown on the boot screen,
  Settings header, and **Radio Ink → About**).
- **Built on:** CrossPoint Reader by Dave Allie & community (MIT); originally inspired by atomic14's
  [diy-esp32-epub-reader](https://github.com/atomic14/diy-esp32-epub-reader). See [Credits](#10-credits--license).
- ⚠️ **Authorized testing only.** Transmitting/attack features are compiled out of release builds and
  require an on-device confirmation in dev builds.

---

## 1. Hardware & platform

- **MCU:** ESP32-C3 (single-core RISC-V, ~400 KB SRAM, **no PSRAM**).
- **Display:** 792×528 e-ink, 1-bit, single framebuffer (52 272 bytes). Slow full refresh;
  fast/partial refresh leaves ghosting in the single buffer (see dev rig notes).
- **RTC:** DS3231 (I²C `0x68`) — battery-backed, X3-only. Tracks **time-of-day only** (no date);
  synced from NTP on first WiFi connect.
- **Battery:** `powerManager.getBatteryPercentage()`.
- **Flash:** ~85 % of a 6.25 MB app partition (dual-OTA layout). No room for large lookup tables
  (e.g. a full OUI DB).
- **RAM discipline:** result vectors are `reserve()`d at activity entry and the 32 KB PCAP ring +
  capture tables are heap-allocated **on demand** (freed when idle) so the BLE controller (~65 KB at
  init) has headroom. BLE scans are heap-floor guarded and run in bounded short windows.

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

`src/activities/util/RadioAuditActivity.{h,cpp}` (+ stateless helpers in `RadioAuditHelpers.{h,cpp}`)
— reachable from Home → **Radio Ink**. Menu is a two-level category tree: an `enum class Action`
dispatched by an exhaustive `switch`, with categories declared as data tables (add a category + a
case to extend). Categories:

| Category | Items |
|---|---|
| **Recon** | Quick Scan · Deep Scan · WiFi Scan · BLE Scan · Client Recon (probes) · Channel usage · Tracker Sweep |
| **Capture** | Live PCAP capture · Handshake / PMKID |
| **Attacks** ⚠ *(dev builds only)* | Deauth (all APs) · Deauth selected · Beacon flood · Evil Twin / Portal · BLE Spoof |
| **Files** | Browse SD files |
| **Results** | Audit Findings · View WiFi results · View BLE results · Camera Sweep |
| **Export** | Save text / CSV / JSON |
| **About** | Version + credits |

### Recon (passive)
- **Quick/Deep Scan** — multi-pass WiFi (`WiFi.scanNetworks`) + BLE (active, WiFi off first to avoid
  coexistence OOM). Deep = 3 passes; merges findings, averages RSSI, tracks seen-count.
- **Per-target deep scan** — Select a WiFi/BLE row to drill in. The detail view's **Actions** menu
  offers (WiFi) mark-for-deauth / deauth-this-AP / locate, or (BLE) **GATT enumerate** / locate.
  - *WiFi:* locks to the AP channel in **promiscuous mode** and parses 802.11 for associated **client
    MACs**, RSSI avg/min/max, beacon/data/mgmt counts, **deauth/disassoc** frames, and security
    posture (Privacy / PMF / WPS) + randomized-BSSID detection.
  - *BLE:* focused scan → RSSI, company ID, services, TX power; **GATT enumerate** connects and dumps
    services/characteristics (R/W/N/I).
- **Client Recon** — channel-hops 1–13 capturing **probe requests** (client MACs + searched SSIDs).
- **Tracker Sweep** — active BLE scan flagging **AirTag/FindMy, Tile, Samsung SmartTag, Chipolo**.

### Capture (→ SD)
- **Live PCAP** — promiscuous frames streamed to `/.radioink/captures/*.pcap` (LINKTYPE_IEEE802_11)
  via a lock-free SPSC ring (Wi-Fi callback producer → activity-loop SD writer). Open in Wireshark.
- **Handshake / PMKID** — detects EAPOL M1/M2 (ANONCE/MIC, MIC zeroed) and RSN PMKID, exports
  **hashcat `22000`** to `/.radioink/captures/hs-*.22000`. In-screen **Deauth** forces a reconnect
  and locks the channel to catch the handshake without leaving the screen.

### Attacks ⚠ (compiled out of release; one-time on-device authorization in dev builds)
Requires `-DRADIO_AUDIT_ENABLE_ACTIVE` (in `[env:default]` only) and `-Wl,--allow-multiple-definition`
to override the IDF's `ieee80211_raw_frame_sanity_check` for raw TX.
- **Deauth** — focused (one AP from its detail menu), grouped (mark several in WiFi results, then
  "Deauth selected"), or all visible APs. Round-robins targets, broadcast deauth+disassoc.
- **Beacon flood** — random SSIDs across channels.
- **Evil Twin / Portal** — open rogue AP cloning a chosen SSID + DNS captive portal + credential
  page → `/.radioink/loot/`. (`EvilTwinActivity`, also compiled out of release.)
- **BLE Spoof** — floods phantom BLE advertisers.

### Analysis & output
- **Audit findings** — WPS, missing PMF, open/WEP, duplicate-SSID/rogue-AP, deauth activity,
  possible tracker, etc. Selectable → jump to the related target's deep scan.
- **Camera Sweep** — runs a fresh WiFi AP scan + **associated-client OUI capture** + active BLE, then
  fingerprints likely cameras (camera SSIDs/names, Amazon = Ring/Blink clients, Hikvision/Dahua/Axis).
- **Intelligence** — OUI→vendor lookup, BLE advert decode (iBeacon/Eddystone/Apple Continuity),
  `watchlist.txt` matching, scan-to-scan **NEW/GONE** diff, channel-usage map, RSSI **locator**.
- **Files browser** — list/delete everything under `/.radioink/` on-device.
- **Reports** — TXT / CSV / JSON under `/.radioink/`, RTC-stamped.

### SD layout
```
/.radioink/
├── radio_ink/    reports + watchlist.txt + last_scan.txt (diff snapshot)
├── captures/     *.pcap, *.22000
└── loot/         evil-twin captured credentials (dev builds)
```

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
src/activities/util/RadioAuditActivity.{h,cpp}      audit tool (menu, scans, capture, attacks)
src/activities/util/RadioAuditHelpers.{h,cpp}       stateless helpers (hex/MAC/OUI/BLE decode/classifiers)
src/activities/util/EvilTwinActivity.{h,cpp}        rogue AP + captive portal (dev builds only)
src/components/themes/radioink/RadioInkTheme.{h,cpp} theme
src/components/themes/lyra/LyraTheme.*              base theme + metrics
src/images/RadioInkSkull.h                          logo bitmap (128px)
src/main.cpp                                        loop, CMD: handlers, migrations
lib/hal/HalGPIO.{h,cpp}                             button input + tap injection
scripts/grab_screen.py, key.py, screenshot.sh       dev rig
```

## 10. Credits & license

Radio Ink is a fork and would not exist without the upstream work it builds on:

- **[CrossPoint Reader](https://github.com/crosspoint-reader/crosspoint-reader)** — by **Dave Allie**
  and the CrossPoint community. Radio Ink keeps CrossPoint's reading engine, HAL, theming, i18n, and
  wireless stack; the e-reader half of this firmware is entirely their work.
- **[diy-esp32-epub-reader](https://github.com/atomic14/diy-esp32-epub-reader)** by **atomic14** —
  the project that originally inspired CrossPoint.
- The CrossPoint contributors, translators, and community-fork authors (see upstream
  [GOVERNANCE.md](./GOVERNANCE.md)).
- **Radio Ink** — the RF-audit fork, audit tool, theme, and dev rig — by **dag nazty**
  (<https://dagnazty.dev>), at <https://github.com/dagnazty/Radio-Ink>.

**License:** MIT (see [LICENSE](./LICENSE)) — original copyright © 2025 Dave Allie; Radio Ink
modifications retain the same MIT license. **Not affiliated with Xteink.** Authorized testing only.
