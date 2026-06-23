# Changelog

All notable changes to **Radio Ink** are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions track `[radioink] version`
in `platformio.ini` and the GitHub release tags.

## [1.1.1] — 2026-06-22

### Added
- **Movie autoloop toggle** — Pause or End screen shows an `Autoloop: [ ]/[x]` box (Up toggles it);
  when on, finished movies restart instead of stopping. Choice persists across reboots.

### Changed
- **Camera Sweep ranking** — confident vendor/OUI camera hits (Ring/Blink) now sort to the top;
  low-confidence randomized-MAC candidates sink to the bottom (stronger signal first within each tier).
- **About screen** shows device model (X3/X4) and free heap.

### Fixed
- Movies menu ignored the front Left/Right buttons — now navigates via the shared `NavNext`/`NavPrevious`
  aggregate (side + front buttons, orientation-aware) like every other menu.
- File browser hides OS cruft (`.Spotlight-V100`, `.Trashes`, `.fseventsd`, `.DS_Store`,
  `.TemporaryItems`, AppleDouble `._*`) even with hidden files shown; `/.radioink` stays visible.
- Movie player no longer busy-spins between frames (yields when idle) — lower CPU/battery during playback.

## [1.1.0] — 2026-06-22

### Added
- **Deauth Detector** (Recon) — passive promiscuous monitor that tallies deauth/disassoc frames per
  source MAC, flags floods, and logs offenders to `/.radioink/captures/deauth-*.txt`.
- **Interactive Camera Sweep** — camera hits are now a selectable list; pick one to open a detail view
  with **Locate** (RSSI hunt) and **Deauth** (directed, kicks the camera off its AP).
- **Ring/Blink detection** — hardcoded Ring/Blink/Amazon OUIs (works with no database), substring
  vendor matching, and **randomized-MAC clients** surfaced as camera candidates.
- **WiGLE-1.4 CSV export** for wardriving; optional `/.radioink/radio_ink/location.txt` (`lat,lon`)
  stamps real coordinates (no onboard GPS).
- **Karma / probe-response** attack (dev builds) — beacons back the SSIDs clients probe for.
- **39,572-vendor IEEE OUI database** on the SD card (`/.radioink/oui.bin`, built by
  `scripts/gen_oui.py`), keeping ~660 KB off the app partition.
- **Movies** — novelty 1-bit monochrome e-ink flipbook player (`.rivid` packs built off-device by
  `scripts/gen_video.py`); reachable from the Home menu.
- **About** screen in the Home menu (moved out of the Radio Ink menu).
- Dev rig: `CMD:SCREENSHOT` / `CMD:KEY:` serial commands for off-device UI capture and control.

### Changed
- **Unified file browser** — one browser for the whole device: the Home "Browse Files" now lists every
  file with sizes and shows dot-folders like `/.radioink`; the Radio Ink "Files" entry was removed.
- **Home menu scrolls** — `RadioInkTheme::drawButtonMenu` windows rows so off-screen items (e.g.
  About) stay reachable; benefits every Radio Ink menu.
- Camera Sweep capture dwells on the discovered AP channels (far higher client hit-rate) and records
  each client's AP BSSID + channel for accurate locate/deauth.
- Promiscuous management-frame callbacks share one `parsePromiscFrame` helper (dedup + centralized
  bounds checks).
- Movie blit uses precomputed scaling lookup tables instead of a per-pixel divide.

### Fixed
- **X3 RTC drift/reset across sleep** — `HalClock` now clears the DS3231 `EOSC` bit (oscillator keeps
  running on the backup battery) and reads `OSF` to detect a stopped oscillator; a known-invalid time
  shows blank instead of wrong.
- Home logo no longer collides with a selected bottom menu row (menu reserves the skull's corner).
- OUI database is found whether it's at `/.radioink/oui.bin` or the SD root.

## [1.0.0] — 2026-06-21

Initial **Radio Ink** release: rebrand of the CrossPoint e-reader firmware into an RF audit / pentest
tool for the Xteink X-series (ESP32-C3), keeping the full reader intact.

### Added
- **Radio Audit toolkit** under Home → Radio Ink (category-tree menu):
  - Recon: Quick/Deep scan, WiFi scan, BLE scan, Client Recon (probes), Channel usage, Tracker Sweep
    (AirTag/FindMy/Tile/SmartTag/Chipolo), per-target deep scan with GATT enumerate.
  - Capture: live PCAP to SD (Wireshark-openable), handshake/PMKID → hashcat 22000.
  - Attacks (dev builds only, behind `RADIO_AUDIT_ENABLE_ACTIVE` + on-device authorization): deauth
    (focused/grouped/all), beacon flood, Evil Twin captive portal, BLE spoof.
  - Results/Export: audit findings, camera sweep, text/CSV/JSON reports, watchlist, scan diff, locator.
- `RadioInkTheme` (hacker × hiphop), Radio Ink branding, SD layout under `/.radioink/`.
- GitHub release workflow (web-flashable via ESP Terminator).
