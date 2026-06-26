# Changelog

All notable changes to **Radio Ink** are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions track `[radioink] version`
in `platformio.ini` and the GitHub release tags.

## [1.2.0] — 2026-06-23

### Added
- **Guardian Mode** (Detect) — set-and-forget passive monitor that unifies the detectors: each round runs
  a flood-safe BLE scan plus a promiscuous Wi-Fi deauth-flood window, flagging BLE pairing spam, Flipper,
  drones, item-trackers / watchlisted MACs that follow you across rounds, and deauth/disassoc floods.
  Live ALL CLEAR / threat dashboard; Stop responds mid-round.
- **Web Report** (Results → Share Findings) — stands up a WPA2 SoftAP + captive-portal web server that
  serves the current scan's findings as an HTML page, with a Wi-Fi-join QR. Scan it on a phone → join →
  the captive portal opens the report like a website. Fully offline. (The device auto-reboots on exit: a
  SoftAP fragments the heap past any runtime fix, and BLE needs a contiguous block afterward.)
- **Report Viewer** (Results → View Reports) — browse and read saved reports/captures on-device (opens
  `/.radioink` in the file browser; TXT opens in the reader).
- **Scheduled Log** (Capture) — unattended periodic scan → timestamped CSV on SD. A setup form picks the
  scan **interval** (15 s–10 min), **run-time** (15 min–8 h, or until stopped), and **radios** (Wi-Fi+BLE /
  Wi-Fi only / BLE only).
- **WPS detection** — APs advertising WPS are flagged (PIN brute-force / Pixie-Dust exposure), read from
  the scan record; auto-surfaces in Audit Findings.
- **Evil-twin / rogue-AP detection** — one SSID broadcast by multiple BSSIDs with *different encryption* is
  flagged HIGH (a rogue clone); uniform-auth duplicates stay INFO. Auto-surfaces in Audit Findings.
- **Pwnagotchi beacon sniffer** — Threat Sweep now does a brief promiscuous beacon listen, catching the
  sparse `DE:AD:BE:EF` / JSON-identity presence beacons that a quick scan misses.
- **Anti-Stalk Watch** (Detect) — re-scans BLE on an interval (flood-safe streaming scan) and tracks which
  devices persist across passes. A tracker or watchlisted MAC seen across ≥3 passes is flagged as a
  possible follower. Walk around with it running; live list updates each pass. (AirTags rotate their MAC,
  which can reset their per-device count.)
- **Drone RID Scan** (Detect) — passive **OpenDroneID / ASTM F3411** Remote ID monitor. Parses the ASTM
  vendor IE (OUI `FA:0B:BC`) in Wi-Fi beacons to decode drone **serial, UA type, and live GPS
  lat/lon/altitude**, channel-hopping 1–13. BLE-broadcast Remote ID (service/company `0xFFFA`) is also
  classified in the BLE and Threat Sweep scans and Audit Findings. *(Untested against a real drone —
  parser built to spec.)*
- **BLE vendor & service identification.** BLE `Vendor:` lines now resolve via the Bluetooth SIG
  company-ID table (~4,000 vendors) shipped on SD as `/.radioink/ble_companies.bin`
  (`scripts/gen_ble_companies.py`), the BLE counterpart to `oui.bin` — kept off flash, binary-searched by
  seek with a small cache, graceful fallback to the built-in set when absent. GATT **service-UUID** names
  (~75 SIG services) are compiled into flash (~3.6 KB) so service identification needs no SD file. Source
  snapshots committed under `data/ble/`.
- **Threat Sweep** (Recon) — one Wi-Fi + active-BLE scan that flags known threat signatures and lists
  every hit. Passive/read-only, ships in release builds. Detects:
  - **Flipper Zero** — advertised BLE serial-service UUID `0x3082` (the device name is the user/random
    name with no "Flipper" prefix, so the service UUID is the reliable signature).
  - **Pwnagotchi** — `DE:AD:BE:EF` beacon MAC, `pwnagotchi` name, or JSON-identity SSID.
  - **Meshtastic** — advertised BLE service UUID `6ba1b218…` (or `Meshtastic_` name).
  - **Card skimmers** — factory-default names of cheap serial-BT modules used in pump/ATM skimmers
    (HC-05/06, HM-10 / HMSoft / BT05 / MLT-BT05, JDY-xx, CC41, SPP-C, KCX_BT).
  - **BLE relay / spoof** — heuristic RSSI-anomaly flag (large swing across several sightings).
  - **BLE pairing spam** — flags a Flipper/app advertising-spam flood (≥8 Apple proximity-pairing /
    Microsoft Swift Pair / Google Fast Pair / Samsung popup adverts in one sweep).
- **Axon camera detection** — Axon Enterprise (formerly TASER) body / in-car / Fleet cameras, via the
  verified `00:25:DF` OUI, SD vendor-database name match, and SSID/name fingerprints
  (axonbody / axon fleet / axon signal / taser / evidence.com). Surfaces as a HIGH camera finding.
- All Threat Sweep signatures also auto-surface in **Audit Findings** after any Quick/Deep scan.

### Changed
- **Radio Ink menu reorganized** for the growing toolset. The overloaded "Recon" (11 items) is split into
  **Scan** (enumeration) and **Detect** (passive monitors); Camera Sweep moved from Results into Detect.
  New tree: **Scan · Detect · Capture · Attacks · Results · Export**, each with a distinct icon. Category
  item counts are now derived from the array (`CAT_ENTRY`) so they can't drift out of sync.
- BLE scans now capture the advertised **primary service UUID** (not just service-*data*), enabling
  service-UUID detection (e.g. Meshtastic) even when a device hides or renames itself.
- **Threat Sweep BLE is now flood-safe** — a streaming scan parses each advert into a 24-slot cap and
  immediately erases it from the BLE library's results map, so a BLE-spam flood can't pile up hundreds
  of parsed adverts and abort the scan on `bad_alloc`. (Passive scan; Flipper still detected via its
  advertised service UUID.)
- **Per-language hyphenation toggles; English-only by default** to reclaim flash (the pattern tries are
  the largest data in the binary). Every non-English language is now individually opt-in — enable one
  with `-DHYPH_ENABLE_DE` / `_FR` / `_RU` / `_ES` / `_IT` / `_PL` / `_SV` / `_UK`, or all at once with
  `-DHYPH_ENABLE_ALL`. Net flash with the default English-only build is **80.7%** (down ~322 KB from
  all-languages-on). Disabled languages still render and wrap at word boundaries — only mid-word
  hyphenation is removed.

### Fixed
- **QR codes now scan reliably.** The QR display used a fast/partial e-ink refresh, whose ghosting smeared
  the modules so phones couldn't decode them — it now does a full refresh. Also fixed an instant-close (the
  button that opened the screen bled through and dismissed it) and removed the skull logo that overlapped
  the QR's corner. Applies to every QR screen (Web Report, reader "Show as QR").

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
