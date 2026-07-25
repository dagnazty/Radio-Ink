# Changelog

All notable changes to **Radio Ink** are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions track `[radioink] version`
in `platformio.ini` and the GitHub release tags.

## [1.3.0] — 2026-06-27

### Added
- **mDNS Browser** (Radio Audit → **Network**) — new menu category for LAN-layer reconnaissance. Joins a
  Wi-Fi network (via the standard Wi-Fi picker, or reuses an existing connection), then enumerates common
  mDNS/Bonjour service types (HTTP/HTTPS, IPP printers, AirPlay, Chromecast, RTSP cameras, SSH, SMB,
  workstations, HomeKit) one type per loop tick so the watchdog never trips. Results are a **selectable
  list** — open any responder to a detail view showing its instance name, hostname, IP:port, and all
  advertised **TXT records** (model / firmware / paths), captured passively from the query response.
- **Notepad** (Home → **Notepad**) — a two-level on-device notes / to-do app saved to a human-readable
  `/notes.txt` on SD. The top level is a list of titled **pages**; each page is a free-text **note** (opens
  to a scrollable, word-wrapped body you append lines to or rewrite) or a **checklist** (toggleable items
  with add / edit / delete). Pages can be renamed, deleted, and converted note⇄checklist (content migrates
  either way). Reuses the shared on-screen keyboard for all text entry.
- **Discard-changes guard** on notepad text entry — pressing Back after typing or editing prompts
  *"Discard changes?"* so text can't be lost mid-sentence by accident. Opt-in per keyboard (only the
  notepad enables it; Wi-Fi-password / OPDS / KOReader entry are unchanged) and fires only when the text
  actually changed.
- **Notepad Wi-Fi sync** (Notepad page menu → **Sync over Wi-Fi**, also reachable when the list is empty) —
  stands up a WPA2 SoftAP + captive portal that serves `/notes.txt` in an editable textarea, so you can
  add / remove / edit notes from a phone or PC and Save writes it back to SD. Shows a Wi-Fi-join QR like the
  Web Report; reboots on exit to free the heap for BLE.
- **LAN Scanner** (Radio Audit → Network) — after associating, ARP-sweeps the local `/24` (a batch of hosts
  per loop tick, watchdog-safe) and lists every live host with its IP, MAC, and OUI vendor; the gateway is
  flagged. Uses lwip `etharp` under the TCP/IP core lock.
- **WPS Audit** (Radio Audit → Results) — filtered view of the last Wi-Fi scan showing only APs advertising
  WPS (PIN brute-force / Pixie-Dust exposure), with BSSID / channel / auth.
- **Port Probe** (Radio Audit → Network) — enter a target IP (defaults to the gateway), then TCP-connect to a
  curated set of common ports (one per loop tick, watchdog-safe) and list the open ones. HTTP ports get a
  banner grab — the `Server:` header and page `<title>` — for fingerprinting web UIs (routers, cameras, NVRs).
- **Network Info** (Radio Audit → Network) — after associating, shows SSID / IP / gateway / subnet / DNS /
  MAC / RSSI / channel and runs real ICMP **pings** (via `esp_ping`) against the gateway and 8.8.8.8 to
  report reachability + average latency.
- **NTP Time Sync** (Radio Audit → Network) — associates to Wi-Fi (or reuses an existing connection), then
  sets the DS3231 RTC from an internet NTP server via `halClock.syncFromNTP()`, so captures and reports are
  timestamped. Self-contained (brings up Wi-Fi itself), unlike the existing Settings → Clock Sync which
  needs Wi-Fi already up; returns the radio to idle afterward.
- **System Stats** (Radio Audit → Results) — on-device field diagnostics: firmware version, chip / CPU,
  free / max-alloc / min-free heap, flash size, internal temperature, uptime, and STA MAC.
- **I2C Bus Scan** (Radio Audit → Results) — probes the I2C bus and lists every responding address, labelling
  the known chips (battery / RTC / IMU) and flagging NFC-controller/tag addresses as candidates. Groundwork
  for driving the X3's (as-yet unidentified) NFC chip.
- **Clock** (Home → Clock) — a three-mode clock utility, switched left/right like tabs: **Clock** (wall
  time + date from the RTC), **Stopwatch** (count-up, Confirm start/stop, Up reset), and **Timer** (count-down,
  Up/Down set minutes, Confirm start/pause; a full-screen blinking alert when it reaches zero, since the
  device has no buzzer). Stopwatch/Timer are `millis()`-based so they work without an RTC sync.
- **Authenticator** (Home → Authenticator) — an on-device TOTP 2FA generator (RFC 6238): stores base32
  secrets in a readable `/totp.txt` and computes 6-digit codes via mbedtls HMAC-SHA1, using the DS3231 RTC
  for time (set it first with Network → NTP Time Sync). Codes roll over each 30 s window; add/delete on
  device or drop the file on SD.
- **Badge** (Home → Badge) — a full-screen digital identity card: Radio Ink skull, big name/handle, a
  subtitle, and a scannable QR (URL or vCard/MECARD contact). Left toggles a full-screen QR for easy
  scanning; Confirm edits the fields; config persists to a readable `/badge.txt`. (The C3 has no NFC radio,
  so the QR stands in for a tap.)
- **Tools**: four more utilities in Home → Tools — **Password Generator** (esp_random()-backed, adjustable
  length/character set), **Hash Calculator** (MD5/SHA-1/SHA-256 of typed text via mbedtls), **Encode/Decode**
  (Base64, Hex, URL — encode or decode, cycled with Left/Right), and **QR Generator** (type any text, see it
  as a full-screen scannable QR).
- **BLE deep-scan improvements**: the detail view now breaks an iBeacon/Eddystone advert into structured
  rows (UUID/major/minor, TX power, Eddystone URL or namespace/instance) instead of one summary line, and
  GATT enumerate now attempts a bounded set of characteristic reads to report whether data came back
  **without any pairing/PIN prompt** — a factual security-posture signal, not a vulnerability verdict.
- **WiFi passive-detection additions**: Enterprise (802.1X/EAP) networks are now flagged in Audit Findings;
  a new **SSID look-alike** detector flags evil-twin typosquats (e.g. `Starbucks_WiFi` vs `Starbucks_WlFi`)
  via edit-distance; a **KARMA/mana signature** is now caught — a BSSID that reports a *different* SSID
  across Deep Scan passes is flagged HIGH (previously silently overwritten and lost); and **Channel Usage**
  now shows a Clear/Busy/Congested label per channel (accounting for 2.4GHz adjacent-channel overlap, not
  just a flat per-channel AP count), plus a new "Congested channel neighborhood" finding for the 1/6/11
  planning channels.
- **Network additions**: **Subnet Calculator** (IP/CIDR → network/broadcast/host range, pure offline math),
  **Traceroute** (TTL-incrementing ping trace using `esp_ping`'s per-hop reply address), **Rogue DHCP Probe**
  (broadcasts a DHCPDISCOVER and flags if more than one distinct server offers a lease — the classic
  rogue-DHCP tell), and **SNMP Sweep** (tries default community strings — public/private/community/admin/
  manager/cisco — against a target's UDP 161 and reports which are accepted, with a best-effort sysDescr
  readout). LAN Scanner also gained an **ARP-spoof check**: any MAC answering for more than one IP in the
  same sweep (especially the gateway) is now flagged HIGH in Audit Findings.
- **Recent Books library views** — the recent-books screen now has **Continue / Finished / All** tabs so
  finished books can be separated from active reading without a full SD-card library database.
- **Reader time-remaining estimates** — EPUB reading now samples forward page-turn cadence and shows a
  compact live header estimate (for example `~18m`) plus a fuller chapter/book estimate in the reader menu.
- **Offline EPUB dictionary lookup** — the reader menu now includes **Dictionary**, which builds a bounded
  word picker from the current page and looks up definitions from SD-card TSV dictionary files.
- **SD-card dictionary tooling** — added `scripts/gcide_to_tsv.py` to convert GNU GCIDE `CIDE.*` files into
  `dictionary.tsv`, and `scripts/split_dictionary.py` to split a large TSV into `/dictionary/a.tsv`,
  `/dictionary/b.tsv`, etc. The firmware checks sharded files first and falls back to `/dictionary.tsv`.
- **Resume last screen on wake** — waking from sleep now returns to the tool or menu you were using (any of the
  Tools, the Tools submenu, File Browser, Recents, Settings, Movies, or Radio Audit) instead of always dropping
  to the Home screen. A full power-on or software restart still starts fresh at Home, and holding **Back** while
  the device boots forces Home. Network/AP screens deliberately wake to Home so a server isn't silently restarted.
- **Distinct Tools icons** — each Tools submenu entry now has its own glyph (note, badge, lock, clock, key, hash,
  QR); the Home menu's **Movies** and **About** entries gained film and info icons (previously blank in the
  Radio Ink theme).
- **Tracker Play Sound** (Radio Audit → Detect → Tracker Sweep) — the tracker sweep is now a selectable list;
  pick a tag to **Locate** it (RSSI hot/cold) or **Play Sound** to make a *separated* Find My tag chirp so a
  tracker planted on you can be found by ear. Connects with the advertised address type and auto-detects the
  DULT / FMNA / legacy-AirTag sound protocol (subscribe-then-write, no pairing). Authorization-gated like the
  other active features. Based on the [ESP32Marauder](https://github.com/justcallmekoko/ESP32Marauder) project
  by justcallmekoko (GPL-3.0) — see README credits; Radio Ink's version is an independent Bluedroid
  reimplementation.

### Changed
- **Home "Tools" submenu.** The utility apps (Notepad, Badge, Authenticator, Clock) moved off the home menu
  into a single **Tools** entry, keeping the home screen short. Each tool's Back returns to the Tools menu
  (with that tool reselected); the Tools menu's Back returns home.
- **RTC now stores the full calendar date.** `HalClock` previously wrote only H:M:S on NTP sync, leaving the
  DS3231 date registers unset (why WiGLE used a placeholder date). NTP sync now writes the date too, and a new
  `HalClock::getUnixTime()` returns a TZ-independent UTC epoch from the RTC (used by the Authenticator).
- Dictionary lookup now scales to larger SD-card dictionaries by opening only the selected word's first-letter
  shard instead of scanning one full dictionary file every time, and reads that shard in 512-byte blocks
  (rather than one SD byte at a time) — it also no longer skips entries whose definition line exceeds the buffer.
- **Tools suite is now fully translatable** — every user-facing string across Notepad, Badge, Authenticator,
  Clock, Password Generator, Hash Calculator, Encode/Decode, QR Generator, and the reader Dictionary now routes
  through the i18n `tr()` system instead of hardcoded English (Spanish/French/German translations included).
- **Shared tool chrome** — the eight utility tools now share a `ToolActivityBase` for their header, button-hint
  bar, and Back-to-Tools navigation, removing duplicated per-tool boilerplate.
- Generated dictionary outputs (`/dictionary.tsv` and `/dictionary/`) are ignored by git because they are
  SD-card artifacts, not firmware source.

### Fixed
- **Brand skull logo painted over full-screen views.** The Radio Ink skull is meant for the home screen
  only, but the shared on-screen keyboard never suppressed it, so it overlapped the keys on every text-entry
  screen (Wi-Fi password, OPDS, KOReader auth, etc.); the new Notepad screens had the same gap. All
  non-home views now call `suppressBrandLogoOnce()` before drawing the button hints.
- **Wrong Authenticator/Clock time before an NTP sync** — `HalClock::getUnixTime()` now rejects implausible
  (pre-2024) RTC dates, so a device whose date registers were never written no longer produces year-2000 TOTP
  codes or wall-clock time. Set the clock via Radio Audit → Network → NTP Time Sync.
- **Notepad note/checklist corruption** — note body or checklist text that begins with `@note`, `@list`, or
  `[x]` is no longer re-parsed as structure on reload; the on-disk `/notes.txt` format is now length-prefixed.
- **Authenticator labels containing a colon** — `label:secret` is now split on the *last* colon, so a label such
  as `AWS: prod` parses correctly (base32 secrets never contain a colon).
- **Hash Calculator crash** on an empty/failed SHA-256 digest — guarded a `substr` that could abort under
  `-fno-exceptions`.
- **Status bar** no longer appends the time-remaining estimate when the status-bar title is set to *Hidden*.
- **Notepad** no longer rewrites the entire notes file to SD on every checkbox toggle (deferred to exit), and a
  stale checklist index can no longer read out of bounds.
- **Clock timer alert** now blinks with a fast (custom-LUT) refresh instead of a full refresh the panel could not
  sustain, keeping the device responsive during the alert.
- **Authenticator** now polls the DS3231 RTC at most once a second instead of on every loop tick.
- On-hold button state no longer carries across entries into Notepad, Badge, or Authenticator (`ButtonNavigator`
  is now a per-activity member instead of a file-static).
- Opening the reader **Dictionary** no longer copies a ~2.5 KB word list onto the reader task stack.

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
