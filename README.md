# Radio Ink

**Open-source RF-audit / pentest firmware for the Xteink X-series (ESP32-C3), forked from
[CrossPoint Reader](https://github.com/crosspoint-reader/crosspoint-reader).**

Radio Ink keeps the **entire CrossPoint e-reader** — community-built, fully hackable, free forever —
and adds a **Wi-Fi / BLE auditing toolkit** for authorized wireless security testing, a custom
theme, and a serial dev rig. Everything CrossPoint does, Radio Ink still does; the
audit tool is bolted on top.

Created and maintained by **dag nazty** — <https://dagnazty.dev>. Fork at
<https://github.com/dagnazty/Radio-Ink>.

**Now running on:** ESP32C3-based Xteink [X4](https://www.xteink.com/products/xteink-x4) and
[X3](https://www.xteink.com/products/xteink-x3).

![Radio Ink running on Xteink device](./docs/images/cover.jpg)

> ### ⚠️ Authorized use only
> Radio Ink's auditing and **transmitting** features (deauthentication, beacon flooding, evil-twin
> captive portals, BLE spoofing) are for security testing on networks/devices you **own or are
> explicitly authorized to test**, plus education and research. Using them against networks you do
> not control is disruptive and illegal in most jurisdictions. Transmitting (attack) features are
> **compiled out of release builds** and require a one-time on-device authorization confirmation in
> dev builds. You are responsible for complying with all applicable laws. No warranty — see
> [LICENSE](./LICENSE).

---

## What can Radio Ink do?

### Radio Audit toolkit (the Radio Ink additions)

Reachable from **Home → Radio Ink**, grouped into menu categories:

- **Scan** — Quick / Deep Wi-Fi + BLE scans, **client recon** (probe-request harvesting), and a
  **channel-usage** map with a per-channel Clear/Busy/Congested rating (overlap-aware, not just a flat AP
  count).
- **Network** — LAN-layer recon once you've joined a Wi-Fi network:
  - **mDNS Browser** — enumerates Bonjour/mDNS service types (HTTP/HTTPS, IPP printers, AirPlay, Chromecast,
    RTSP cameras, SSH, SMB, workstations, HomeKit) and lists every responder. Open one to see its hostname,
    IP:port, and all advertised **TXT records** (model / firmware / paths) — passive, straight from the
    query response.
  - **LAN Scanner** — ARP-sweeps the local `/24` and lists every live host with its IP, MAC, and vendor
    (gateway flagged), sweeping in watchdog-safe batches. Also flags an **ARP-spoof / MITM** signature: any
    MAC answering for more than one IP in the same sweep (especially the gateway).
  - **NTP Time Sync** — sets the DS3231 RTC from an internet time server so captures/reports are stamped
    with the real date/time (also available in Settings → Clock Sync).
  - **Network Info** — SSID / IP / gateway / subnet / DNS / MAC / RSSI / channel, plus ICMP **pings** of the
    gateway and 8.8.8.8 (reachability + latency).
  - **Port Probe** — TCP-scans a curated set of common ports on a target IP and lists what's open, with an
    **HTTP banner grab** (`Server:` header + page `<title>`) for fingerprinting web UIs.
  - **Subnet Calculator** — IP/CIDR → network / broadcast / netmask / host range, pure offline math.
  - **Traceroute** — TTL-incrementing ping trace to a target IP.
  - **Rogue DHCP Probe** — broadcasts a DHCPDISCOVER and flags it if more than one distinct server offers a
    lease — the classic rogue-DHCP-server tell.
  - **SNMP Sweep** — tries default community strings (public/private/community/admin/manager/cisco) against
    a target's UDP 161 and reports which are accepted, with a best-effort `sysDescr` readout.
- **Detect** — passive threat / signature monitors:
  - **Guardian Mode** — set-and-forget watch that unifies the detectors below (BLE pairing spam, Flipper,
    drones, item-trackers / watchlisted MACs that follow you, and Wi-Fi deauth floods) into one **ALL
    CLEAR / alert** dashboard. Leave it running; Stop responds mid-round.
  - **Threat Sweep** — flags **Flipper Zero** (BLE service `0x3082`), **Pwnagotchi** (promiscuous beacon
    listen for the `DE:AD:BE:EF` / JSON-SSID signature), **Meshtastic** nodes,
    BLE **card-skimmer** modules (HC-05/06, HM-10, JDY…), **BLE relay/spoof** RSSI anomalies, **BLE pairing
    spam** floods (Flipper/app Apple/SwiftPair/FastPair/Samsung popups), and **Axon** body/in-car cameras.
    The BLE scan is flood-safe (streams + discards each advert) so a spam attack can't OOM it.
  - **Camera Sweep** *(interactive)* — Wi-Fi/BLE + associated-client OUI fingerprinting for IP cameras,
    **Ring / Blink** (hardcoded OUIs, plus randomized-MAC candidates), doorbells and NVRs — select a hit to
    **Locate** or **Deauth** it.
  - **Tracker Sweep** — AirTag / FindMy / Tile / Samsung SmartTag / Chipolo tags, as a selectable list.
    Pick a tag to **Locate** it (RSSI hot/cold) or **Play Sound** — connect to a *separated* Find My tag and
    make it chirp so you can find a tracker planted on you (DULT / FMNA / legacy-AirTag protocols;
    authorization-gated; based on ESP32Marauder — see credits).
  - **Anti-Stalk Watch** — re-scans BLE on an interval and flags a tracker or watchlisted device that keeps
    following you across passes.
  - **Drone RID Scan** — decodes **OpenDroneID / ASTM F3411** Remote ID from Wi-Fi beacons (drone serial, UA
    type, live GPS lat/lon/altitude); BLE Remote ID (service `0xFFFA`) also surfaces in the BLE scans.
  - **Deauth Detector** — flags deauth/disassoc floods and the source MAC.
- **Capture** — **Live PCAP** streamed to SD (open in Wireshark), **WPA handshake / PMKID** capture
  exported in **hashcat `22000`** format, and a **Scheduled Log** — unattended periodic Wi-Fi+BLE scan to a
  timestamped CSV on SD, with a setup screen to pick the **interval** (15 s–10 min), **run-time**
  (15 min–8 h or until stopped), and **radios** (Wi-Fi+BLE / Wi-Fi only / BLE only).
- **Attacks** *(dev builds only, authorization-gated)* — targeted / grouped / all **deauth** (including
  directed deauth of a selected camera), **beacon flood**, **evil-twin captive portal** with credential
  capture, **Karma / probe-response**, and **BLE advertisement spoof**.
- **Results** — audit findings (open / WEP / legacy-WPA / hidden / **WPS** / **evil-twin** — one SSID on
  multiple BSSIDs with mixed encryption / rogue-AP / deauth activity / **enterprise (802.1X)** networks /
  **SSID look-alike** typosquats / **KARMA signature** (a BSSID that changes its advertised SSID across scan
  passes) / **ARP-spoof** hits / congested-channel neighborhoods, plus every Threat Sweep signature:
  Flipper / Pwnagotchi / skimmer / Meshtastic / BLE relay / BLE spam / drone / Axon) and the Wi-Fi / BLE
  result lists. Also **WPS Audit** (filtered list of WPS-advertising APs), **System Stats** (heap / CPU /
  temperature / uptime / MAC field diagnostics), **I2C Scan** (probes the I2C bus, labels known chips),
  **View Reports** (read saved reports/captures on-device) and **Share Findings (web)** — the device hosts a
  WPA2 SoftAP + captive portal; scan the Wi-Fi-join QR on a phone and the findings open like a web page
  (fully offline; the device auto-reboots on exit to free memory for scanning).
- **Export** — TXT / CSV / JSON reports plus **WiGLE-1.4 CSV** for wardriving, all RTC-stamped to SD.
  (No on-board GPS: drop a `location.txt` with `lat,lon` on the SD to tag WiGLE rows.)
- Plus, from any deep-scan detail: **GATT enumerate** (now with a bounded read attempt per characteristic,
  flagging whether data came back with no pairing/PIN prompt), a structured **iBeacon/Eddystone breakdown**
  (UUID/major/minor, TX power, URL or namespace/instance), an **RSSI locator** ("warmer/colder"), vendor
  lookup, BLE-advert decoding, a MAC **watchlist**, and **scan-to-scan diff** (NEW / GONE devices).

**Vendor databases (SD):** two lookup tables live on the SD card (kept off flash, same as a real
wardriver's data) — copy both into `/.radioink/`:

- `oui.bin` — the full IEEE OUI table (~39,500 Wi-Fi/MAC vendors), built by `scripts/gen_oui.py`. Drives
  vendor names across scans, Camera Sweep, and exports; without it, MAC lookups (including Ring/Blink)
  fall back to a small hardcoded set.
- `ble_companies.bin` — the Bluetooth SIG company-ID table (~4,000 BLE vendors), built by
  `scripts/gen_ble_companies.py`. Turns BLE `Vendor:` lines from `0x004C` into `Apple, Inc.` etc.;
  without it, BLE vendor naming falls back to a small built-in set.

BLE **service-UUID** names (GAP/GATT/HID/battery/…) are compiled into flash (~75 entries), so service
identification works with no SD file.

Full technical detail: **[RADIO_INK.md](./RADIO_INK.md)**. All audit data lives under `/.radioink/`.

### Reader & device features (inherited from CrossPoint)

- **Reader engine**: EPUB 2/3 rendering with embedded-style option, image handling, hyphenation,
  kerning, chapter navigation, footnotes, bookmarks, go-to-percent, auto page turn, orientation control,
  focus reading, KOReader progress sync, time-remaining estimates and more.

- **Various formats**: native handling for `.epub`, `.xtc/.xtch`, `.txt`, and `.bmp`.

- **Screenshots.**

- **Custom fonts**: install your favorite fonts on the SD card.

- **Tilt page turn (X3 only)**.

- **Library workflow**: one unified file browser (from Home → Browse Files) that lists every file with
  sizes, shows `/.radioink/` and other dot-folders, opens books, and deletes anything via long-press;
  plus recent books, Recent Books library views (**Continue / Finished / All**), and SD-cache management.

- **Offline dictionary lookup**: from the EPUB reader menu, choose **Dictionary**, pick a word from the
  current page, and Radio Ink looks it up from SD. Use `scripts/gcide_to_tsv.py` to convert GNU GCIDE into
  `dictionary.tsv`, then `scripts/split_dictionary.py` to create `/dictionary/a.tsv`, `/dictionary/b.tsv`,
  etc. on the SD card. The firmware checks the sharded files first and falls back to `/dictionary.tsv`.

- **Notepad**: a two-level on-device notes / to-do app (Home → Tools → Notepad) saved to a readable `/notes.txt` on
  SD. Titled **pages** are each a free-text **note** (scrollable, word-wrapped body you append to or rewrite)
  or a **checklist** (toggleable items); convert either way. A discard-changes prompt guards against losing
  text on an accidental Back. **Sync over Wi-Fi** stands up a captive-portal web editor (join the QR, edit
  `/notes.txt` from a phone/PC, Save) — reboots on exit to free memory.

- **Clock**: a three-mode clock utility (Home → Tools → Clock), tabs switched left/right — **Clock** (wall time +
  date from the RTC), **Stopwatch**, and **Timer** (count-down with a blinking full-screen alert at zero).

- **Authenticator**: an on-device TOTP 2FA code generator (Home → Tools → Authenticator) — base32 secrets in a
  readable `/totp.txt`, 6-digit codes via mbedtls HMAC-SHA1 off the DS3231 RTC (set the clock first with
  Radio Ink → Network → NTP Time Sync). Add/delete on device or drop the file on the SD card.

- **Badge**: a full-screen digital identity card (Home → Tools → Badge) — Radio Ink skull, name/handle, subtitle,
  and a scannable QR (URL or vCard/MECARD). Press Left for a full-screen QR; Confirm to edit. Config in a
  readable `/badge.txt`. (No NFC on the C3 — the QR is the tap.)

- **Read Later** (Home → Tools): type a URL, and Radio Ink fetches the page over Wi-Fi, strips it to plain
  text, and saves it to `/articles` on SD so it opens in the normal reader. One page per request — the radio
  comes up, fetches, and goes back off. Left adds a URL, Confirm opens an article, Right deletes one.

- **News / RSS** (Home → Tools): subscriptions live in a plain `/feeds.txt` (one per line, either
  `https://example.com/feed` or `Name|https://example.com/feed`), or add them on device. Nothing polls in the
  background — opening a feed fetches its headlines on demand, and opening a headline runs it through the same
  HTML-to-text pipeline as Read Later, landing in `/articles` and opening in the reader. RSS 2.0 and Atom.

- **Flashcards** (Home → Tools): spaced repetition off the SD card. Decks are tab-separated files at
  `/flashcards/<name>.tsv` (`front<TAB>back`, one card per line); scheduling state is persisted beside each
  deck as `<name>.sched`. Confirm flips the card, then Left / Confirm / Right grade it **Again / Good / Easy**
  (SM-2 intervals). Card text is streamed from SD as each card is shown, so deck size costs no RAM. Needs the
  RTC set for real scheduling — without it the deck is simply walked end to end.

- **Calculator** (Home → Tools): a 5x4 keypad — digits, `+ - * /`, parentheses, decimal point, clear,
  backspace, and `=` — moved around with the D-pad and pressed with Confirm, under a readout showing the
  expression and its result. Correct precedence; division by zero or an unbalanced expression shows `Error`.
  Typing a digit after a result starts fresh, pressing an operator continues from it.

- **Password Generator** (Home → Tools): `esp_random()`-backed, adjustable length and character set
  (letters+digits, +symbols, or digits-only for a PIN), with an entropy estimate.

- **Hash Calculator** (Home → Tools): MD5 / SHA-1 / SHA-256 of typed text, via mbedtls.

- **Encode / Decode** (Home → Tools): Base64, Hex, and URL — encode or decode, cycled with Left/Right.

- **QR Generator** (Home → Tools): type any text (a URL, a Wi-Fi PSK, anything) and see it as a full-screen
  scannable QR — separate from Badge's fixed one.

- **Movies (novelty)**: a monochrome flipbook player (Home → Movies) for 1-bit `.rivid` frame packs
  converted off-device with `scripts/gen_video.py`. It is **not** real video — the e-ink panel runs at a
  few fps, monochrome, no audio — but it'll flip high-contrast clips you convert yourself. Pause/End has
  an **autoloop** toggle that persists across reboots.

- **Resume on wake**: waking from sleep returns you to the tool or menu you were using (a reading book already
  resumed; now the Tools, File Browser, Recents, Settings, Movies, and Radio Audit do too) instead of always
  dropping to Home. A full power-on or software restart still starts fresh at Home, and holding **Back** while
  the device boots forces Home.

- **Wireless workflows**:

  - File transfer web UI
  - EPUB Optimizer
  - Web settings UI/API (edit many device settings from browser)
  - WebSocket fast uploads
  - WebDAV handler
  - AP mode (hotspot) and STA mode (join existing Wi-Fi), both with QR helpers
  - Calibre wireless connect flow
  - OPDS browser with saved servers (up to 8), search, pagination, and direct download
  - OTA update checks and installs from GitHub releases

- **Customization**: multiple themes (Classic, Lyra, Lyra Extended, RoundedRaff, **Radio Ink**), sleep screen modes, front/side button remapping, status bar controls, power-button behavior, refresh cadence, and more.

- **Localization**: 24 UI languages and counting. RTL support.

---

## USB-locked devices (Xteink Unlocker)

Some Xteink units purchased from third-party stores (e.g. AliExpress) ship with USB flashing locked
from the factory. If your device is locked, you will need to use the **Xteink Unlocker** tool
available at https://crosspointreader.com/#unlock-tool before you can flash.

**You do not need this tool if you bought your device directly from xteink.com.** Those units are not
locked.

**Not sure if your device is locked?** Power it on, connect the USB-C cable, and try flashing first.
If the browser's serial device picker / esptool does not show your device, try a different USB port or
browser before assuming the device is locked. Only reach for the unlocker if the device still doesn't
appear.

> ### ⚠️ WARNING: READ THIS BEFORE USING THE UNLOCKER ⚠️
>
> **The only firmwares officially supported in the unlock tool are CrossPoint and CrossInk — Radio
> Ink is not on that list.** Flashing unsupported firmware on a USB-locked device may **permanently
> brick the device** or leave it **permanently stuck on that firmware with no recovery path**. Once
> USB flashing is re-locked, your only way back is via OTA, and if the firmware you flashed has a
> broken OTA path, **there is no way out**. **Flashing Radio Ink on a USB-locked unit is at your own
> risk.** Prefer a device bought directly from xteink.com (not locked), and confirm you can flash
> before committing.

## Install firmware

### Web installer (recommended)

**[ESP Terminator](https://espterminator.com/) is the official Radio Ink web flasher** — a
browser-based installer (WebSerial; use Chrome or Edge), no local tooling required:

1. Connect your device via USB-C and wake/unlock it.
2. Open <https://espterminator.com/> in a WebSerial-capable browser.
3. Select your device, choose the Radio Ink firmware (or upload a local/CI `firmware.bin`), and flash.

You can build a `firmware.bin` yourself (see [Development quick start](#development-quick-start)) or
grab one from the [fork's releases](https://github.com/dagnazty/Radio-Ink/releases).

*(Alternative: the CrossPoint flasher at https://crosspointreader.com/#flash-tools also accepts a
**Custom .bin** upload — its "official release" selector flashes CrossPoint, not Radio Ink.)*

### Revert to official firmware

Flash the latest official CrossPoint/Xteink firmware via https://crosspointreader.com/#flash-tools.

### Command line

1. Install [`esptool`](https://github.com/espressif/esptool):

```bash
pip install esptool
```

2. Build or download a Radio Ink `firmware.bin`.
3. Connect your device via USB-C.
4. Find the device port. On Linux, run `dmesg` after connecting. On macOS:

```bash
log stream --predicate 'subsystem == "com.apple.iokit"' --info
```

5. Flash:

```bash
esptool.py --chip esp32c3 --port /dev/ttyACM0 --baud 921600 write_flash 0x10000 /path/to/firmware.bin
```

Adjust `/dev/ttyACM0` to match your system (macOS: `/dev/cu.usbmodem*`).

### Manual

See [Development quick start](#development-quick-start) below.

---

## Custom SD-card fonts

Convert your own TTF/OTF files into `.cpfont` files that load from the SD card. No firmware reflash is
needed. Radio Ink uses CrossPoint's font system unchanged, so the upstream builder works as-is:

1. Go to https://crosspointreader.com/fonts and open the "SD-card font builder" form.
2. Upload up to four styles (regular, bold, italic, bold-italic), set the family name, point sizes, and Unicode range.
3. Download the generated `.cpfont` files.
4. Copy them to your SD card under `/fonts/YourFont/` (or `/.fonts/YourFont/` to hide the folder).
5. Select the font on the device from the font settings.

Conversion runs the firmware repo's `lib/EpdFont/scripts/fontconvert_sdcard.py` script unmodified, so
output matches a local host build.

---

## Offline dictionary files

The EPUB reader's **Dictionary** menu item needs dictionary data on the SD card. The firmware prefers
sharded files because it only has to scan the selected word's first-letter file:

```text
/dictionary/a.tsv
/dictionary/b.tsv
/dictionary/c.tsv
...
```

It also supports a flat fallback file:

```text
/dictionary.tsv
```

To generate the recommended sharded dictionary locally from GNU GCIDE:

```bash
curl -L https://ftp.gnu.org/gnu/gcide/gcide-latest.tar.xz -o gcide-latest.tar.xz
tar -xf gcide-latest.tar.xz
python3 scripts/gcide_to_tsv.py gcide-*/ dictionary.tsv
python3 scripts/split_dictionary.py dictionary.tsv dictionary
```

Then copy the generated `dictionary/` folder to the root of the SD card. A GCIDE-based build is about
12-14 MB and produces roughly 108k lookup entries.

---

## Documentation

- [RADIO_INK.md](./RADIO_INK.md) — Radio Ink technical reference (audit tool, dev rig, theme, internals)
- [CHANGELOG.md](./CHANGELOG.md) — version history
- [User Guide](./USER_GUIDE.md)
- [Web server usage](./docs/webserver.md)
- [Web server endpoints](./docs/webserver-endpoints.md)
- [Project scope](./SCOPE.md)
- [Contributing docs](./docs/contributing/README.md)

---

## Development quick start

### Prerequisites

- [pioarduino](https://github.com/pioarduino/pioarduino) or VS Code + pioarduino plugin
- Python 3.8+
- `clang-format` 21
- USB-C cable supporting data transfer

### Setup

```bash
git clone --recursive https://github.com/dagnazty/Radio-Ink
cd Radio-Ink

# if cloned without --recursive:
git submodule update --init --recursive
```

### Build / flash / monitor

```bash
pio run -e default                  # dev build (serial logging; attack features enabled, gated)
pio run -e default --target upload  # build + flash + monitor
pio run -e gh_release               # production build (no serial; attack features compiled out)
```

**Optional build flags — hyphenation languages:**

To minimize flash, **English is the only hyphenation language compiled in by default.** Every other
language is opt-in, since the pattern tries are the largest data in the firmware (de ~206 KB, ru ~33 KB,
sv ~24 KB, uk ~21 KB, pl ~16 KB, es ~14 KB, fr ~7 KB, it ~1.5 KB). Disabling a language only removes
mid-word hyphenation — those books still render and wrap at word boundaries.

- `-DHYPH_ENABLE_DE` / `_FR` / `_RU` / `_ES` / `_IT` / `_PL` / `_SV` / `_UK` — compile a specific
  language's hyphenation back in.
- `-DHYPH_ENABLE_ALL` — compile every language's hyphenation in (the pre-1.2.0 behavior).

Add these to `build_flags` in `platformio.local.ini` (recommended) or `platformio.ini`.

### Contributor pre-PR checks

```bash
./bin/clang-format-fix
pio check -e default
pio run -e default
```

### Debugging

After flashing new features, it's recommended to capture detailed logs from the serial port.

First, make sure all required Python packages are installed:

```python
python3 -m pip install pyserial colorama matplotlib
```

After that run the script:

```sh
# For Linux (tested on Debian; should work on most Linux systems).
python3 scripts/debugging_monitor.py

# For macOS
python3 scripts/debugging_monitor.py /dev/cu.usbmodem2101
```

Minor adjustments may be required for Windows.

---

## Internals

Radio Ink (like CrossPoint) is pretty aggressive about caching data down to the SD card to minimise
RAM usage. The ESP32-C3 only has ~380KB of usable RAM, so we have to be careful. A lot of the design
decisions were based on this constraint — and the audit tool follows the same rule (on-demand heap
buffers, reserved vectors, streaming captures to SD).

### Data caching

The first time chapters of a book are loaded, they are cached to the SD card. Subsequent loads are
served from the cache. This cache directory exists at `.radioink` on the SD card (renamed from
`.crosspoint` on first boot, with a one-time migration). The structure is as follows:

```text
.radioink/
├── epub_<hash>/         # one directory per book, named by content hash
│   ├── progress.bin     # reading position (chapter, page, etc.)
│   ├── cover.bmp        # generated cover image
│   ├── book.bin         # metadata: title, author, spine, TOC
│   ├── css_rules.cache  # parsed CSS rule cache
│   ├── img_*            # rendered image cache files
│   └── sections/        # per-chapter layout cache
│       ├── 0.bin
│       ├── 1.bin
│       └── ...
├── settings.json        # device settings
├── state.json           # resume/runtime state
├── recent.json          # recent books list
├── radio_ink/           # audit reports, watchlist.txt, last_scan.txt (diff snapshot)
├── captures/            # PCAP + hashcat .22000 captures
└── loot/                # evil-twin captured credentials (dev builds)
```

Removing `/.radioink` clears all cached metadata and forces a full regeneration on next open. Book
deletes, overwrites, and moves done through the firmware or web UI clear or re-key matching caches;
manual SD-card edits may leave stale cache directories behind.

For more details on the internal file structures, see the [file formats document](./docs/file-formats.md).

---

## Contributing

Contributions are welcome. Radio Ink shares CrossPoint's codebase, so the upstream
[contributing docs](./docs/contributing/README.md) apply. For the e-reader half, consider
contributing upstream to [CrossPoint](https://github.com/crosspoint-reader/crosspoint-reader) so the
whole community benefits; for Radio-Ink-specific (audit) work, open an issue/PR on the
[fork](https://github.com/dagnazty/Radio-Ink).

Everyone here is a volunteer, so please be respectful and patient. For governance and community
expectations, see [GOVERNANCE.md](./GOVERNANCE.md).

---

## Credits & attribution

Radio Ink is a fork and would not exist without the upstream work it builds on:

- **[CrossPoint Reader](https://github.com/crosspoint-reader/crosspoint-reader)** — by **Dave Allie**
  and the CrossPoint community. The entire e-reader (reading engine, HAL, theming, i18n, wireless
  stack) is their work; Radio Ink keeps it intact. Consider supporting upstream:
  [![Fund contributors](https://img.shields.io/badge/%F0%9F%91%91_Fund_contributors-royalty.dev-BB953A?style=flat&labelColor=1a1a1a)](https://app.royalty.dev/crosspoint-reader/crosspoint-reader)
- **[diy-esp32-epub-reader](https://github.com/atomic14/diy-esp32-epub-reader)** by **atomic14** — the
  project that originally inspired CrossPoint.
- The CrossPoint contributors, translators, and community-fork authors.
- **[ESP32Marauder](https://github.com/justcallmekoko/ESP32Marauder)** by **justcallmekoko** (GPL-3.0) —
  the tracker **Play Sound** feature (make a separated AirTag / Find My accessory chirp) is based on his
  work. The three-protocol approach (DULT / FMNA / legacy AirTag), the service & characteristic UUIDs, the
  command bytes, and the subscribe-before-write + observed-address-type requirements all come from studying
  ESP32Marauder; Radio Ink's version is an independent reimplementation for the Bluedroid BLE stack (Marauder
  uses NimBLE), and the credit for the technique is his.
- **Radio Ink** — the RF-audit fork, audit tool, theme, and dev rig — by **dag nazty**
  (<https://dagnazty.dev>).

### Other CrossPoint forks

CrossPoint has a rich ecosystem; if you need something outside Radio Ink's focus, check these out:

- [CrossInk](https://github.com/uxjulia/CrossInk) — typography & reading tracking (Bionic Reading, guide dots, custom fonts).
- [papyrix-reader](https://github.com/bigbag/papyrix-reader) — FB2 and MD support, Arabic script, SD-card themes.
- [crosspet](https://github.com/trilwu/crosspet) — Vietnamese fork with a Tamagotchi-style reading pet, flashcards, weather, Pomodoro, mini-games.
- [crosspoint-reader-cjk](https://github.com/aBER0724/crosspoint-reader-cjk) — Chinese/Japanese/Korean reading.
- [inx](https://github.com/obijuankenobiii/inx) — reimagined tabbed UI.
- [crosspoint-reader-papers3](https://github.com/juicecultus/crosspoint-reader-papers3) — port for M5Stack Paper S3.
- [t5s3-reader](https://github.com/ShallowGreen123/t5s3-reader) — port for LilyGo T5 ePaper S3 / T5S3.

Want to build your own device? Check out the [de-link](https://github.com/iandchasse/de-link) project.

## License

MIT — see [LICENSE](./LICENSE). Original copyright © 2025 Dave Allie (CrossPoint Reader); Radio Ink
modifications retain the same MIT license.

Radio Ink is **not affiliated with Xteink** or any device manufacturer. Use responsibly — authorized
testing only.
