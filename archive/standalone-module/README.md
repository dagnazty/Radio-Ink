# Radio Ink X3 Auditor

Wi-Fi/BLE audit app module for the Xteink X3 ESP32-C3.

This is structured as an embeddable app module, not a required full-device firmware replacement. The scanner lives behind `RadioInkAuditApp` so an X3 launcher/menu can call it from the stock or alternate app runtime if that runtime exposes a way to add native apps.

## What It Does

- Auto scan Wi-Fi and BLE
- Deep scan a single selected Wi-Fi AP or BLE device for detailed auditing info
- Save scans and issues to LittleFS
- Export compact X3-readable text
- Export CSV and JSON
- Avoid saving Wi-Fi passwords to flash

Captured fields:

- Wi-Fi: SSID, BSSID, RSSI, channel, auth mode, hidden flag
- BLE: address, name, RSSI, TX power when advertised, address type, manufacturer data hex, service UUID
- Issues: severity, area, finding, action

### Deep Scan

After a broad scan populates the results, you can focus on one target and gather
much richer audit data without re-scanning everything.

`DEEPSCAN WIFI <index|bssid|ssid>` locks the radio to that AP's channel in
promiscuous mode for a few seconds and reports:

- RSSI stability (average / min / max over many frames)
- Beacon, management, and data frame counts
- Associated **client MAC addresses** seen talking to that AP
- Security posture parsed from beacons: Privacy, PMF (802.11w), WPS presence
- Whether the BSSID is locally administered (randomized)

WPS-enabled and PMF-missing APs automatically raise deduplicated issues that
flow into the report and score.

`DEEPSCAN BLE <index|address|name>` runs a focused multi-pass scan of one device
and reports RSSI profile, decoded company ID, advertised service UUID, and
random-address detection.

The `<index>` matches the 1-based numbering shown in the report's WIFI/BLE lists,
so a host UI can "select row N, deep scan" by passing the row number. The same
actions are exposed to the host app as `RadioInkAuditApp::deepScanWifi(i)` and
`RadioInkAuditApp::deepScanBle(i)`. Deep results appear in the X3/CSV/JSON
exports and are persisted with the audit.

## App Integration

Include the module:

```cpp
#include "RadioInkAuditApp.h"
```

Initialize it from the X3 app start hook:

```cpp
RadioInkAuditApp::begin(false);
```

Trigger scans from the X3 menu/button handler:

```cpp
RadioInkAuditApp::autoScan(8);
```

Render/export the current report:

```cpp
String report = RadioInkAuditApp::reportText();
String csv = RadioInkAuditApp::reportCsv();
String json = RadioInkAuditApp::reportJson();
```

If the host app framework is command-oriented, route commands directly:

```cpp
RadioInkAuditApp::command("AUTO 8");
RadioInkAuditApp::command("EXPORT X3");
```

The missing piece for true one-tap installation is the Xteink X3 app ABI/SDK or the source tree for the launcher/runtime you want this added to. The ESP32-C3 itself does not magically load native apps unless the installed X3 firmware provides a loader.

## Standalone Test Harness

`platformio.ini` currently defines `RADIO_INK_STANDALONE_DEMO=1`, which builds a USB serial harness for testing the app module before wiring it into the X3 UI.

Build with Arduino CLI:

```bash
arduino-cli compile \
  --fqbn esp32:esp32:esp32c3:PartitionScheme=huge_app \
  --build-property "build.extra_flags=-DARDUINO_USB_MODE=1 -DARDUINO_USB_CDC_ON_BOOT=1 -DRADIO_INK_STATUS_LED=8 -DRADIO_INK_STANDALONE_DEMO=1" \
  .
```

Serial commands in the harness:

```text
HELP
NEW
SET LABEL Office RF walk
NOTE Baseline scan around the X3 location.
AUTO 8
WIFI-SCAN
BLE-SCAN 10
DEEPSCAN WIFI 1
DEEPSCAN BLE 1
WIFI-CONNECT MySSID|MyPassword
WIFI-DISCONNECT
ISSUE HIGH|WiFi|Open AP found near device|Move to WPA2/WPA3 or remove it
CLEAR WIFI
STATUS
SAVE
EXPORT X3
EXPORT CSV
EXPORT JSON
LIST
LOAD 1
```

## Storage

Audits are saved under `/audits/NNN.ria`. Exports are saved under `/exports/NNN.txt`, `/exports/NNN.csv`, or `/exports/NNN.json`.
