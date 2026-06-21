#include <Arduino.h>
#include <FS.h>
#include <LittleFS.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include "RadioInkAuditApp.h"

#ifndef RADIO_INK_STATUS_LED
#define RADIO_INK_STATUS_LED 8
#endif

#ifndef RADIO_INK_MAX_WIFI
#define RADIO_INK_MAX_WIFI 64
#endif

#ifndef RADIO_INK_MAX_BLE
#define RADIO_INK_MAX_BLE 64
#endif

#ifndef RADIO_INK_MAX_ISSUES
#define RADIO_INK_MAX_ISSUES 32
#endif

#ifndef RADIO_INK_MAX_STATIONS
#define RADIO_INK_MAX_STATIONS 16
#endif

#ifndef RADIO_INK_DEEP_WIFI_MS
#define RADIO_INK_DEEP_WIFI_MS 6000
#endif

struct WiFiFinding {
  String ssid;
  String bssid;
  String auth;
  int32_t rssi = 0;
  int32_t channel = 0;
  bool hidden = false;
  uint32_t seenSeconds = 0;
};

struct BleFinding {
  String address;
  String name;
  String manufacturerHex;
  String services;
  int rssi = 0;
  int8_t txPower = 0;
  uint8_t addressType = 0;
  bool hasTxPower = false;
  uint32_t seenSeconds = 0;
};

struct Issue {
  String severity;
  String area;
  String finding;
  String action;
};

// Deep (focused) audit of a single selected Wi-Fi AP.
struct WiFiDeep {
  bool valid = false;
  String bssid;
  String ssid;
  int32_t channel = 0;
  int rssiMin = 0;
  int rssiMax = 0;
  int rssiAvg = 0;
  uint16_t rssiSamples = 0;
  uint16_t beaconCount = 0;
  uint16_t mgmtFrames = 0;
  uint16_t dataFrames = 0;
  uint8_t stationCount = 0;
  String stations[RADIO_INK_MAX_STATIONS];
  bool privacy = false;
  bool pmfCapable = false;
  bool wpsPresent = false;
  bool randomBssid = false;
  uint32_t scannedSeconds = 0;
};

// Deep (focused) audit of a single selected BLE device.
struct BleDeep {
  bool valid = false;
  String address;
  String name;
  String company;
  String services;
  int rssiMin = 0;
  int rssiMax = 0;
  int rssiAvg = 0;
  uint16_t samples = 0;
  uint8_t addressType = 0;
  bool randomAddress = false;
  uint32_t scannedSeconds = 0;
};

struct Audit {
  uint16_t id = 0;
  String label = "ESP32-C3 RF Audit";
  String note;
  WiFiFinding wifi[RADIO_INK_MAX_WIFI];
  BleFinding ble[RADIO_INK_MAX_BLE];
  Issue issues[RADIO_INK_MAX_ISSUES];
  WiFiDeep wifiDeep;
  BleDeep bleDeep;
  uint8_t wifiCount = 0;
  uint8_t bleCount = 0;
  uint8_t issueCount = 0;
  uint32_t startedSeconds = 0;
  uint32_t lastScanSeconds = 0;
};

static Audit currentAudit;
static String inputLine;
static BLEScan *bleScan = nullptr;
static bool bleReady = false;

String upperCopy(String value);
String clean(String value);
String partAt(const String &value, uint8_t part);
void upsertBleFinding(BLEAdvertisedDevice advertisedDevice);

class RadioInkBleCallbacks : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice advertisedDevice) override {
    upsertBleFinding(advertisedDevice);
  }
};

// Scratch buffer filled by the Wi-Fi promiscuous callback during a deep scan.
// Kept C-style (no String/heap) so the callback stays lightweight.
struct DeepCapture {
  uint8_t bssid[6];
  volatile bool active;
  volatile uint16_t beaconCount;
  volatile uint16_t mgmtFrames;
  volatile uint16_t dataFrames;
  volatile long rssiSum;
  volatile int rssiMin;
  volatile int rssiMax;
  volatile uint16_t rssiSamples;
  uint8_t stations[RADIO_INK_MAX_STATIONS][6];
  volatile uint8_t stationCount;
  volatile bool privacy;
  volatile bool pmf;
  volatile bool wps;
};
static DeepCapture deepCap;

static bool macEq(const uint8_t *a, const uint8_t *b) {
  for (int i = 0; i < 6; i++) if (a[i] != b[i]) return false;
  return true;
}

// Group bit set => broadcast/multicast, not an individual station.
static bool macIsGroup(const uint8_t *m) { return (m[0] & 0x01) != 0; }

static void deepAddStation(const uint8_t *mac) {
  if (macIsGroup(mac)) return;
  if (macEq(mac, deepCap.bssid)) return;
  for (uint8_t i = 0; i < deepCap.stationCount; i++)
    if (macEq(deepCap.stations[i], mac)) return;
  if (deepCap.stationCount < RADIO_INK_MAX_STATIONS) {
    memcpy(deepCap.stations[deepCap.stationCount], mac, 6);
    deepCap.stationCount++;
  }
}

static void deepPromiscuousCb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (!deepCap.active) return;
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
  const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
  const uint8_t *p = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;
  if (len >= 4) len -= 4;  // drop trailing FCS so IE walking stays in bounds
  if (len < 24) return;

  uint8_t ftype = (p[0] >> 2) & 0x03;
  uint8_t fsub = (p[0] >> 4) & 0x0F;
  uint8_t flags = p[1];
  bool toDS = flags & 0x01;
  bool fromDS = flags & 0x02;
  const uint8_t *a1 = p + 4;
  const uint8_t *a2 = p + 10;
  const uint8_t *a3 = p + 16;

  if (!macEq(a1, deepCap.bssid) && !macEq(a2, deepCap.bssid) && !macEq(a3, deepCap.bssid)) return;

  // RSSI is only meaningful from frames the AP itself transmitted (addr2 == BSSID).
  if (macEq(a2, deepCap.bssid)) {
    int rssi = pkt->rx_ctrl.rssi;
    deepCap.rssiSum += rssi;
    if (deepCap.rssiSamples == 0) {
      deepCap.rssiMin = rssi;
      deepCap.rssiMax = rssi;
    } else {
      if (rssi < deepCap.rssiMin) deepCap.rssiMin = rssi;
      if (rssi > deepCap.rssiMax) deepCap.rssiMax = rssi;
    }
    deepCap.rssiSamples++;
  }

  if (ftype == 0) {  // management
    deepCap.mgmtFrames++;
    if (fsub == 8 || fsub == 5) {  // beacon or probe response
      deepCap.beaconCount++;
      if (len >= 24 + 12) {
        uint16_t cap = p[24 + 10] | (p[24 + 11] << 8);
        if (cap & 0x0010) deepCap.privacy = true;  // Privacy bit
        uint16_t idx = 24 + 12;                     // skip fixed params
        while (idx + 2 <= len) {
          uint8_t tag = p[idx];
          uint8_t tlen = p[idx + 1];
          if (idx + 2 + tlen > len) break;
          const uint8_t *d = p + idx + 2;
          if (tag == 48) {  // RSN IE -> walk to RSN capabilities for MFP bits
            uint16_t o = 2;                                  // version
            if (o + 4 <= tlen) o += 4;                       // group cipher
            if (o + 2 <= tlen) { uint16_t c = d[o] | (d[o + 1] << 8); o += 2 + 4 * c; }  // pairwise
            if (o + 2 <= tlen) { uint16_t c = d[o] | (d[o + 1] << 8); o += 2 + 4 * c; }  // akm
            if (o + 2 <= tlen) {
              uint16_t rsncap = d[o] | (d[o + 1] << 8);
              if (rsncap & 0x00C0) deepCap.pmf = true;  // MFPC/MFPR
            }
          } else if (tag == 221 && tlen >= 4) {  // vendor specific
            if (d[0] == 0x00 && d[1] == 0x50 && d[2] == 0xF2 && d[3] == 0x04) deepCap.wps = true;
          }
          idx += 2 + tlen;
        }
      }
    }
    deepAddStation(macEq(a1, deepCap.bssid) ? a2 : a1);
  } else if (ftype == 2) {  // data
    deepCap.dataFrames++;
    if (toDS && !fromDS) deepAddStation(a2);
    else if (!toDS && fromDS) deepAddStation(a1);
    else { deepAddStation(a1); deepAddStation(a2); }
  }
}

String upperCopy(String value) {
  value.toUpperCase();
  return value;
}

String clean(String value) {
  value.trim();
  return value;
}

String pad3(uint16_t value) {
  char buffer[8];
  snprintf(buffer, sizeof(buffer), "%03u", value);
  return String(buffer);
}

String auditPath(uint16_t id) {
  return String("/audits/") + pad3(id) + ".ria";
}

String exportPath(uint16_t id, const String &ext) {
  return String("/exports/") + pad3(id) + "." + ext;
}

String partAt(const String &value, uint8_t part) {
  int start = 0;
  for (uint8_t i = 0; i < part; i++) {
    start = value.indexOf('|', start);
    if (start < 0) return "";
    start++;
  }
  int end = value.indexOf('|', start);
  if (end < 0) end = value.length();
  return value.substring(start, end);
}

String jsonEscape(const String &value) {
  String out;
  out.reserve(value.length() + 8);
  for (size_t i = 0; i < value.length(); i++) {
    char c = value[i];
    if (c == '"' || c == '\\') {
      out += '\\';
      out += c;
    } else if (c == '\n') {
      out += "\\n";
    } else if (c == '\r') {
      out += "\\r";
    } else {
      out += c;
    }
  }
  return out;
}

String csvEscape(const String &value) {
  String out = "\"";
  for (size_t i = 0; i < value.length(); i++) {
    if (value[i] == '"') out += '"';
    out += value[i];
  }
  out += "\"";
  return out;
}

String hexEncode(const String &bytes) {
  static const char *hex = "0123456789ABCDEF";
  String out;
  out.reserve(bytes.length() * 2);
  for (size_t i = 0; i < bytes.length(); i++) {
    uint8_t b = (uint8_t)bytes[i];
    out += hex[(b >> 4) & 0x0F];
    out += hex[b & 0x0F];
  }
  return out;
}

String wrapLine(const String &text, uint8_t width) {
  String out;
  String line;
  int start = 0;
  while (start < (int)text.length()) {
    int next = text.indexOf(' ', start);
    if (next < 0) next = text.length();
    String word = text.substring(start, next);
    if (line.length() && line.length() + 1 + word.length() > width) {
      out += line + "\n";
      line = word;
    } else {
      if (line.length()) line += " ";
      line += word;
    }
    start = next + 1;
  }
  if (line.length()) out += line;
  return out;
}

String wifiAuthName(wifi_auth_mode_t auth) {
  switch (auth) {
    case WIFI_AUTH_OPEN: return "OPEN";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-EAP";
    case WIFI_AUTH_WPA3_PSK: return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
    case WIFI_AUTH_WAPI_PSK: return "WAPI";
    default: return "UNKNOWN";
  }
}

uint8_t issuePenalty(const String &severity) {
  String sev = upperCopy(severity);
  if (sev == "CRITICAL") return 16;
  if (sev == "HIGH") return 9;
  if (sev == "MEDIUM") return 4;
  return 1;
}

uint8_t auditScore() {
  int score = 100;
  uint8_t openNetworks = 0;
  uint8_t weakNetworks = 0;
  uint8_t veryWeak = 0;

  for (uint8_t i = 0; i < currentAudit.wifiCount; i++) {
    if (currentAudit.wifi[i].auth == "OPEN" || currentAudit.wifi[i].auth == "WEP") openNetworks++;
    if (currentAudit.wifi[i].auth == "WPA" || currentAudit.wifi[i].auth == "WEP") weakNetworks++;
    if (currentAudit.wifi[i].rssi < -88) veryWeak++;
  }
  score -= min<int>(openNetworks * 8, 32);
  score -= min<int>(weakNetworks * 5, 20);
  score -= min<int>(veryWeak * 2, 12);

  for (uint8_t i = 0; i < currentAudit.issueCount; i++) {
    score -= issuePenalty(currentAudit.issues[i].severity);
  }

  if (currentAudit.wifiCount == 0 && currentAudit.bleCount == 0) score = 0;
  if (score < 0) score = 0;
  if (score > 100) score = 100;
  return (uint8_t)score;
}

String riskLabel(uint8_t score) {
  if (score >= 90) return "CLEAN";
  if (score >= 75) return "WATCH";
  if (score >= 55) return "NOISY";
  if (score > 0) return "RISK";
  return "UNSCANNED";
}

void ensureDirs() {
  if (!LittleFS.exists("/audits")) LittleFS.mkdir("/audits");
  if (!LittleFS.exists("/exports")) LittleFS.mkdir("/exports");
}

uint16_t nextAuditId() {
  uint16_t maxId = 0;
  File dir = LittleFS.open("/audits");
  File file = dir.openNextFile();
  while (file) {
    String name = file.name();
    int slash = name.lastIndexOf('/');
    int dot = name.lastIndexOf('.');
    if (dot > slash) {
      uint16_t id = name.substring(slash + 1, dot).toInt();
      if (id > maxId) maxId = id;
    }
    file = dir.openNextFile();
  }
  return maxId + 1;
}

void resetAudit() {
  currentAudit = Audit();
  currentAudit.id = nextAuditId();
  currentAudit.startedSeconds = millis() / 1000;
}

int wifiIndexByBssid(const String &bssid) {
  for (uint8_t i = 0; i < currentAudit.wifiCount; i++) {
    if (currentAudit.wifi[i].bssid == bssid) return i;
  }
  return -1;
}

int bleIndexByAddress(const String &address) {
  for (uint8_t i = 0; i < currentAudit.bleCount; i++) {
    if (currentAudit.ble[i].address == address) return i;
  }
  return -1;
}

void upsertWiFiFinding(uint8_t scanIndex) {
  String bssid = WiFi.BSSIDstr(scanIndex);
  int existing = wifiIndexByBssid(bssid);
  if (existing < 0 && currentAudit.wifiCount >= RADIO_INK_MAX_WIFI) return;

  WiFiFinding &finding = existing >= 0 ? currentAudit.wifi[existing] : currentAudit.wifi[currentAudit.wifiCount++];
  finding.ssid = WiFi.SSID(scanIndex);
  finding.bssid = bssid;
  finding.rssi = WiFi.RSSI(scanIndex);
  finding.channel = WiFi.channel(scanIndex);
  finding.auth = wifiAuthName(WiFi.encryptionType(scanIndex));
  finding.hidden = finding.ssid.length() == 0;
  finding.seenSeconds = millis() / 1000;
}

void upsertBleFinding(BLEAdvertisedDevice advertisedDevice) {
  String address = advertisedDevice.getAddress().toString();
  int existing = bleIndexByAddress(address);
  if (existing < 0 && currentAudit.bleCount >= RADIO_INK_MAX_BLE) return;

  BleFinding &finding = existing >= 0 ? currentAudit.ble[existing] : currentAudit.ble[currentAudit.bleCount++];
  finding.address = address;
  finding.name = advertisedDevice.haveName() ? advertisedDevice.getName() : "";
  finding.rssi = advertisedDevice.getRSSI();
  finding.addressType = advertisedDevice.getAddressType();
  finding.hasTxPower = advertisedDevice.haveTXPower();
  finding.txPower = finding.hasTxPower ? advertisedDevice.getTXPower() : 0;
  finding.manufacturerHex = advertisedDevice.haveManufacturerData() ? hexEncode(advertisedDevice.getManufacturerData()) : "";
  finding.services = advertisedDevice.haveServiceUUID() ? String(advertisedDevice.getServiceUUID().toString().c_str()) : "";
  finding.seenSeconds = millis() / 1000;
}

void initWiFiRadio() {
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.disconnect(false, false);
}

void initBleRadio() {
  if (bleReady) return;
  BLEDevice::init("RadioInk-X3");
  bleScan = BLEDevice::getScan();
  bleScan->setAdvertisedDeviceCallbacks(new RadioInkBleCallbacks(), true);
  bleScan->setActiveScan(true);
  bleScan->setInterval(100);
  bleScan->setWindow(99);
  bleReady = true;
}

void scanWiFi() {
  initWiFiRadio();
  Serial.println(F("WIFI scan start"));
  int found = WiFi.scanNetworks(false, true);
  if (found < 0) {
    Serial.println(F("ERR WiFi scan failed"));
    return;
  }
  for (int i = 0; i < found; i++) upsertWiFiFinding((uint8_t)i);
  WiFi.scanDelete();
  currentAudit.lastScanSeconds = millis() / 1000;
  Serial.print(F("OK WIFI "));
  Serial.print(found);
  Serial.print(F(" found, "));
  Serial.print(currentAudit.wifiCount);
  Serial.println(F(" unique"));
}

void scanBle(uint8_t seconds) {
  initBleRadio();
  if (seconds == 0) seconds = 5;
  if (seconds > 30) seconds = 30;
  Serial.print(F("BLE scan start "));
  Serial.print(seconds);
  Serial.println(F("s"));
  BLEScanResults *results = bleScan->start(seconds, false);
  int found = results ? results->getCount() : 0;
  bleScan->clearResults();
  currentAudit.lastScanSeconds = millis() / 1000;
  Serial.print(F("OK BLE "));
  Serial.print(found);
  Serial.print(F(" found, "));
  Serial.print(currentAudit.bleCount);
  Serial.println(F(" unique"));
}

void runAutoAudit(uint8_t bleSeconds) {
  scanWiFi();
  scanBle(bleSeconds);
}

bool parseMac(const String &text, uint8_t out[6]) {
  unsigned int v[6];
  if (sscanf(text.c_str(), "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return false;
  for (int i = 0; i < 6; i++) out[i] = (uint8_t)v[i];
  return true;
}

// Add an issue if no existing one shares the same finding text (dedup for repeated deep scans).
void pushIssue(const String &severity, const String &area, const String &finding, const String &action) {
  for (uint8_t i = 0; i < currentAudit.issueCount; i++)
    if (currentAudit.issues[i].finding == finding) return;
  if (currentAudit.issueCount >= RADIO_INK_MAX_ISSUES) return;
  Issue &issue = currentAudit.issues[currentAudit.issueCount++];
  issue.severity = severity;
  issue.area = area;
  issue.finding = finding;
  issue.action = action;
}

bool isNumeric(const String &value) {
  if (!value.length()) return false;
  for (size_t i = 0; i < value.length(); i++)
    if (!isDigit(value[i])) return false;
  return true;
}

// Report lists targets 1-based, so numeric selectors are 1-based too.
int resolveWifiSelector(const String &sel) {
  if (!sel.length()) return -1;
  if (isNumeric(sel)) {
    int n = sel.toInt() - 1;
    return (n >= 0 && n < currentAudit.wifiCount) ? n : -1;
  }
  String want = upperCopy(sel);
  for (uint8_t i = 0; i < currentAudit.wifiCount; i++) {
    if (upperCopy(currentAudit.wifi[i].bssid) == want) return i;
    if (upperCopy(currentAudit.wifi[i].ssid) == want) return i;
  }
  return -1;
}

int resolveBleSelector(const String &sel) {
  if (!sel.length()) return -1;
  if (isNumeric(sel)) {
    int n = sel.toInt() - 1;
    return (n >= 0 && n < currentAudit.bleCount) ? n : -1;
  }
  String want = upperCopy(sel);
  for (uint8_t i = 0; i < currentAudit.bleCount; i++) {
    if (upperCopy(currentAudit.ble[i].address) == want) return i;
    if (upperCopy(currentAudit.ble[i].name) == want) return i;
  }
  return -1;
}

String bleCompany(const String &hex) {
  if (hex.length() < 4) return "";
  uint16_t id = (uint16_t)strtol(hex.substring(0, 2).c_str(), nullptr, 16) |
                ((uint16_t)strtol(hex.substring(2, 4).c_str(), nullptr, 16) << 8);
  switch (id) {
    case 0x004C: return "Apple";
    case 0x0006: return "Microsoft";
    case 0x00E0: return "Google";
    case 0x0075: return "Samsung";
    case 0x000F: return "Broadcom";
    case 0x0059: return "Nordic";
    case 0x0157: return "Huawei";
    case 0x00D7: return "Qualcomm";
    case 0x0499: return "Ruuvi";
    default: {
      char buffer[12];
      snprintf(buffer, sizeof(buffer), "0x%04X", id);
      return String(buffer);
    }
  }
}

bool deepScanWifi(uint8_t index) {
  if (index >= currentAudit.wifiCount) {
    Serial.println(F("ERR wifi index out of range"));
    return false;
  }
  WiFiFinding &w = currentAudit.wifi[index];
  uint8_t bssid[6];
  if (!parseMac(w.bssid, bssid)) {
    Serial.println(F("ERR bad bssid"));
    return false;
  }

  memset(&deepCap, 0, sizeof(deepCap));
  memcpy(deepCap.bssid, bssid, 6);

  initWiFiRadio();
  WiFi.scanDelete();

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&deepPromiscuousCb);
  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel((uint8_t)w.channel, WIFI_SECOND_CHAN_NONE);

  Serial.print(F("DEEP WiFi "));
  Serial.print(w.ssid.length() ? w.ssid : String("<hidden>"));
  Serial.print(' ');
  Serial.print(w.bssid);
  Serial.print(F(" CH"));
  Serial.print(w.channel);
  Serial.print(F(" for "));
  Serial.print(RADIO_INK_DEEP_WIFI_MS / 1000);
  Serial.println(F("s..."));

  deepCap.active = true;
  uint32_t start = millis();
  while (millis() - start < RADIO_INK_DEEP_WIFI_MS) delay(50);
  deepCap.active = false;

  esp_wifi_set_promiscuous(false);
  initWiFiRadio();

  WiFiDeep &d = currentAudit.wifiDeep;
  d = WiFiDeep();
  d.valid = true;
  d.bssid = w.bssid;
  d.ssid = w.ssid;
  d.channel = w.channel;
  d.beaconCount = deepCap.beaconCount;
  d.mgmtFrames = deepCap.mgmtFrames;
  d.dataFrames = deepCap.dataFrames;
  d.rssiSamples = deepCap.rssiSamples;
  if (deepCap.rssiSamples) {
    d.rssiMin = deepCap.rssiMin;
    d.rssiMax = deepCap.rssiMax;
    d.rssiAvg = (int)(deepCap.rssiSum / (long)deepCap.rssiSamples);
  }
  d.privacy = deepCap.privacy;
  d.pmfCapable = deepCap.pmf;
  d.wpsPresent = deepCap.wps;
  d.randomBssid = (bssid[0] & 0x02) != 0;
  d.stationCount = deepCap.stationCount;
  for (uint8_t i = 0; i < deepCap.stationCount; i++) {
    char buffer[18];
    snprintf(buffer, sizeof(buffer), "%02X:%02X:%02X:%02X:%02X:%02X",
             deepCap.stations[i][0], deepCap.stations[i][1], deepCap.stations[i][2],
             deepCap.stations[i][3], deepCap.stations[i][4], deepCap.stations[i][5]);
    d.stations[i] = String(buffer);
  }
  d.scannedSeconds = millis() / 1000;

  String who = d.ssid.length() ? d.ssid : d.bssid;
  if (d.wpsPresent)
    pushIssue("MEDIUM", "WiFi", String("WPS enabled on ") + who, "Disable WPS to block PIN brute force");
  if (d.privacy && !d.pmfCapable)
    pushIssue("LOW", "WiFi", String("No PMF on ") + who, "Enable 802.11w management frame protection");

  Serial.println(F("---- DEEP WIFI RESULT ----"));
  Serial.print(F("RSSI avg/min/max: "));
  Serial.print(d.rssiAvg); Serial.print('/'); Serial.print(d.rssiMin); Serial.print('/'); Serial.print(d.rssiMax);
  Serial.print(F(" ("));  Serial.print(d.rssiSamples); Serial.println(F(" samples)"));
  Serial.print(F("Beacons: ")); Serial.println(d.beaconCount);
  Serial.print(F("Mgmt/Data frames: ")); Serial.print(d.mgmtFrames); Serial.print('/'); Serial.println(d.dataFrames);
  Serial.print(F("Privacy/PMF/WPS: "));
  Serial.print(d.privacy ? F("yes") : F("no")); Serial.print('/');
  Serial.print(d.pmfCapable ? F("yes") : F("no")); Serial.print('/');
  Serial.println(d.wpsPresent ? F("yes") : F("no"));
  Serial.print(F("Randomized BSSID: ")); Serial.println(d.randomBssid ? F("yes") : F("no"));
  Serial.print(F("Clients: ")); Serial.println(d.stationCount);
  for (uint8_t i = 0; i < d.stationCount; i++) {
    Serial.print(F("  - ")); Serial.println(d.stations[i]);
  }
  return true;
}

bool deepScanBle(uint8_t index) {
  if (index >= currentAudit.bleCount) {
    Serial.println(F("ERR ble index out of range"));
    return false;
  }
  String address = currentAudit.ble[index].address;
  initBleRadio();

  int rssiMin = 0, rssiMax = 0;
  long rssiSum = 0;
  uint16_t samples = 0;

  Serial.print(F("DEEP BLE "));
  Serial.print(address);
  Serial.println(F(" (3 passes)..."));

  for (int pass = 0; pass < 3; pass++) {
    bleScan->start(4, false);
    bleScan->clearResults();
    int idx = bleIndexByAddress(address);
    if (idx >= 0) {
      int rssi = currentAudit.ble[idx].rssi;
      rssiSum += rssi;
      if (samples == 0) { rssiMin = rssi; rssiMax = rssi; }
      else { if (rssi < rssiMin) rssiMin = rssi; if (rssi > rssiMax) rssiMax = rssi; }
      samples++;
    }
  }
  currentAudit.lastScanSeconds = millis() / 1000;

  int idx = bleIndexByAddress(address);
  BleFinding &b = currentAudit.ble[idx >= 0 ? idx : index];
  BleDeep &d = currentAudit.bleDeep;
  d = BleDeep();
  d.valid = true;
  d.address = b.address;
  d.name = b.name;
  d.company = bleCompany(b.manufacturerHex);
  d.services = b.services;
  d.addressType = b.addressType;
  d.randomAddress = (b.addressType == 1 || b.addressType == 3);  // random / random-id
  d.rssiMin = rssiMin;
  d.rssiMax = rssiMax;
  d.samples = samples;
  d.rssiAvg = samples ? (int)(rssiSum / (long)samples) : 0;
  d.scannedSeconds = millis() / 1000;

  Serial.println(F("---- DEEP BLE RESULT ----"));
  Serial.print(F("Name: ")); Serial.println(d.name.length() ? d.name : String("<unnamed>"));
  Serial.print(F("Company: ")); Serial.println(d.company.length() ? d.company : String("<none>"));
  Serial.print(F("Services: ")); Serial.println(d.services.length() ? d.services : String("<none>"));
  Serial.print(F("RSSI avg/min/max: "));
  Serial.print(d.rssiAvg); Serial.print('/'); Serial.print(d.rssiMin); Serial.print('/'); Serial.print(d.rssiMax);
  Serial.print(F(" (")); Serial.print(d.samples); Serial.println(F(" passes seen)"));
  Serial.print(F("Random address: ")); Serial.println(d.randomAddress ? F("yes") : F("no"));
  return true;
}

void writeKv(File &file, const String &key, const String &value) {
  file.print(key);
  file.print('=');
  file.println(value);
}

bool saveAudit() {
  ensureDirs();
  if (currentAudit.id == 0) currentAudit.id = nextAuditId();
  File file = LittleFS.open(auditPath(currentAudit.id), "w");
  if (!file) return false;

  writeKv(file, "label", currentAudit.label);
  writeKv(file, "note", currentAudit.note);
  writeKv(file, "started", String(currentAudit.startedSeconds));
  writeKv(file, "lastScan", String(currentAudit.lastScanSeconds));

  for (uint8_t i = 0; i < currentAudit.wifiCount; i++) {
    WiFiFinding &w = currentAudit.wifi[i];
    writeKv(file, "wifi", w.ssid + "|" + w.bssid + "|" + w.rssi + "|" + w.channel + "|" + w.auth + "|" + (w.hidden ? "1" : "0") + "|" + w.seenSeconds);
  }
  for (uint8_t i = 0; i < currentAudit.bleCount; i++) {
    BleFinding &b = currentAudit.ble[i];
    writeKv(file, "ble", b.address + "|" + b.rssi + "|" + b.txPower + "|" + (b.hasTxPower ? "1" : "0") + "|" + b.addressType + "|" + b.name + "|" + b.manufacturerHex + "|" + b.seenSeconds);
  }
  for (uint8_t i = 0; i < currentAudit.issueCount; i++) {
    Issue &issue = currentAudit.issues[i];
    writeKv(file, "issue", issue.severity + "|" + issue.area + "|" + issue.finding + "|" + issue.action);
  }
  if (currentAudit.wifiDeep.valid) {
    WiFiDeep &d = currentAudit.wifiDeep;
    writeKv(file, "wdeep", d.bssid + "|" + d.ssid + "|" + d.channel + "|" + d.rssiMin + "|" + d.rssiMax + "|" + d.rssiAvg + "|" + d.rssiSamples + "|" + d.beaconCount + "|" + d.mgmtFrames + "|" + d.dataFrames + "|" + (d.privacy ? "1" : "0") + "|" + (d.pmfCapable ? "1" : "0") + "|" + (d.wpsPresent ? "1" : "0") + "|" + (d.randomBssid ? "1" : "0") + "|" + d.scannedSeconds);
    for (uint8_t i = 0; i < d.stationCount; i++) writeKv(file, "wsta", d.stations[i]);
  }
  if (currentAudit.bleDeep.valid) {
    BleDeep &d = currentAudit.bleDeep;
    writeKv(file, "bdeep", d.address + "|" + d.name + "|" + d.company + "|" + d.services + "|" + d.rssiMin + "|" + d.rssiMax + "|" + d.rssiAvg + "|" + d.samples + "|" + d.addressType + "|" + (d.randomAddress ? "1" : "0") + "|" + d.scannedSeconds);
  }
  file.close();
  return true;
}

bool loadAudit(uint16_t id) {
  File file = LittleFS.open(auditPath(id), "r");
  if (!file) return false;
  currentAudit = Audit();
  currentAudit.id = id;

  while (file.available()) {
    String line = clean(file.readStringUntil('\n'));
    if (!line.length()) continue;
    int sep = line.indexOf('=');
    if (sep < 0) continue;
    String key = line.substring(0, sep);
    String value = line.substring(sep + 1);

    if (key == "label") currentAudit.label = value;
    else if (key == "note") currentAudit.note = value;
    else if (key == "started") currentAudit.startedSeconds = value.toInt();
    else if (key == "lastScan") currentAudit.lastScanSeconds = value.toInt();
    else if (key == "wifi" && currentAudit.wifiCount < RADIO_INK_MAX_WIFI) {
      WiFiFinding &w = currentAudit.wifi[currentAudit.wifiCount++];
      w.ssid = partAt(value, 0);
      w.bssid = partAt(value, 1);
      w.rssi = partAt(value, 2).toInt();
      w.channel = partAt(value, 3).toInt();
      w.auth = partAt(value, 4);
      w.hidden = partAt(value, 5) == "1";
      w.seenSeconds = partAt(value, 6).toInt();
    } else if (key == "ble" && currentAudit.bleCount < RADIO_INK_MAX_BLE) {
      BleFinding &b = currentAudit.ble[currentAudit.bleCount++];
      b.address = partAt(value, 0);
      b.rssi = partAt(value, 1).toInt();
      b.txPower = partAt(value, 2).toInt();
      b.hasTxPower = partAt(value, 3) == "1";
      b.addressType = partAt(value, 4).toInt();
      b.name = partAt(value, 5);
      b.manufacturerHex = partAt(value, 6);
      b.seenSeconds = partAt(value, 7).toInt();
    } else if (key == "issue" && currentAudit.issueCount < RADIO_INK_MAX_ISSUES) {
      Issue &issue = currentAudit.issues[currentAudit.issueCount++];
      issue.severity = partAt(value, 0);
      issue.area = partAt(value, 1);
      issue.finding = partAt(value, 2);
      issue.action = partAt(value, 3);
    } else if (key == "wdeep") {
      WiFiDeep &d = currentAudit.wifiDeep;
      d = WiFiDeep();
      d.valid = true;
      d.bssid = partAt(value, 0);
      d.ssid = partAt(value, 1);
      d.channel = partAt(value, 2).toInt();
      d.rssiMin = partAt(value, 3).toInt();
      d.rssiMax = partAt(value, 4).toInt();
      d.rssiAvg = partAt(value, 5).toInt();
      d.rssiSamples = partAt(value, 6).toInt();
      d.beaconCount = partAt(value, 7).toInt();
      d.mgmtFrames = partAt(value, 8).toInt();
      d.dataFrames = partAt(value, 9).toInt();
      d.privacy = partAt(value, 10) == "1";
      d.pmfCapable = partAt(value, 11) == "1";
      d.wpsPresent = partAt(value, 12) == "1";
      d.randomBssid = partAt(value, 13) == "1";
      d.scannedSeconds = partAt(value, 14).toInt();
    } else if (key == "wsta" && currentAudit.wifiDeep.stationCount < RADIO_INK_MAX_STATIONS) {
      currentAudit.wifiDeep.stations[currentAudit.wifiDeep.stationCount++] = value;
    } else if (key == "bdeep") {
      BleDeep &d = currentAudit.bleDeep;
      d = BleDeep();
      d.valid = true;
      d.address = partAt(value, 0);
      d.name = partAt(value, 1);
      d.company = partAt(value, 2);
      d.services = partAt(value, 3);
      d.rssiMin = partAt(value, 4).toInt();
      d.rssiMax = partAt(value, 5).toInt();
      d.rssiAvg = partAt(value, 6).toInt();
      d.samples = partAt(value, 7).toInt();
      d.addressType = partAt(value, 8).toInt();
      d.randomAddress = partAt(value, 9) == "1";
      d.scannedSeconds = partAt(value, 10).toInt();
    }
  }
  file.close();
  return true;
}

String makeX3Report() {
  uint8_t score = auditScore();
  String out;
  out += "RADIO INK X3 RF AUDIT\n";
  out += "=====================\n";
  out += String("ID:    ") + pad3(currentAudit.id) + "\n";
  out += String("Label: ") + currentAudit.label + "\n";
  out += String("Score: ") + score + "/100 " + riskLabel(score) + "\n";
  out += String("WiFi:  ") + currentAudit.wifiCount + " APs\n";
  out += String("BLE:   ") + currentAudit.bleCount + " devices\n";
  out += String("Issues: ") + currentAudit.issueCount + "\n\n";

  out += "NOTE\n----\n";
  out += wrapLine(currentAudit.note.length() ? currentAudit.note : "No note.", 34) + "\n\n";

  out += "WIFI APs\n--------\n";
  if (!currentAudit.wifiCount) out += "No WiFi scan captured.\n";
  for (uint8_t i = 0; i < currentAudit.wifiCount; i++) {
    WiFiFinding &w = currentAudit.wifi[i];
    out += String(i + 1) + ". " + (w.ssid.length() ? w.ssid : String("<hidden>")) + "\n";
    out += String("   ") + w.bssid + " CH" + w.channel + "\n";
    out += String("   ") + w.rssi + " dBm " + w.auth + "\n";
  }

  out += "\nBLE DEVICES\n-----------\n";
  if (!currentAudit.bleCount) out += "No BLE scan captured.\n";
  for (uint8_t i = 0; i < currentAudit.bleCount; i++) {
    BleFinding &b = currentAudit.ble[i];
    out += String(i + 1) + ". " + b.address + "\n";
    out += String("   ") + (b.name.length() ? b.name : String("<unnamed>")) + "\n";
    out += String("   ") + b.rssi + " dBm";
    if (b.hasTxPower) out += String(" TX ") + b.txPower;
    out += "\n";
  }

  out += "\nISSUES\n------\n";
  if (!currentAudit.issueCount) out += "No issues logged.\n";
  for (uint8_t i = 0; i < currentAudit.issueCount; i++) {
    Issue &issue = currentAudit.issues[i];
    out += String(i + 1) + ". [" + issue.severity + "] " + issue.area + "\n";
    out += wrapLine(issue.finding, 34) + "\n";
    if (issue.action.length()) out += String("Act: ") + wrapLine(issue.action, 29) + "\n";
  }

  if (currentAudit.wifiDeep.valid) {
    WiFiDeep &d = currentAudit.wifiDeep;
    out += "\nDEEP WIFI\n---------\n";
    out += (d.ssid.length() ? d.ssid : String("<hidden>")) + "\n";
    out += d.bssid + " CH" + d.channel + "\n";
    out += String("RSSI ") + d.rssiAvg + " (" + d.rssiMin + "/" + d.rssiMax + ")\n";
    out += String("Beacons ") + d.beaconCount + " Data " + d.dataFrames + "\n";
    out += String("Priv ") + (d.privacy ? "Y" : "N") + " PMF " + (d.pmfCapable ? "Y" : "N") + " WPS " + (d.wpsPresent ? "Y" : "N") + "\n";
    if (d.randomBssid) out += "Randomized BSSID\n";
    out += String("Clients: ") + d.stationCount + "\n";
    for (uint8_t i = 0; i < d.stationCount; i++) out += String("  ") + d.stations[i] + "\n";
  }

  if (currentAudit.bleDeep.valid) {
    BleDeep &d = currentAudit.bleDeep;
    out += "\nDEEP BLE\n--------\n";
    out += d.address + "\n";
    out += (d.name.length() ? d.name : String("<unnamed>")) + "\n";
    if (d.company.length()) out += String("Vendor ") + d.company + "\n";
    out += String("RSSI ") + d.rssiAvg + " (" + d.rssiMin + "/" + d.rssiMax + ")\n";
    if (d.services.length()) out += String("Svc ") + d.services + "\n";
    if (d.randomAddress) out += "Random address\n";
  }
  return out;
}

String makeCsvReport() {
  String out = "type,index,ssid,bssid,address,rssi,channel,auth,name,tx_power,address_type,manufacturer,severity,area,text,action\n";
  for (uint8_t i = 0; i < currentAudit.wifiCount; i++) {
    WiFiFinding &w = currentAudit.wifi[i];
    out += String("wifi,") + (i + 1) + "," + csvEscape(w.ssid) + "," + csvEscape(w.bssid) + ",,";
    out += String(w.rssi) + "," + w.channel + "," + csvEscape(w.auth) + ",,,,,,,\n";
  }
  for (uint8_t i = 0; i < currentAudit.bleCount; i++) {
    BleFinding &b = currentAudit.ble[i];
    out += String("ble,") + (i + 1) + ",,," + csvEscape(b.address) + ",";
    out += String(b.rssi) + ",,," + csvEscape(b.name) + ",";
    out += (b.hasTxPower ? String(b.txPower) : String("")) + "," + b.addressType + "," + csvEscape(b.manufacturerHex) + ",,,,\n";
  }
  for (uint8_t i = 0; i < currentAudit.issueCount; i++) {
    Issue &issue = currentAudit.issues[i];
    out += String("issue,") + (i + 1) + ",,,,,,,,,,,";
    out += csvEscape(issue.severity) + "," + csvEscape(issue.area) + "," + csvEscape(issue.finding) + "," + csvEscape(issue.action) + "\n";
  }
  if (currentAudit.wifiDeep.valid) {
    WiFiDeep &d = currentAudit.wifiDeep;
    for (uint8_t i = 0; i < d.stationCount; i++) {
      out += String("client,") + (i + 1) + "," + csvEscape(d.ssid) + "," + csvEscape(d.bssid) + "," + csvEscape(d.stations[i]) + ",";
      out += String(",") + d.channel + ",,,,,,,,,\n";
    }
  }
  return out;
}

String makeJsonReport() {
  String out = "{\n";
  out += String("  \"id\":\"") + pad3(currentAudit.id) + "\",\n";
  out += String("  \"label\":\"") + jsonEscape(currentAudit.label) + "\",\n";
  out += String("  \"score\":") + auditScore() + ",\n";
  out += String("  \"risk\":\"") + riskLabel(auditScore()) + "\",\n";
  out += String("  \"note\":\"") + jsonEscape(currentAudit.note) + "\",\n";
  out += "  \"wifi\":[";
  for (uint8_t i = 0; i < currentAudit.wifiCount; i++) {
    WiFiFinding &w = currentAudit.wifi[i];
    if (i) out += ",";
    out += String("{\"ssid\":\"") + jsonEscape(w.ssid) + "\",\"bssid\":\"" + jsonEscape(w.bssid);
    out += String("\",\"rssi\":") + w.rssi + ",\"channel\":" + w.channel + ",\"auth\":\"" + jsonEscape(w.auth);
    out += String("\",\"hidden\":") + (w.hidden ? "true" : "false") + "}";
  }
  out += "],\n  \"ble\":[";
  for (uint8_t i = 0; i < currentAudit.bleCount; i++) {
    BleFinding &b = currentAudit.ble[i];
    if (i) out += ",";
    out += String("{\"address\":\"") + jsonEscape(b.address) + "\",\"name\":\"" + jsonEscape(b.name);
    out += String("\",\"rssi\":") + b.rssi + ",\"tx_power\":";
    out += b.hasTxPower ? String(b.txPower) : String("null");
    out += String(",\"address_type\":") + b.addressType + ",\"manufacturer\":\"" + jsonEscape(b.manufacturerHex) + "\"}";
  }
  out += "],\n  \"issues\":[";
  for (uint8_t i = 0; i < currentAudit.issueCount; i++) {
    Issue &issue = currentAudit.issues[i];
    if (i) out += ",";
    out += String("{\"severity\":\"") + jsonEscape(issue.severity) + "\",\"area\":\"" + jsonEscape(issue.area);
    out += String("\",\"finding\":\"") + jsonEscape(issue.finding) + "\",\"action\":\"" + jsonEscape(issue.action) + "\"}";
  }
  out += "],\n  \"wifi_deep\":";
  if (currentAudit.wifiDeep.valid) {
    WiFiDeep &d = currentAudit.wifiDeep;
    out += String("{\"bssid\":\"") + jsonEscape(d.bssid) + "\",\"ssid\":\"" + jsonEscape(d.ssid) + "\",\"channel\":" + d.channel;
    out += String(",\"rssi_avg\":") + d.rssiAvg + ",\"rssi_min\":" + d.rssiMin + ",\"rssi_max\":" + d.rssiMax + ",\"rssi_samples\":" + d.rssiSamples;
    out += String(",\"beacons\":") + d.beaconCount + ",\"mgmt_frames\":" + d.mgmtFrames + ",\"data_frames\":" + d.dataFrames;
    out += String(",\"privacy\":") + (d.privacy ? "true" : "false") + ",\"pmf\":" + (d.pmfCapable ? "true" : "false") + ",\"wps\":" + (d.wpsPresent ? "true" : "false") + ",\"random_bssid\":" + (d.randomBssid ? "true" : "false");
    out += ",\"clients\":[";
    for (uint8_t i = 0; i < d.stationCount; i++) {
      if (i) out += ",";
      out += String("\"") + jsonEscape(d.stations[i]) + "\"";
    }
    out += "]}";
  } else {
    out += "null";
  }
  out += ",\n  \"ble_deep\":";
  if (currentAudit.bleDeep.valid) {
    BleDeep &d = currentAudit.bleDeep;
    out += String("{\"address\":\"") + jsonEscape(d.address) + "\",\"name\":\"" + jsonEscape(d.name) + "\",\"company\":\"" + jsonEscape(d.company) + "\",\"services\":\"" + jsonEscape(d.services) + "\"";
    out += String(",\"rssi_avg\":") + d.rssiAvg + ",\"rssi_min\":" + d.rssiMin + ",\"rssi_max\":" + d.rssiMax + ",\"samples\":" + d.samples;
    out += String(",\"address_type\":") + d.addressType + ",\"random_address\":" + (d.randomAddress ? "true" : "false") + "}";
  } else {
    out += "null";
  }
  out += "\n}\n";
  return out;
}

bool writeExport(const String &report, const String &ext) {
  ensureDirs();
  File file = LittleFS.open(exportPath(currentAudit.id, ext), "w");
  if (!file) return false;
  file.print(report);
  file.close();
  return true;
}

void exportReport(const String &kindRaw) {
  String kind = upperCopy(kindRaw);
  String report;
  String ext;
  if (kind == "CSV") {
    report = makeCsvReport();
    ext = "csv";
  } else if (kind == "JSON") {
    report = makeJsonReport();
    ext = "json";
  } else {
    report = makeX3Report();
    ext = "txt";
  }
  if (!saveAudit()) Serial.println(F("WARN audit save failed"));
  writeExport(report, ext);
  Serial.println(F("----- BEGIN EXPORT -----"));
  Serial.print(report);
  Serial.println(F("------ END EXPORT ------"));
  Serial.print(F("Saved: "));
  Serial.println(exportPath(currentAudit.id, ext));
}

void addIssue(const String &body) {
  if (currentAudit.issueCount >= RADIO_INK_MAX_ISSUES) {
    Serial.println(F("ERR issue limit reached"));
    return;
  }
  Issue &issue = currentAudit.issues[currentAudit.issueCount++];
  issue.severity = upperCopy(clean(partAt(body, 0)));
  issue.area = clean(partAt(body, 1));
  issue.finding = clean(partAt(body, 2));
  issue.action = clean(partAt(body, 3));
  Serial.println(F("OK issue added"));
}

void connectWiFi(const String &body) {
  String ssid = clean(partAt(body, 0));
  String pass = partAt(body, 1);
  if (!ssid.length()) {
    Serial.println(F("ERR WIFI-CONNECT <ssid>|<password>"));
    return;
  }
  initWiFiRadio();
  Serial.print(F("WIFI connect "));
  Serial.println(ssid);
  WiFi.begin(ssid.c_str(), pass.c_str());
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) {
    delay(250);
    Serial.print('.');
  }
  Serial.println();
  if (WiFi.status() == WL_CONNECTED) {
    Serial.print(F("OK IP "));
    Serial.println(WiFi.localIP());
  } else {
    Serial.println(F("ERR connect timeout"));
  }
}

void printStatus() {
  uint8_t score = auditScore();
  Serial.println(F("---- XTEINK ESP32-C3 RF AUDIT ----"));
  Serial.print(F("ID: ")); Serial.println(pad3(currentAudit.id));
  Serial.print(F("Label: ")); Serial.println(currentAudit.label);
  Serial.print(F("Score: ")); Serial.print(score); Serial.print(F("/100 ")); Serial.println(riskLabel(score));
  Serial.print(F("WiFi APs: ")); Serial.println(currentAudit.wifiCount);
  Serial.print(F("BLE devices: ")); Serial.println(currentAudit.bleCount);
  Serial.print(F("Issues: ")); Serial.println(currentAudit.issueCount);
  if (currentAudit.wifiDeep.valid) {
    Serial.print(F("Deep WiFi: "));
    Serial.print(currentAudit.wifiDeep.ssid.length() ? currentAudit.wifiDeep.ssid : currentAudit.wifiDeep.bssid);
    Serial.print(F(" ("));
    Serial.print(currentAudit.wifiDeep.stationCount);
    Serial.println(F(" clients)"));
  }
  if (currentAudit.bleDeep.valid) {
    Serial.print(F("Deep BLE: "));
    Serial.println(currentAudit.bleDeep.address);
  }
  Serial.print(F("WiFi status: ")); Serial.println(WiFi.status() == WL_CONNECTED ? WiFi.localIP().toString() : "disconnected");
}

void listAudits() {
  ensureDirs();
  File dir = LittleFS.open("/audits");
  File file = dir.openNextFile();
  Serial.println(F("Saved audits:"));
  while (file) {
    Serial.print(F("  "));
    Serial.print(file.name());
    Serial.print(F("  "));
    Serial.print(file.size());
    Serial.println(F(" bytes"));
    file = dir.openNextFile();
  }
}

void clearSection(const String &sectionRaw) {
  String section = upperCopy(sectionRaw);
  if (section == "WIFI") { currentAudit.wifiCount = 0; currentAudit.wifiDeep = WiFiDeep(); }
  else if (section == "BLE") { currentAudit.bleCount = 0; currentAudit.bleDeep = BleDeep(); }
  else if (section == "ISSUES") currentAudit.issueCount = 0;
  else if (section == "DEEP") {
    currentAudit.wifiDeep = WiFiDeep();
    currentAudit.bleDeep = BleDeep();
  } else if (section == "ALL") {
    currentAudit.wifiCount = 0;
    currentAudit.bleCount = 0;
    currentAudit.issueCount = 0;
    currentAudit.wifiDeep = WiFiDeep();
    currentAudit.bleDeep = BleDeep();
  } else {
    Serial.println(F("ERR CLEAR WIFI|BLE|ISSUES|DEEP|ALL"));
    return;
  }
  Serial.println(F("OK cleared"));
}

void printHelp() {
  Serial.println();
  Serial.println(F("Radio Ink X3 ESP32-C3 WiFi/BLE Auditor"));
  Serial.println(F("Commands:"));
  Serial.println(F("  NEW"));
  Serial.println(F("  SET LABEL <name>"));
  Serial.println(F("  NOTE <text>"));
  Serial.println(F("  AUTO [ble_seconds]"));
  Serial.println(F("  WIFI-SCAN"));
  Serial.println(F("  BLE-SCAN [seconds]"));
  Serial.println(F("  DEEPSCAN WIFI <index|bssid|ssid>"));
  Serial.println(F("  DEEPSCAN BLE <index|address|name>"));
  Serial.println(F("  WIFI-CONNECT <ssid>|<password>"));
  Serial.println(F("  WIFI-DISCONNECT"));
  Serial.println(F("  ISSUE <severity>|<area>|<finding>|<action>"));
  Serial.println(F("  CLEAR WIFI|BLE|ISSUES|DEEP|ALL"));
  Serial.println(F("  STATUS"));
  Serial.println(F("  SAVE"));
  Serial.println(F("  EXPORT X3|TXT|CSV|JSON"));
  Serial.println(F("  LIST"));
  Serial.println(F("  LOAD <id>"));
  Serial.println(F("  HELP"));
  Serial.println();
}

void handleCommand(String line) {
  line = clean(line);
  if (!line.length()) return;
  int space = line.indexOf(' ');
  String command = upperCopy(space < 0 ? line : line.substring(0, space));
  String rest = clean(space < 0 ? "" : line.substring(space + 1));

  digitalWrite(RADIO_INK_STATUS_LED, HIGH);

  if (command == "HELP" || command == "?") {
    printHelp();
  } else if (command == "NEW") {
    resetAudit();
    Serial.print(F("OK new audit "));
    Serial.println(pad3(currentAudit.id));
  } else if (command == "SET") {
    int sep = rest.indexOf(' ');
    if (sep < 0) Serial.println(F("ERR SET LABEL <value>"));
    else if (upperCopy(rest.substring(0, sep)) == "LABEL") {
      currentAudit.label = clean(rest.substring(sep + 1));
      Serial.println(F("OK"));
    } else {
      Serial.println(F("ERR unknown SET field"));
    }
  } else if (command == "NOTE") {
    currentAudit.note = rest;
    Serial.println(F("OK"));
  } else if (command == "AUTO" || command == "AUTO-NET") {
    runAutoAudit(rest.length() ? rest.toInt() : 5);
  } else if (command == "WIFI-SCAN" || command == "NETWORK-SCAN") {
    scanWiFi();
  } else if (command == "BLE-SCAN") {
    scanBle(rest.length() ? rest.toInt() : 5);
  } else if (command == "DEEPSCAN" || command == "DEEP") {
    int sep = rest.indexOf(' ');
    String kind = upperCopy(sep < 0 ? rest : rest.substring(0, sep));
    String selector = clean(sep < 0 ? "" : rest.substring(sep + 1));
    if (kind == "WIFI") {
      int idx = resolveWifiSelector(selector);
      if (idx < 0) Serial.println(F("ERR DEEPSCAN WIFI <index|bssid|ssid>"));
      else deepScanWifi((uint8_t)idx);
    } else if (kind == "BLE") {
      int idx = resolveBleSelector(selector);
      if (idx < 0) Serial.println(F("ERR DEEPSCAN BLE <index|address|name>"));
      else deepScanBle((uint8_t)idx);
    } else {
      Serial.println(F("ERR DEEPSCAN WIFI|BLE <selector>"));
    }
  } else if (command == "WIFI-CONNECT") {
    connectWiFi(rest);
  } else if (command == "WIFI-DISCONNECT") {
    WiFi.disconnect(false, false);
    Serial.println(F("OK disconnected"));
  } else if (command == "ISSUE") {
    addIssue(rest);
  } else if (command == "CLEAR") {
    clearSection(rest);
  } else if (command == "STATUS") {
    printStatus();
  } else if (command == "SAVE") {
    Serial.println(saveAudit() ? F("OK saved") : F("ERR save failed"));
  } else if (command == "EXPORT") {
    exportReport(rest.length() ? rest : "X3");
  } else if (command == "LIST") {
    listAudits();
  } else if (command == "LOAD") {
    uint16_t id = rest.toInt();
    Serial.println(loadAudit(id) ? F("OK loaded") : F("ERR load failed"));
  } else {
    Serial.println(F("ERR unknown command. Type HELP."));
  }

  digitalWrite(RADIO_INK_STATUS_LED, LOW);
}

namespace RadioInkAuditApp {
void begin(bool announce) {
  pinMode(RADIO_INK_STATUS_LED, OUTPUT);
  digitalWrite(RADIO_INK_STATUS_LED, LOW);

  if (!LittleFS.begin(true)) {
    Serial.println(F("ERR LittleFS mount failed"));
  } else {
    ensureDirs();
  }

  initWiFiRadio();
  resetAudit();
  if (!announce) return;
  Serial.println();
  Serial.println(F("Radio Ink X3 ESP32-C3 WiFi/BLE Auditor ready."));
  Serial.print(F("Current audit: "));
  Serial.println(pad3(currentAudit.id));
  printHelp();
}

void pollSerial() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      handleCommand(inputLine);
      inputLine = "";
    } else if (inputLine.length() < 512) {
      inputLine += c;
    }
  }
}

void command(const String &line) {
  handleCommand(line);
}

void autoScan(uint8_t bleSeconds) {
  runAutoAudit(bleSeconds);
}

bool deepScanWifi(uint8_t index) {
  return ::deepScanWifi(index);
}

bool deepScanBle(uint8_t index) {
  return ::deepScanBle(index);
}

String reportText() {
  return makeX3Report();
}

String reportCsv() {
  return makeCsvReport();
}

String reportJson() {
  return makeJsonReport();
}
}

#if defined(RADIO_INK_STANDALONE_DEMO)
void setup() {
  Serial.begin(115200);
  delay(250);
  RadioInkAuditApp::begin(true);
}

void loop() {
  RadioInkAuditApp::pollSerial();
}
#endif
