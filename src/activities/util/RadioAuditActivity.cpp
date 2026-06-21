#include "RadioAuditActivity.h"

#include <GfxRenderer.h>
#include <HalClock.h>
#include <HalStorage.h>
#include <Logging.h>
#include <esp_wifi.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "MappedInputManager.h"
#include "components/UITheme.h"
#include "fontIds.h"
#include "images/RadioInkSkull.h"

namespace {
constexpr const char* RADIO_INK_VERSION = "v0.1";
constexpr int ACTION_COUNT = 10;

// Leaf action labels (index = action id used by runAction()).
constexpr const char* ACTION_LABELS[ACTION_COUNT] = {
    "Quick Scan",       "Deep Scan",       "Audit Findings",         "View WiFi results",     "View BLE results",
    "Save text report", "Save CSV report", "Save JSON report",       "Client Recon (probes)", "Channel usage"};

// Top-level menu categories, each grouping a set of leaf action ids.
struct ActionCategory {
  const char* name;
  const int* items;
  int count;
};
constexpr int CAT_SCAN_ITEMS[] = {0, 1, 8};        // Quick, Deep, Client Recon
constexpr int CAT_RESULTS_ITEMS[] = {2, 3, 4, 9};  // Findings, WiFi, BLE, Channel usage
constexpr int CAT_EXPORT_ITEMS[] = {5, 6, 7};      // text, CSV, JSON
constexpr ActionCategory ACTION_CATEGORIES[] = {
    {"Scan", CAT_SCAN_ITEMS, 3},
    {"Results", CAT_RESULTS_ITEMS, 4},
    {"Export", CAT_EXPORT_ITEMS, 3},
};
constexpr int CATEGORY_COUNT = 3;

constexpr int QUICK_SCAN_PASSES = 1;
constexpr int DEEP_SCAN_PASSES = 3;
constexpr size_t MAX_WIFI_FINDINGS = 64;
constexpr size_t MAX_BLE_FINDINGS = 24;
constexpr const char* AUDIT_DIR = "/.radioink/radio_ink";
constexpr const char* TEXT_EXPORT_PATH = "/.radioink/radio_ink/latest.txt";
constexpr const char* CSV_EXPORT_PATH = "/.radioink/radio_ink/latest.csv";
constexpr const char* JSON_EXPORT_PATH = "/.radioink/radio_ink/latest.json";
constexpr const char* WATCHLIST_PATH = "/.radioink/radio_ink/watchlist.txt";
constexpr const char* SNAPSHOT_PATH = "/.radioink/radio_ink/last_scan.txt";

String hexEncode(const String& bytes) {
  static constexpr char hex[] = "0123456789ABCDEF";
  String out;
  out.reserve(bytes.length() * 2);
  for (size_t i = 0; i < bytes.length(); i++) {
    const uint8_t b = static_cast<uint8_t>(bytes[i]);
    out += hex[(b >> 4) & 0x0F];
    out += hex[b & 0x0F];
  }
  return out;
}

// ---- Per-target Wi-Fi deep scan (promiscuous capture) ----
constexpr int TARGET_WIFI_DEEP_MS = 6000;
constexpr int TARGET_MAX_CLIENTS = 24;

struct WifiTargetCapture {
  uint8_t bssid[6];
  volatile bool active;
  volatile uint16_t beaconCount;
  volatile uint16_t mgmtFrames;
  volatile uint16_t dataFrames;
  volatile uint16_t deauthFrames;
  volatile uint16_t disassocFrames;
  volatile long rssiSum;
  volatile int rssiMin;
  volatile int rssiMax;
  volatile uint16_t rssiSamples;
  uint8_t clients[TARGET_MAX_CLIENTS][6];
  volatile uint8_t clientCount;
  volatile bool privacy;
  volatile bool pmf;
  volatile bool wps;
};
WifiTargetCapture g_targetCap;

bool macEq(const uint8_t* a, const uint8_t* b) {
  for (int i = 0; i < 6; i++)
    if (a[i] != b[i]) return false;
  return true;
}

// Group bit set => broadcast/multicast, not an individual station.
bool macIsGroup(const uint8_t* m) { return (m[0] & 0x01) != 0; }

void targetAddClient(const uint8_t* mac) {
  if (macIsGroup(mac)) return;
  if (macEq(mac, g_targetCap.bssid)) return;
  for (uint8_t i = 0; i < g_targetCap.clientCount; i++)
    if (macEq(g_targetCap.clients[i], mac)) return;
  if (g_targetCap.clientCount < TARGET_MAX_CLIENTS) {
    memcpy(g_targetCap.clients[g_targetCap.clientCount], mac, 6);
    g_targetCap.clientCount++;
  }
}

void targetPromiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!g_targetCap.active) return;
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
  const wifi_promiscuous_pkt_t* pkt = static_cast<const wifi_promiscuous_pkt_t*>(buf);
  const uint8_t* p = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;
  if (len >= 4) len -= 4;  // drop trailing FCS so IE walking stays in bounds
  if (len < 24) return;

  const uint8_t ftype = (p[0] >> 2) & 0x03;
  const uint8_t fsub = (p[0] >> 4) & 0x0F;
  const uint8_t flags = p[1];
  const bool toDS = flags & 0x01;
  const bool fromDS = flags & 0x02;
  const uint8_t* a1 = p + 4;
  const uint8_t* a2 = p + 10;
  const uint8_t* a3 = p + 16;

  if (!macEq(a1, g_targetCap.bssid) && !macEq(a2, g_targetCap.bssid) && !macEq(a3, g_targetCap.bssid)) return;

  // RSSI is only meaningful from frames the AP itself transmitted (addr2 == BSSID).
  if (macEq(a2, g_targetCap.bssid)) {
    const int rssi = pkt->rx_ctrl.rssi;
    g_targetCap.rssiSum += rssi;
    if (g_targetCap.rssiSamples == 0) {
      g_targetCap.rssiMin = rssi;
      g_targetCap.rssiMax = rssi;
    } else {
      if (rssi < g_targetCap.rssiMin) g_targetCap.rssiMin = rssi;
      if (rssi > g_targetCap.rssiMax) g_targetCap.rssiMax = rssi;
    }
    g_targetCap.rssiSamples++;
  }

  if (ftype == 0) {  // management
    g_targetCap.mgmtFrames++;
    if (fsub == 12) g_targetCap.deauthFrames++;       // deauthentication
    else if (fsub == 10) g_targetCap.disassocFrames++;  // disassociation
    if (fsub == 8 || fsub == 5) {  // beacon or probe response
      g_targetCap.beaconCount++;
      if (len >= 24 + 12) {
        const uint16_t cap = p[24 + 10] | (p[24 + 11] << 8);
        if (cap & 0x0010) g_targetCap.privacy = true;  // Privacy bit
        uint16_t idx = 24 + 12;                          // skip fixed params
        while (idx + 2 <= len) {
          const uint8_t tag = p[idx];
          const uint8_t tlen = p[idx + 1];
          if (idx + 2 + tlen > len) break;
          const uint8_t* d = p + idx + 2;
          if (tag == 48) {  // RSN IE -> walk to RSN capabilities for MFP bits
            uint16_t o = 2;                                  // version
            if (o + 4 <= tlen) o += 4;                       // group cipher
            if (o + 2 <= tlen) { uint16_t c = d[o] | (d[o + 1] << 8); o += 2 + 4 * c; }  // pairwise
            if (o + 2 <= tlen) { uint16_t c = d[o] | (d[o + 1] << 8); o += 2 + 4 * c; }  // akm
            if (o + 2 <= tlen) {
              const uint16_t rsncap = d[o] | (d[o + 1] << 8);
              if (rsncap & 0x00C0) g_targetCap.pmf = true;  // MFPC/MFPR
            }
          } else if (tag == 221 && tlen >= 4) {  // vendor specific
            if (d[0] == 0x00 && d[1] == 0x50 && d[2] == 0xF2 && d[3] == 0x04) g_targetCap.wps = true;
          }
          idx += 2 + tlen;
        }
      }
    }
    targetAddClient(macEq(a1, g_targetCap.bssid) ? a2 : a1);
  } else if (ftype == 2) {  // data
    g_targetCap.dataFrames++;
    if (toDS && !fromDS) targetAddClient(a2);
    else if (!toDS && fromDS) targetAddClient(a1);
    else { targetAddClient(a1); targetAddClient(a2); }
  }
}

bool parseBssid(const std::string& text, uint8_t out[6]) {
  unsigned int v[6];
  if (sscanf(text.c_str(), "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return false;
  for (int i = 0; i < 6; i++) out[i] = static_cast<uint8_t>(v[i]);
  return true;
}

std::string macToString(const uint8_t* m) {
  char b[18];
  snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
  return std::string(b);
}

std::string bleCompany(const std::string& hex) {
  if (hex.size() < 4) return "";
  const uint16_t id = static_cast<uint16_t>(strtol(hex.substr(0, 2).c_str(), nullptr, 16)) |
                      (static_cast<uint16_t>(strtol(hex.substr(2, 2).c_str(), nullptr, 16)) << 8);
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
      char b[12];
      snprintf(b, sizeof(b), "0x%04X", id);
      return std::string(b);
    }
  }
}

// Reads HH:MM:SS UTC straight from the DS3231 (X3 only). Returns "" if no RTC.
std::string clockStampUtc() {
  if (!halClock.isAvailable()) return "";
  Wire.beginTransmission(I2C_ADDR_DS3231);
  Wire.write(DS3231_SEC_REG);
  if (Wire.endTransmission(false) != 0) return "";
  Wire.requestFrom(static_cast<uint8_t>(I2C_ADDR_DS3231), static_cast<uint8_t>(3));
  if (Wire.available() < 3) return "";
  const uint8_t rawSec = Wire.read();
  const uint8_t rawMin = Wire.read();
  const uint8_t rawHour = Wire.read();
  const uint8_t sec = ((rawSec >> 4) & 0x07) * 10 + (rawSec & 0x0F);
  const uint8_t min = ((rawMin >> 4) & 0x07) * 10 + (rawMin & 0x0F);
  uint8_t hour;
  if (rawHour & 0x40) {  // 12h mode
    uint8_t h12 = ((rawHour >> 4) & 0x01) * 10 + (rawHour & 0x0F);
    const bool pm = rawHour & 0x20;
    if (h12 == 12) h12 = 0;
    hour = pm ? h12 + 12 : h12;
  } else {  // 24h mode
    hour = ((rawHour >> 4) & 0x03) * 10 + (rawHour & 0x0F);
  }
  char buf[16];
  snprintf(buf, sizeof(buf), "%02u:%02u:%02uZ", hour, min, sec);
  return std::string(buf);
}

// Best available stamp: RTC time of day, else device uptime.
std::string timeStamp() {
  const std::string t = clockStampUtc();
  if (!t.empty()) return t;
  return std::string("uptime ") + std::to_string(millis() / 1000) + "s";
}

std::string upperStr(std::string s) {
  for (auto& c : s) c = static_cast<char>(toupper(static_cast<unsigned char>(c)));
  return s;
}

// ---- Curated OUI -> vendor lookup (first 3 MAC octets) ----
struct OuiEntry {
  uint32_t oui;
  const char* name;
};
const OuiEntry OUI_TABLE[] = {
    // Espressif (ESP8266/ESP32 - very common in IoT)
    {0x240AC4, "Espressif"}, {0x246F28, "Espressif"}, {0x30AEA4, "Espressif"}, {0x7C9EBD, "Espressif"},
    {0x84CCA8, "Espressif"}, {0xA020A6, "Espressif"}, {0xAC67B2, "Espressif"}, {0xB4E62D, "Espressif"},
    {0xC44F33, "Espressif"}, {0xD8A01D, "Espressif"}, {0xECFABC, "Espressif"}, {0x3C71BF, "Espressif"},
    // Apple
    {0xACBC32, "Apple"}, {0xDCA904, "Apple"}, {0xF01898, "Apple"}, {0x3C0754, "Apple"}, {0x88665A, "Apple"},
    {0x001CB3, "Apple"}, {0x001EC2, "Apple"}, {0xF099BF, "Apple"},
    // Raspberry Pi
    {0xB827EB, "Raspberry Pi"}, {0xDCA632, "Raspberry Pi"}, {0xE45F01, "Raspberry Pi"}, {0x28CDC1, "Raspberry Pi"},
    // Samsung
    {0x0012FB, "Samsung"}, {0x5C0A5B, "Samsung"}, {0x8C7712, "Samsung"}, {0xAC5F3E, "Samsung"}, {0xC819F7, "Samsung"},
    // Google / Nest
    {0x3C5AB4, "Google"}, {0x94EB2C, "Google"}, {0xA47733, "Google"}, {0xF4F5E8, "Google"}, {0xD86C63, "Google"},
    // Amazon
    {0x0C47C9, "Amazon"}, {0x44650D, "Amazon"}, {0x6837E9, "Amazon"}, {0xF0272D, "Amazon"}, {0xFC65DE, "Amazon"},
    // Intel
    {0x001B21, "Intel"}, {0x3413E8, "Intel"}, {0x3CA9F4, "Intel"}, {0x7C7A91, "Intel"}, {0xA08869, "Intel"},
    // TP-Link
    {0x50C7BF, "TP-Link"}, {0x60A4B7, "TP-Link"}, {0xA42BB0, "TP-Link"}, {0xEC086B, "TP-Link"},
    // Ubiquiti
    {0x00156D, "Ubiquiti"}, {0x245A4C, "Ubiquiti"}, {0x7483C2, "Ubiquiti"}, {0xFCECDA, "Ubiquiti"},
    // Netgear
    {0x00146C, "Netgear"}, {0x20E52A, "Netgear"}, {0x9C3DCF, "Netgear"}, {0xA040A0, "Netgear"},
    // Sonos
    {0x000E58, "Sonos"}, {0x347E5C, "Sonos"}, {0x48A6B8, "Sonos"}, {0xB8E937, "Sonos"},
    // Texas Instruments (BLE)
    {0x00124B, "TI"}, {0x98072D, "TI"}, {0x546C0E, "TI"}, {0xA0E6F8, "TI"},
    // Microsoft
    {0x7C1E52, "Microsoft"}, {0xC83F26, "Microsoft"}, {0x281878, "Microsoft"},
};

// Returns a vendor name, "randomized" for locally-administered MACs, or "" if unknown.
std::string macVendor(const std::string& mac) {
  unsigned int b0, b1, b2;
  if (sscanf(mac.c_str(), "%x:%x:%x", &b0, &b1, &b2) != 3) return "";
  if (b0 & 0x02) return "randomized";  // locally administered -> likely a random MAC
  const uint32_t oui = (b0 << 16) | (b1 << 8) | b2;
  for (const auto& e : OUI_TABLE)
    if (e.oui == oui) return e.name;
  return "";
}

// ---- BLE advertising-data decoder (iBeacon / Eddystone / Apple / etc.) ----
std::vector<uint8_t> hexToBytes(const std::string& hex) {
  std::vector<uint8_t> out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2)
    out.push_back(static_cast<uint8_t>(strtol(hex.substr(i, 2).c_str(), nullptr, 16)));
  return out;
}

std::string eddystoneUrl(const std::vector<uint8_t>& d) {
  static const char* schemes[] = {"http://www.", "https://www.", "http://", "https://"};
  static const char* expansions[] = {".com/", ".org/", ".edu/", ".net/", ".info/", ".biz/", ".gov/",
                                     ".com",  ".org",  ".edu",  ".net",  ".info",  ".biz",  ".gov"};
  std::string url;
  if (d.size() < 3) return url;
  if (d[2] <= 3) url += schemes[d[2]];
  for (size_t i = 3; i < d.size(); i++) {
    const uint8_t c = d[i];
    if (c < 14) url += expansions[c];
    else if (c >= 0x20 && c < 0x7F) url += static_cast<char>(c);
  }
  return url;
}

std::string decodeBleAdvert(const std::string& manufacturerHex, const std::string& svcUuid,
                            const std::string& svcDataHex) {
  std::string uuid = svcUuid;
  for (auto& ch : uuid) ch = static_cast<char>(toupper(static_cast<unsigned char>(ch)));
  if (uuid.find("FEAA") != std::string::npos) {  // Eddystone
    const std::vector<uint8_t> d = hexToBytes(svcDataHex);
    if (!d.empty()) {
      switch (d[0]) {
        case 0x00: return "Eddystone-UID";
        case 0x10: {
          const std::string u = eddystoneUrl(d);
          return u.empty() ? "Eddystone-URL" : ("Eddystone " + u);
        }
        case 0x20: return "Eddystone-TLM";
        case 0x30: return "Eddystone-EID";
        default: return "Eddystone";
      }
    }
    return "Eddystone";
  }
  if (uuid.find("FE2C") != std::string::npos) return "Google Fast Pair";

  const std::vector<uint8_t> m = hexToBytes(manufacturerHex);
  if (m.size() < 2) return "";
  const uint16_t company = m[0] | (m[1] << 8);
  if (company == 0x004C) {  // Apple
    if (m.size() >= 25 && m[2] == 0x02 && m[3] == 0x15) {
      char uuidStr[40];
      snprintf(uuidStr, sizeof(uuidStr), "%02X%02X%02X%02X-%02X%02X-%02X%02X", m[4], m[5], m[6], m[7], m[8], m[9],
               m[10], m[11]);
      const uint16_t major = (m[20] << 8) | m[21];
      const uint16_t minor = (m[22] << 8) | m[23];
      return std::string("iBeacon ") + uuidStr + " " + std::to_string(major) + "/" + std::to_string(minor);
    }
    if (m.size() >= 3) {
      switch (m[2]) {
        case 0x12: return "Apple FindMy/AirTag";
        case 0x07: return "Apple AirPods/pairing";
        case 0x10: return "Apple Nearby";
        case 0x0C: return "Apple Handoff";
        case 0x05: return "Apple AirDrop";
        default: break;
      }
    }
    return "Apple device";
  }
  if (company == 0x0006) return "Microsoft (Swift Pair?)";
  if (company == 0x00E0) return "Google";
  if (company == 0x0075) return "Samsung";
  return "";
}

// ---- Probe-request harvesting (channel-hopping promiscuous capture) ----
constexpr int PROBE_MAX = 48;

struct ProbeCapture {
  volatile bool active;
  struct Row {
    uint8_t mac[6];
    char ssid[33];
    int8_t rssi;
  };
  Row rows[PROBE_MAX];
  volatile uint8_t count;
};
ProbeCapture g_probeCap;

void probePromiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!g_probeCap.active) return;
  if (type != WIFI_PKT_MGMT) return;
  const wifi_promiscuous_pkt_t* pkt = static_cast<const wifi_promiscuous_pkt_t*>(buf);
  const uint8_t* p = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;
  if (len >= 4) len -= 4;
  if (len < 24) return;

  const uint8_t ftype = (p[0] >> 2) & 0x03;
  const uint8_t fsub = (p[0] >> 4) & 0x0F;
  if (ftype != 0 || fsub != 4) return;  // probe request only
  const uint8_t* sa = p + 10;           // addr2 = source (client)
  if (sa[0] & 0x01) return;             // ignore group source addresses

  char ssid[33];
  ssid[0] = '\0';
  if (len >= 24 + 2) {  // SSID IE (tag 0) is first tagged param in the body
    const uint8_t tag = p[24];
    const uint8_t tlen = p[24 + 1];
    if (tag == 0 && tlen > 0 && 24 + 2 + tlen <= len) {
      const uint8_t n = tlen > 32 ? 32 : tlen;
      memcpy(ssid, p + 24 + 2, n);
      ssid[n] = '\0';
    }
  }

  for (uint8_t i = 0; i < g_probeCap.count; i++)
    if (macEq(g_probeCap.rows[i].mac, sa) && strcmp(g_probeCap.rows[i].ssid, ssid) == 0) return;
  if (g_probeCap.count < PROBE_MAX) {
    memcpy(g_probeCap.rows[g_probeCap.count].mac, sa, 6);
    memcpy(g_probeCap.rows[g_probeCap.count].ssid, ssid, sizeof(ssid));
    g_probeCap.rows[g_probeCap.count].rssi = static_cast<int8_t>(pkt->rx_ctrl.rssi);
    g_probeCap.count++;
  }
}
}  // namespace

void RadioAuditActivity::onEnter() {
  Activity::onEnter();
  selectedAction = 0;
  currentCategory = -1;
  selectedCategory = 0;
  selectedItem = 0;
  showingDetails = false;
  showingFindings = false;
  showingTarget = false;
  locating = false;
  targetLocatable = false;
  status = "Ready";
  requestUpdate();
}

void RadioAuditActivity::onExit() {
  Activity::onExit();
  if (locating) {
    locating = false;
    esp_wifi_set_promiscuous(false);
  }
  WiFi.scanDelete();
  shutdownBleController();
}

void RadioAuditActivity::loop() {
  if (state == State::WIFI_SCANNING) {
    processWifiScan();
    return;
  }

  // Live "find it" RSSI locator: sample periodically, any button exits to detail.
  if (locating) {
    if (mappedInput.wasPressed(MappedInputManager::Button::Back) ||
        mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
      stopLocator();
      showingTarget = true;
      requestUpdate();
      return;
    }
    const uint32_t now = millis();
    if (locLastSampleMs == 0 || now - locLastSampleMs >= 700) {
      locPrevRssi = locHasSignal ? locCurRssi : locPrevRssi;
      locatorSample();
      locLastSampleMs = millis();
      requestUpdate();
    }
    return;
  }

  // Per-target deep-scan detail view: scroll lines; Select locates (when locatable).
  if (showingTarget) {
    if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
      showingTarget = false;
      showingDetails = targetFromList;  // return to the list only if we came from one
      requestUpdate();
      return;
    }
    if (mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
      if (targetLocatable) {
        startLocator();
        return;
      }
      showingTarget = false;
      showingDetails = targetFromList;
      requestUpdate();
      return;
    }
    const int lineCount = static_cast<int>(targetLines.size());
    if (lineCount > 0) {
      buttonNavigator.onNext([this, lineCount] {
        targetScroll = ButtonNavigator::nextIndex(targetScroll, lineCount);
        requestUpdate();
      });
      buttonNavigator.onPrevious([this, lineCount] {
        targetScroll = ButtonNavigator::previousIndex(targetScroll, lineCount);
        requestUpdate();
      });
    }
    return;
  }

  if (showingDetails || showingFindings) {
    const int itemCount =
        showingFindings ? static_cast<int>(auditFindings.size())
                        : (showingBleDetails ? static_cast<int>(bleFindings.size()) : static_cast<int>(wifiFindings.size()));
    // Back closes the list. Select (Confirm) deep-scans the highlighted target.
    if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
      showingDetails = false;
      showingFindings = false;
      requestUpdate();
      return;
    }
    if (mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
      if (showingFindings) {
        // Jump to the related target's deep scan when the finding maps to one.
        if (itemCount > 0 && selectedFinding < itemCount) {
          const AuditFinding& f = auditFindings[selectedFinding];
          if (f.wifiIndex >= 0) {
            showingFindings = false;
            showingDetails = true;
            showingBleDetails = false;
            selectedFinding = f.wifiIndex;
            deepScanWifiTarget(f.wifiIndex);
            return;
          }
          if (f.bleIndex >= 0) {
            showingFindings = false;
            showingDetails = true;
            showingBleDetails = true;
            selectedFinding = f.bleIndex;
            deepScanBleTarget(f.bleIndex);
            return;
          }
        }
        showingFindings = false;
        requestUpdate();
        return;
      }
      if (itemCount > 0) {
        if (showingBleDetails) deepScanBleTarget(selectedFinding);
        else deepScanWifiTarget(selectedFinding);
      }
      return;
    }
    if (itemCount > 0) {
      buttonNavigator.onNext([this, itemCount] {
        selectedFinding = ButtonNavigator::nextIndex(selectedFinding, itemCount);
        requestUpdate();
      });
      buttonNavigator.onPrevious([this, itemCount] {
        selectedFinding = ButtonNavigator::previousIndex(selectedFinding, itemCount);
        requestUpdate();
      });
    }
    return;
  }

  if (currentCategory < 0) {
    // Top-level category list.
    if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
      onGoHome(HomeMenuItem::RADIO_AUDIT);
      return;
    }
    if (mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
      currentCategory = selectedCategory;
      selectedItem = 0;
      requestUpdate();
      return;
    }
    buttonNavigator.onNext([this] {
      selectedCategory = ButtonNavigator::nextIndex(selectedCategory, CATEGORY_COUNT);
      requestUpdate();
    });
    buttonNavigator.onPrevious([this] {
      selectedCategory = ButtonNavigator::previousIndex(selectedCategory, CATEGORY_COUNT);
      requestUpdate();
    });
    return;
  }

  // Inside a category: items run leaf actions; Back returns to the category list.
  const ActionCategory& cat = ACTION_CATEGORIES[currentCategory];
  if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
    currentCategory = -1;
    requestUpdate();
    return;
  }
  if (mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
    runAction(cat.items[selectedItem]);
    return;
  }
  buttonNavigator.onNext([this, &cat] {
    selectedItem = ButtonNavigator::nextIndex(selectedItem, cat.count);
    requestUpdate();
  });
  buttonNavigator.onPrevious([this, &cat] {
    selectedItem = ButtonNavigator::previousIndex(selectedItem, cat.count);
    requestUpdate();
  });
}

void RadioAuditActivity::runAction(int action) {
  switch (action) {
    case 0: startScan(false); return;
    case 1: startScan(true); return;
    case 2: showAuditFindings(); return;
    case 3: showWifiDetails(); return;
    case 4: showBleDetails(); return;
    case 5: exportText(); return;
    case 6: exportCsv(); return;
    case 7: exportJson(); return;
    case 8: startProbeScan(); return;
    case 9: showChannelUsage(); return;
    default: return;
  }
}

void RadioAuditActivity::startScan(bool deepScan) {
  deepScanMode = deepScan;
  scanTotalPasses = deepScan ? DEEP_SCAN_PASSES : QUICK_SCAN_PASSES;
  scanCurrentPass = 1;
  state = State::WIFI_SCANNING;
  wifiFindings.clear();
  bleFindings.clear();
  auditFindings.clear();
  startWifiScanPass();
}

void RadioAuditActivity::startWifiScanPass() {
  state = State::WIFI_SCANNING;
  status = (String(deepScanMode ? "Deep WiFi pass " : "Scanning WiFi ") + scanCurrentPass + "/" + scanTotalPasses)
               .c_str();
  requestUpdate();

  resetWifiForScan();
  delay(250);
  WiFi.mode(WIFI_STA);
  delay(100);
  WiFi.scanNetworks(true, true);
}

void RadioAuditActivity::processWifiScan() {
  const int16_t result = WiFi.scanComplete();
  if (result == WIFI_SCAN_RUNNING) return;

  if (result == WIFI_SCAN_FAILED) {
    status = "WiFi scan failed";
    state = State::ERROR;
    requestUpdate();
    return;
  }

  for (int i = 0; i < result; i++) {
    WifiFinding finding;
    finding.ssid = WiFi.SSID(i).c_str();
    finding.bssid = WiFi.BSSIDstr(i).c_str();
    finding.rssi = WiFi.RSSI(i);
    finding.rssiMin = finding.rssi;
    finding.rssiMax = finding.rssi;
    finding.rssiSum = finding.rssi;
    finding.channel = WiFi.channel(i);
    finding.seenCount = 1;
    finding.auth = authName(WiFi.encryptionType(i));
    finding.hidden = finding.ssid.empty();
    mergeWifiFinding(std::move(finding));
  }
  std::sort(wifiFindings.begin(), wifiFindings.end(),
            [](const WifiFinding& a, const WifiFinding& b) { return a.rssi > b.rssi; });
  WiFi.scanDelete();

  startBleScan();
}

void RadioAuditActivity::startBleScan() {
#if defined(RADIO_AUDIT_ENABLE_BLE)
  state = State::BLE_SCANNING;
  status = (String(deepScanMode ? "Deep BLE pass " : "Scanning BLE ") + scanCurrentPass + "/" + scanTotalPasses)
               .c_str();
  requestUpdateAndWait();

  // BLE is memory-hungry on the ESP32-C3. Turn off WiFi before starting the
  // controller to avoid coexistence pressure and crashes during scans.
  WiFi.scanDelete();
  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);
  delay(200);

  if (!bleReady) {
    BLEDevice::init("RadioInk");
    bleScan = BLEDevice::getScan();
    bleReady = true;
  }
  bleScan->setActiveScan(false);
  bleScan->setInterval(320);
  bleScan->setWindow(80);

  BLEScanResults* results = bleScan->start(2, false);
  const int count = results ? results->getCount() : 0;
  for (int i = 0; i < count; i++) {
    BLEAdvertisedDevice device = results->getDevice(i);
    BleFinding finding;
    finding.address = device.getAddress().toString().c_str();
    finding.name = device.haveName() ? device.getName().c_str() : "";
    finding.rssi = device.getRSSI();
    finding.rssiMin = finding.rssi;
    finding.rssiMax = finding.rssi;
    finding.rssiSum = finding.rssi;
    finding.seenCount = 1;
    finding.hasTxPower = device.haveTXPower();
    finding.txPower = finding.hasTxPower ? device.getTXPower() : 0;
    finding.manufacturerHex = device.haveManufacturerData() ? hexEncode(device.getManufacturerData()).c_str() : "";
    if (device.haveServiceData()) {
      finding.serviceDataUuid = device.getServiceDataUUID().toString().c_str();
      finding.serviceDataHex = hexEncode(device.getServiceData()).c_str();
    }
    mergeBleFinding(std::move(finding));
  }
  shutdownBleController();
#endif

  finishScanPass();
}

void RadioAuditActivity::shutdownBleController() {
#if defined(RADIO_AUDIT_ENABLE_BLE)
  if (bleScan) {
    bleScan->stop();
    bleScan->clearResults();
  }
  if (bleReady) {
    // Do not pass true here. Releasing controller memory can make the next
    // BLE init unsafe without reboot, which breaks Deep Scan pass 2.
    BLEDevice::deinit(false);
  }
  bleScan = nullptr;
  bleReady = false;
  delay(500);
#endif
}

void RadioAuditActivity::resetWifiForScan() {
  WiFi.scanDelete();
  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);
  delay(250);
}

void RadioAuditActivity::finishScanPass() {
  std::sort(wifiFindings.begin(), wifiFindings.end(),
            [](const WifiFinding& a, const WifiFinding& b) { return a.rssi > b.rssi; });
  std::sort(bleFindings.begin(), bleFindings.end(),
            [](const BleFinding& a, const BleFinding& b) { return a.rssi > b.rssi; });

  if (scanCurrentPass < scanTotalPasses) {
    scanCurrentPass++;
    resetWifiForScan();
    startWifiScanPass();
    return;
  }

  rebuildAuditFindings();
  scanTime = timeStamp();
  state = State::DONE;
  status = (String(deepScanMode ? "Deep scan complete, " : "Scan complete, ") + auditFindings.size() + " findings")
               .c_str();
  requestUpdate();
}

void RadioAuditActivity::mergeWifiFinding(WifiFinding&& finding) {
  for (auto& existing : wifiFindings) {
    if (existing.bssid == finding.bssid) {
      existing.rssi = averageRssi(existing.rssiSum + finding.rssi, existing.seenCount + 1);
      existing.rssiMin = std::min(existing.rssiMin, finding.rssi);
      existing.rssiMax = std::max(existing.rssiMax, finding.rssi);
      existing.rssiSum += finding.rssi;
      existing.seenCount++;
      if (existing.ssid.empty() && !finding.ssid.empty()) existing.ssid = finding.ssid;
      existing.auth = finding.auth;
      existing.channel = finding.channel;
      existing.hidden = existing.hidden && finding.hidden;
      return;
    }
  }

  if (wifiFindings.size() < MAX_WIFI_FINDINGS) {
    wifiFindings.push_back(std::move(finding));
    return;
  }

  auto weakest = std::min_element(wifiFindings.begin(), wifiFindings.end(),
                                  [](const WifiFinding& a, const WifiFinding& b) { return a.rssi < b.rssi; });
  if (weakest != wifiFindings.end() && finding.rssi > weakest->rssi) {
    *weakest = std::move(finding);
  }
}

void RadioAuditActivity::mergeBleFinding(BleFinding&& finding) {
  for (auto& existing : bleFindings) {
    if (existing.address == finding.address) {
      existing.rssi = averageRssi(existing.rssiSum + finding.rssi, existing.seenCount + 1);
      existing.rssiMin = std::min(existing.rssiMin, finding.rssi);
      existing.rssiMax = std::max(existing.rssiMax, finding.rssi);
      existing.rssiSum += finding.rssi;
      existing.seenCount++;
      if (existing.name.empty() && !finding.name.empty()) existing.name = finding.name;
      if (existing.manufacturerHex.empty() && !finding.manufacturerHex.empty()) {
        existing.manufacturerHex = finding.manufacturerHex;
      }
      if (existing.serviceDataHex.empty() && !finding.serviceDataHex.empty()) {
        existing.serviceDataUuid = finding.serviceDataUuid;
        existing.serviceDataHex = finding.serviceDataHex;
      }
      if (finding.hasTxPower) {
        existing.hasTxPower = true;
        existing.txPower = finding.txPower;
      }
      return;
    }
  }

  if (bleFindings.size() < MAX_BLE_FINDINGS) {
    bleFindings.push_back(std::move(finding));
    return;
  }

  auto weakest = std::min_element(bleFindings.begin(), bleFindings.end(),
                                  [](const BleFinding& a, const BleFinding& b) { return a.rssi < b.rssi; });
  if (weakest != bleFindings.end() && finding.rssi > weakest->rssi) {
    *weakest = std::move(finding);
  }
}

void RadioAuditActivity::exportText() {
  const String report = makeTextReport();
  const bool ok = saveFile(TEXT_EXPORT_PATH, report) && saveFile(makeTimestampedPath("txt").c_str(), report);
  state = State::SAVED;
  status = ok ? "Saved text report" : "Save failed";
  requestUpdate();
}

void RadioAuditActivity::exportCsv() {
  const String report = makeCsvReport();
  const bool ok = saveFile(CSV_EXPORT_PATH, report) && saveFile(makeTimestampedPath("csv").c_str(), report);
  state = State::SAVED;
  status = ok ? "Saved CSV report" : "Save failed";
  requestUpdate();
}

void RadioAuditActivity::exportJson() {
  const String report = makeJsonReport();
  const bool ok = saveFile(JSON_EXPORT_PATH, report) && saveFile(makeTimestampedPath("json").c_str(), report);
  state = State::SAVED;
  status = ok ? "Saved JSON report" : "Save failed";
  requestUpdate();
}

bool RadioAuditActivity::saveFile(const char* path, const String& content) {
  Storage.ensureDirectoryExists(AUDIT_DIR);
  if (!Storage.writeFile(path, content)) {
    LOG_ERR("RADIO", "Failed to save %s", path);
    state = State::ERROR;
    status = "Save failed";
    return false;
  }
  return true;
}

String RadioAuditActivity::makeTimestampedPath(const char* ext) const {
  return String(AUDIT_DIR) + "/scan-" + String(millis() / 1000) + "." + ext;
}

void RadioAuditActivity::addAuditFinding(const char* severity, const std::string& title, const std::string& detail,
                                         int wifiIndex, int bleIndex) {
  AuditFinding finding;
  finding.severity = severity;
  finding.title = title;
  finding.detail = detail;
  finding.wifiIndex = wifiIndex;
  finding.bleIndex = bleIndex;
  auditFindings.push_back(std::move(finding));
}

void RadioAuditActivity::rebuildAuditFindings() {
  auditFindings.clear();
  loadWatchlist();

  auto addFinding = [this](const char* severity, const std::string& title, const std::string& detail,
                           int wifiIndex = -1, int bleIndex = -1) {
    addAuditFinding(severity, title, detail, wifiIndex, bleIndex);
  };
  auto onWatchlist = [this](const std::string& mac) {
    const std::string up = upperStr(mac);
    for (const auto& entry : watchlist)
      if (!entry.empty() && up.find(entry) != std::string::npos) return true;
    return false;
  };

  int channelCounts[15] = {};
  for (size_t wi = 0; wi < wifiFindings.size(); wi++) {
    const auto& w = wifiFindings[wi];
    if (w.channel >= 1 && w.channel <= 14) channelCounts[w.channel]++;
    if (onWatchlist(w.bssid))
      addFinding("HIGH", "Watchlist hit",
                 (w.ssid.empty() ? w.bssid : w.ssid) + " (" + w.bssid + ") is on your watchlist.", wi);

    const std::string ssid = w.ssid.empty() ? std::string("<hidden>") : w.ssid;
    const std::string base = ssid + " " + w.bssid + " avg " + std::to_string(w.rssi) + " dBm CH" +
                             std::to_string(w.channel) + " seen " + std::to_string(w.seenCount) + "/" +
                             std::to_string(scanTotalPasses);
    if (w.auth == "OPEN") {
      addFinding("HIGH", "Open WiFi network", base + " has no encryption.", wi);
    } else if (w.auth == "WEP") {
      addFinding("HIGH", "WEP WiFi network", base + " uses broken legacy encryption.", wi);
    } else if (w.auth == "WPA") {
      addFinding("MED", "Legacy WPA network", base + " is not WPA2/WPA3.", wi);
    }

    if (w.hidden) {
      addFinding("LOW", "Hidden SSID observed", w.bssid + " is hiding its SSID but still appears in scans.", wi);
    }

    if (deepScanMode && w.seenCount < scanTotalPasses) {
      addFinding("INFO", "Intermittent WiFi AP", base + " was not visible in every scan pass.", wi);
    }
  }

  for (size_t i = 0; i < wifiFindings.size(); i++) {
    if (wifiFindings[i].ssid.empty()) continue;
    bool alreadyReported = false;
    for (size_t previous = 0; previous < i; previous++) {
      if (wifiFindings[previous].ssid == wifiFindings[i].ssid) {
        alreadyReported = true;
        break;
      }
    }
    if (alreadyReported) continue;
    int sameSsidCount = 1;
    for (size_t j = i + 1; j < wifiFindings.size(); j++) {
      if (wifiFindings[j].ssid == wifiFindings[i].ssid) sameSsidCount++;
    }
    if (sameSsidCount > 1) {
      addFinding("INFO", "Duplicate SSID", wifiFindings[i].ssid + " appears on " + std::to_string(sameSsidCount) +
                                             " BSSIDs.");
    }
  }

  for (int channel = 1; channel <= 14; channel++) {
    if (channelCounts[channel] >= 4) {
      addFinding("INFO", "Crowded WiFi channel",
                 "Channel " + std::to_string(channel) + " has " + std::to_string(channelCounts[channel]) +
                     " visible APs.");
    }
  }

  for (size_t bi = 0; bi < bleFindings.size(); bi++) {
    const auto& b = bleFindings[bi];
    const std::string label = b.name.empty() ? b.address : b.name + " " + b.address;
    const std::string advType = decodeBleAdvert(b.manufacturerHex, b.serviceDataUuid, b.serviceDataHex);
    if (onWatchlist(b.address))
      addFinding("HIGH", "Watchlist hit", label + " is on your watchlist.", -1, bi);
    if (b.rssi >= -55) {
      addFinding("MED", "Close BLE device",
                 label + " is nearby at avg " + std::to_string(b.rssi) + " dBm, seen " +
                     std::to_string(b.seenCount) + "/" + std::to_string(scanTotalPasses) + ".",
                 -1, bi);
    }
    if (advType.find("FindMy") != std::string::npos || advType.find("AirTag") != std::string::npos) {
      addFinding("MED", "Possible tracker", label + " advertises " + advType + " (AirTag/FindMy).", -1, bi);
    } else if (!advType.empty()) {
      addFinding("INFO", "BLE device identified", label + " looks like: " + advType + ".", -1, bi);
    } else if (!b.manufacturerHex.empty()) {
      addFinding("INFO", "BLE manufacturer data", label + " advertises manufacturer data.", -1, bi);
    }
    if (deepScanMode && b.seenCount < scanTotalPasses) {
      addFinding("INFO", "Intermittent BLE device", label + " was not visible in every scan pass.", -1, bi);
    }
  }

  // Compare against the previous scan and persist this one (adds NEW/GONE findings).
  diffAndSaveSnapshot();

  if (auditFindings.empty() && (!wifiFindings.empty() || !bleFindings.empty())) {
    addFinding("INFO", "No obvious findings", "Scan completed without open, weak, close, or crowded indicators.");
  }
}

void RadioAuditActivity::showAuditFindings() {
  if (auditFindings.empty()) {
    status = "No audit findings";
    requestUpdate();
    return;
  }
  showingFindings = true;
  showingDetails = false;
  selectedFinding = 0;
  requestUpdate();
}

void RadioAuditActivity::showWifiDetails() {
  if (wifiFindings.empty()) {
    status = "No WiFi results";
    requestUpdate();
    return;
  }
  showingDetails = true;
  showingFindings = false;
  showingBleDetails = false;
  selectedFinding = 0;
  requestUpdate();
}

void RadioAuditActivity::showBleDetails() {
  if (bleFindings.empty()) {
    status = "No BLE results";
    requestUpdate();
    return;
  }
  showingDetails = true;
  showingFindings = false;
  showingBleDetails = true;
  selectedFinding = 0;
  requestUpdate();
}

void RadioAuditActivity::deepScanWifiTarget(int index) {
  if (index < 0 || index >= static_cast<int>(wifiFindings.size())) return;
  const WifiFinding w = wifiFindings[index];  // copy: vector is rebuilt by scans
  targetTitle = std::string("AP ") + (w.ssid.empty() ? std::string("<hidden>") : w.ssid);
  targetLines.clear();
  targetScroll = 0;
  targetFromList = true;

  uint8_t bssid[6];
  if (!parseBssid(w.bssid, bssid)) {
    targetLines.push_back("Bad BSSID: " + w.bssid);
    status = "Deep scan failed";
    showingTarget = true;
    showingDetails = false;
    requestUpdate();
    return;
  }

  status = "Deep scanning AP...";
  requestUpdateAndWait();

  // Sniff this AP's channel in promiscuous mode for clients + posture.
  shutdownBleController();
  WiFi.scanDelete();
  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_STA);
  delay(150);

  memset(&g_targetCap, 0, sizeof(g_targetCap));
  memcpy(g_targetCap.bssid, bssid, 6);

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&targetPromiscuousCb);
  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(static_cast<uint8_t>(w.channel), WIFI_SECOND_CHAN_NONE);

  g_targetCap.active = true;
  delay(TARGET_WIFI_DEEP_MS);
  g_targetCap.active = false;
  esp_wifi_set_promiscuous(false);

  const int samples = g_targetCap.rssiSamples;
  const int avg = samples ? static_cast<int>(g_targetCap.rssiSum / static_cast<long>(samples)) : w.rssi;
  const int lo = samples ? g_targetCap.rssiMin : w.rssi;
  const int hi = samples ? g_targetCap.rssiMax : w.rssi;

  const std::string apVendor = macVendor(w.bssid);
  targetLines.push_back("Time: " + timeStamp());
  targetLines.push_back(w.bssid + "  CH" + std::to_string(w.channel) + "  " + w.auth);
  if (!apVendor.empty()) targetLines.push_back("Vendor: " + apVendor);
  targetLines.push_back("RSSI avg " + std::to_string(avg) + " (" + std::to_string(lo) + "/" + std::to_string(hi) +
                        ")  " + std::to_string(samples) + " frames");
  targetLines.push_back("Beacons " + std::to_string(g_targetCap.beaconCount) + "  Data " +
                        std::to_string(g_targetCap.dataFrames) + "  Mgmt " + std::to_string(g_targetCap.mgmtFrames));
  targetLines.push_back(std::string("Privacy ") + (g_targetCap.privacy ? "Y" : "N") + "  PMF " +
                        (g_targetCap.pmf ? "Y" : "N") + "  WPS " + (g_targetCap.wps ? "Y" : "N"));
  if (bssid[0] & 0x02) targetLines.push_back("Randomized BSSID");
  const int attackFrames = g_targetCap.deauthFrames + g_targetCap.disassocFrames;
  if (attackFrames > 0)
    targetLines.push_back("Deauth " + std::to_string(g_targetCap.deauthFrames) + "  Disassoc " +
                          std::to_string(g_targetCap.disassocFrames));
  targetLines.push_back("Clients: " + std::to_string(g_targetCap.clientCount));
  for (uint8_t i = 0; i < g_targetCap.clientCount; i++) {
    const std::string clientMac = macToString(g_targetCap.clients[i]);
    const std::string vendor = macVendor(clientMac);
    targetLines.push_back("  " + clientMac + (vendor.empty() ? "" : ("  " + vendor)));
  }

  // Raise deduplicated audit findings for this AP.
  auto pushFinding = [this, index](const char* severity, const std::string& title, const std::string& detail) {
    for (const auto& f : auditFindings)
      if (f.title == title && f.detail == detail) return;
    AuditFinding f;
    f.severity = severity;
    f.title = title;
    f.detail = detail;
    f.wifiIndex = index;
    auditFindings.push_back(std::move(f));
  };
  const std::string who = w.ssid.empty() ? w.bssid : w.ssid;
  if (g_targetCap.wps) pushFinding("MED", "WPS enabled", who + " exposes WPS (PIN brute-force risk).");
  if (g_targetCap.privacy && !g_targetCap.pmf)
    pushFinding("LOW", "No PMF", who + " lacks 802.11w management frame protection.");
  if (g_targetCap.clientCount > 0)
    pushFinding("INFO", "Active clients",
                who + " has " + std::to_string(g_targetCap.clientCount) + " associated client(s).");
  if (attackFrames >= 5)
    pushFinding("HIGH", "Possible deauth activity",
                who + " saw " + std::to_string(attackFrames) + " deauth/disassoc frames (possible attack/evil twin).");

  // Return the radio to the idle (off) state the activity expects.
  WiFi.scanDelete();
  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);
  delay(150);

  targetLocatable = true;
  targetLocBle = false;
  memcpy(targetLocBssid, bssid, 6);
  targetLocChannel = w.channel;
  targetLocName = targetTitle;

  status = std::string("Deep AP done, ") + std::to_string(g_targetCap.clientCount) + " clients";
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  requestUpdate();
}

void RadioAuditActivity::deepScanBleTarget(int index) {
  if (index < 0 || index >= static_cast<int>(bleFindings.size())) return;
  targetTitle = std::string("BLE ") +
                (bleFindings[index].name.empty() ? bleFindings[index].address : bleFindings[index].name);
  targetLines.clear();
  targetScroll = 0;
  targetFromList = true;

#if defined(RADIO_AUDIT_ENABLE_BLE)
  const std::string address = bleFindings[index].address;

  status = "Deep scanning device...";
  requestUpdateAndWait();

  WiFi.scanDelete();
  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);
  delay(200);  // let WiFi fully release before the BLE controller starts (C3 is memory-tight)

  if (!bleReady) {
    BLEDevice::init("RadioInk");
    bleScan = BLEDevice::getScan();
    bleReady = true;
  }
  if (!bleScan) {  // controller init failed - bail gracefully instead of crashing
    targetLines.push_back("BLE init failed - try again");
    status = "BLE init failed";
    showingTarget = true;
    showingDetails = false;
    showingFindings = false;
    requestUpdate();
    return;
  }
  // Passive scan + proven timing, matching the main scan path. Active scanning
  // here was triggering an out-of-memory abort() on the ESP32-C3.
  bleScan->setActiveScan(false);
  bleScan->setInterval(320);
  bleScan->setWindow(80);

  int rssiMin = 0, rssiMax = 0, samples = 0;
  long rssiSum = 0;
  std::string name, manufacturer, services, serviceDataUuid, serviceDataHex;
  bool hasTxPower = false;
  int txPower = 0;
  int addressType = -1;

  for (int pass = 0; pass < 3; pass++) {
    BLEScanResults* results = bleScan->start(2, false);
    const int count = results ? results->getCount() : 0;
    for (int i = 0; i < count; i++) {
      BLEAdvertisedDevice device = results->getDevice(i);
      if (std::string(device.getAddress().toString().c_str()) != address) continue;
      const int r = device.getRSSI();
      rssiSum += r;
      if (samples == 0) {
        rssiMin = r;
        rssiMax = r;
      } else {
        rssiMin = std::min(rssiMin, r);
        rssiMax = std::max(rssiMax, r);
      }
      samples++;
      if (name.empty() && device.haveName()) name = device.getName().c_str();
      if (manufacturer.empty() && device.haveManufacturerData())
        manufacturer = hexEncode(device.getManufacturerData()).c_str();
      if (services.empty() && device.haveServiceUUID()) services = device.getServiceUUID().toString().c_str();
      if (serviceDataHex.empty() && device.haveServiceData()) {
        serviceDataUuid = device.getServiceDataUUID().toString().c_str();
        serviceDataHex = hexEncode(device.getServiceData()).c_str();
      }
      if (device.haveTXPower()) {
        hasTxPower = true;
        txPower = device.getTXPower();
      }
      addressType = device.getAddressType();
    }
    bleScan->clearResults();
  }
  shutdownBleController();

  if (name.empty()) name = bleFindings[index].name;
  if (manufacturer.empty()) manufacturer = bleFindings[index].manufacturerHex;
  if (serviceDataUuid.empty()) serviceDataUuid = bleFindings[index].serviceDataUuid;
  if (serviceDataHex.empty()) serviceDataHex = bleFindings[index].serviceDataHex;
  const int avg = samples ? static_cast<int>(rssiSum / static_cast<long>(samples)) : bleFindings[index].rssi;
  const int lo = samples ? rssiMin : avg;
  const int hi = samples ? rssiMax : avg;
  const bool randomAddress = (addressType == 1 || addressType == 3);
  const std::string advType = decodeBleAdvert(manufacturer, serviceDataUuid, serviceDataHex);

  targetLines.push_back("Time: " + timeStamp());
  targetLines.push_back(address);
  targetLines.push_back("Name: " + (name.empty() ? std::string("<unnamed>") : name));
  if (!advType.empty()) targetLines.push_back("Type: " + advType);
  targetLines.push_back("Vendor: " + bleCompany(manufacturer));
  if (!randomAddress) {
    const std::string macVend = macVendor(address);
    if (!macVend.empty() && macVend != "randomized") targetLines.push_back("MAC vendor: " + macVend);
  }
  targetLines.push_back("RSSI avg " + std::to_string(avg) + " (" + std::to_string(lo) + "/" + std::to_string(hi) +
                        ")  seen " + std::to_string(samples) + "/3");
  if (hasTxPower) targetLines.push_back("TX power: " + std::to_string(txPower));
  if (!services.empty()) targetLines.push_back("Service: " + services);
  if (!manufacturer.empty()) targetLines.push_back("Mfr data: " + manufacturer);
  targetLines.push_back(std::string("Random address: ") + (randomAddress ? "Y" : "N"));

  targetLocatable = true;
  targetLocBle = true;
  targetLocAddr = address;
  targetLocName = targetTitle;

  status = "Deep device done";
#else
  targetLines.push_back("BLE support is disabled in this build.");
  status = "BLE disabled";
#endif

  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  requestUpdate();
}

void RadioAuditActivity::startProbeScan() {
  targetTitle = "Probe Requests";
  targetLines.clear();
  targetScroll = 0;
  targetFromList = false;  // launched from the main menu, returns there
  targetLocatable = false;

  status = "Harvesting probes...";
  requestUpdateAndWait();

  shutdownBleController();
  WiFi.scanDelete();
  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_STA);
  delay(150);

  memset(&g_probeCap, 0, sizeof(g_probeCap));

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&probePromiscuousCb);
  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous(true);

  g_probeCap.active = true;
  for (int channel = 1; channel <= 13; channel++) {
    esp_wifi_set_channel(static_cast<uint8_t>(channel), WIFI_SECOND_CHAN_NONE);
    delay(600);
  }
  g_probeCap.active = false;
  esp_wifi_set_promiscuous(false);

  const int count = g_probeCap.count;
  targetLines.push_back("Time: " + timeStamp());
  targetLines.push_back("Clients probing: " + std::to_string(count));
  for (int i = 0; i < count; i++) {
    const auto& row = g_probeCap.rows[i];
    const std::string ssid = row.ssid[0] ? std::string(row.ssid) : std::string("(broadcast)");
    const std::string mac = macToString(row.mac);
    const std::string vendor = macVendor(mac);
    targetLines.push_back(mac + (vendor.empty() ? "" : ("/" + vendor)) + "  " + ssid + "  " +
                          std::to_string(row.rssi) + " dBm");
  }

  WiFi.scanDelete();
  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);
  delay(150);

  status = std::string("Probe scan done, ") + std::to_string(count) + " seen";
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  requestUpdate();
}

void RadioAuditActivity::showChannelUsage() {
  if (wifiFindings.empty()) {
    status = "Run a WiFi scan first";
    requestUpdate();
    return;
  }
  int counts[15] = {};
  int strongest[15];
  for (int i = 0; i < 15; i++) strongest[i] = -127;
  for (const auto& w : wifiFindings) {
    if (w.channel >= 1 && w.channel <= 14) {
      counts[w.channel]++;
      if (w.rssi > strongest[w.channel]) strongest[w.channel] = w.rssi;
    }
  }
  int maxCount = 1;
  for (int ch = 1; ch <= 14; ch++)
    if (counts[ch] > maxCount) maxCount = counts[ch];

  targetTitle = "Channel Usage";
  targetLines.clear();
  targetScroll = 0;
  targetFromList = false;
  targetLocatable = false;
  for (int ch = 1; ch <= 14; ch++) {
    if (counts[ch] == 0) continue;
    int bars = counts[ch] * 12 / maxCount;
    if (bars < 1) bars = 1;
    char head[8];
    snprintf(head, sizeof(head), "CH%-2d ", ch);
    targetLines.push_back(std::string(head) + std::string(bars, '#') + " " + std::to_string(counts[ch]) + " (" +
                          std::to_string(strongest[ch]) + "dBm)");
  }
  status = "Channel usage";
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  requestUpdate();
}

void RadioAuditActivity::loadWatchlist() {
  watchlist.clear();
  if (!Storage.exists(WATCHLIST_PATH)) return;
  const String content = Storage.readFile(WATCHLIST_PATH);
  int start = 0;
  while (start < static_cast<int>(content.length())) {
    int nl = content.indexOf('\n', start);
    if (nl < 0) nl = content.length();
    String line = content.substring(start, nl);
    line.trim();
    line.toUpperCase();
    if (line.length() && line[0] != '#') watchlist.push_back(std::string(line.c_str()));
    start = nl + 1;
  }
}

void RadioAuditActivity::diffAndSaveSnapshot() {
  // Current device keys + human labels.
  std::vector<std::pair<std::string, std::string>> current;
  for (const auto& w : wifiFindings)
    current.emplace_back("W|" + upperStr(w.bssid), w.ssid.empty() ? w.bssid : w.ssid);
  for (const auto& b : bleFindings)
    current.emplace_back("B|" + upperStr(b.address), b.name.empty() ? b.address : b.name);

  std::vector<std::pair<std::string, std::string>> previous;
  const bool hadPrevious = Storage.exists(SNAPSHOT_PATH);
  if (hadPrevious) {
    const String content = Storage.readFile(SNAPSHOT_PATH);
    int start = 0;
    while (start < static_cast<int>(content.length())) {
      int nl = content.indexOf('\n', start);
      if (nl < 0) nl = content.length();
      const String line = content.substring(start, nl);
      const int tab = line.indexOf('\t');
      if (tab > 0) previous.emplace_back(line.substring(0, tab).c_str(), line.substring(tab + 1).c_str());
      start = nl + 1;
    }
  }

  auto contains = [](const std::vector<std::pair<std::string, std::string>>& v, const std::string& key) {
    for (const auto& e : v)
      if (e.first == key) return true;
    return false;
  };

  if (hadPrevious) {
    for (const auto& cur : current)
      if (!contains(previous, cur.first)) addAuditFinding("INFO", "New since last scan", cur.second + " appeared.");
    for (const auto& prev : previous)
      if (!contains(current, prev.first)) addAuditFinding("INFO", "Gone since last scan", prev.second + " disappeared.");
  }

  String out;
  for (const auto& cur : current) out += String(cur.first.c_str()) + "\t" + cur.second.c_str() + "\n";
  Storage.writeFile(SNAPSHOT_PATH, out);
}

void RadioAuditActivity::startLocator() {
  if (!targetLocatable) return;
  locating = true;
  showingTarget = false;
  locBestRssi = -127;
  locCurRssi = -127;
  locPrevRssi = -127;
  locHasSignal = false;
  locLastSampleMs = 0;

  if (!targetLocBle) {
    shutdownBleController();
    WiFi.scanDelete();
    WiFi.disconnect(false, false);
    WiFi.mode(WIFI_STA);
    delay(100);
    memset(&g_targetCap, 0, sizeof(g_targetCap));
    memcpy(g_targetCap.bssid, targetLocBssid, 6);
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(&targetPromiscuousCb);
    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(static_cast<uint8_t>(targetLocChannel), WIFI_SECOND_CHAN_NONE);
    g_targetCap.active = true;
  } else {
#if defined(RADIO_AUDIT_ENABLE_BLE)
    WiFi.scanDelete();
    WiFi.disconnect(false, false);
    WiFi.mode(WIFI_OFF);
    delay(200);
    if (!bleReady) {
      BLEDevice::init("RadioInk");
      bleScan = BLEDevice::getScan();
      bleReady = true;
    }
    if (!bleScan) {  // controller init failed - don't enter the locator
      locating = false;
      status = "BLE init failed";
      showingTarget = true;
      requestUpdate();
      return;
    }
    bleScan->setActiveScan(false);
    bleScan->setInterval(320);
    bleScan->setWindow(80);
#endif
  }
  status = "Locating...";
  requestUpdate();
}

void RadioAuditActivity::stopLocator() {
  locating = false;
  if (!targetLocBle) {
    g_targetCap.active = false;
    esp_wifi_set_promiscuous(false);
    WiFi.scanDelete();
    WiFi.disconnect(false, false);
    WiFi.mode(WIFI_OFF);
    delay(50);
  } else {
    shutdownBleController();
  }
}

void RadioAuditActivity::locatorSample() {
  if (!targetLocBle) {
    if (g_targetCap.rssiSamples > 0) {
      locCurRssi = static_cast<int>(g_targetCap.rssiSum / static_cast<long>(g_targetCap.rssiSamples));
      locHasSignal = true;
    } else {
      locHasSignal = false;
    }
    g_targetCap.rssiSum = 0;
    g_targetCap.rssiSamples = 0;
  } else {
#if defined(RADIO_AUDIT_ENABLE_BLE)
    BLEScanResults* results = bleScan->start(1, false);
    const int count = results ? results->getCount() : 0;
    bool seen = false;
    for (int i = 0; i < count; i++) {
      BLEAdvertisedDevice device = results->getDevice(i);
      if (std::string(device.getAddress().toString().c_str()) == targetLocAddr) {
        locCurRssi = device.getRSSI();
        seen = true;
        break;
      }
    }
    bleScan->clearResults();
    locHasSignal = seen;
#endif
  }
  if (locHasSignal && locCurRssi > locBestRssi) locBestRssi = locCurRssi;
}

void RadioAuditActivity::renderLocator() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  const auto pageHeight = renderer.getScreenHeight();
  renderer.clearScreen();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;
  const int summaryX = metrics.contentSidePadding;

  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight},
                 ("Locate: " + targetLocName).c_str(), status.c_str());

  int y = contentTop;
  if (!locHasSignal) {
    renderer.drawText(UI_12_FONT_ID, summaryX, y, "-- no signal --", true, EpdFontFamily::BOLD);
  } else {
    // Map RSSI [-100..-30] -> 0..30 bar segments.
    int level = (locCurRssi + 100) * 30 / 70;
    if (level < 0) level = 0;
    if (level > 30) level = 30;
    renderer.drawText(UI_12_FONT_ID, summaryX, y, (String("RSSI: ") + locCurRssi + " dBm").c_str(), true,
                      EpdFontFamily::BOLD);
    y += renderer.getLineHeight(UI_12_FONT_ID) + 8;
    const std::string bar = "[" + std::string(level, '#') + std::string(30 - level, '.') + "]";
    renderer.drawText(UI_12_FONT_ID, summaryX, y, bar.c_str(), true, EpdFontFamily::BOLD);
    y += renderer.getLineHeight(UI_12_FONT_ID) + 8;
    renderer.drawText(SMALL_FONT_ID, summaryX, y, (String("Best (closest): ") + locBestRssi + " dBm").c_str());
    y += renderer.getLineHeight(SMALL_FONT_ID) + 8;
    const char* trend = "= holding";
    if (locPrevRssi > -127) {
      if (locCurRssi - locPrevRssi >= 2) trend = "^^ WARMER (closer)";
      else if (locPrevRssi - locCurRssi >= 2) trend = "vv colder (farther)";
    }
    renderer.drawText(UI_12_FONT_ID, summaryX, y, trend, true, EpdFontFamily::BOLD);
  }

  const auto labels = mappedInput.mapLabels("Back", "Back", "", "");
  UITheme::getInstance().suppressBrandLogoOnce();  // log view: no brand logo
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}

String RadioAuditActivity::makeTextReport() const {
  String out;
  out += "RADIO INK REPORT\n";
  out += "================\n";
  out += "Time: ";
  out += (scanTime.empty() ? "n/a" : scanTime.c_str());
  out += "\nMode: ";
  out += scanModeName();
  out += "\nPasses: ";
  out += scanTotalPasses;
  out += "\n";
  out += makeRiskSummary();
  out += "\n";
  out += "WiFi APs: ";
  out += wifiFindings.size();
  out += "\nBLE dev: ";
  out += bleFindings.size();
  out += "\nFindings: ";
  out += auditFindings.size();
  out += "\n\nAUDIT FINDINGS\n--------------\n";
  for (size_t i = 0; i < auditFindings.size(); i++) {
    const auto& f = auditFindings[i];
    out += String(i + 1) + ". [" + f.severity.c_str() + "] " + f.title.c_str() + "\n";
    out += String("   ") + f.detail.c_str() + "\n";
  }
  out += "\nWIFI\n----\n";
  for (size_t i = 0; i < wifiFindings.size(); i++) {
    const auto& w = wifiFindings[i];
    out += String(i + 1) + ". " + (w.ssid.empty() ? "<hidden>" : w.ssid.c_str()) + "\n";
    out += String("   ") + w.bssid.c_str() + " CH" + w.channel + " seen " + w.seenCount + "/" + scanTotalPasses +
           "\n";
    out += String("   avg ") + w.rssi + " dBm min " + w.rssiMin + " max " + w.rssiMax + " " + w.auth.c_str() +
           "\n";
  }
  out += "\nBLE\n---\n";
  for (size_t i = 0; i < bleFindings.size(); i++) {
    const auto& b = bleFindings[i];
    out += String(i + 1) + ". " + b.address.c_str() + "\n";
    out += String("   ") + (b.name.empty() ? "<unnamed>" : b.name.c_str()) + "\n";
    out += String("   avg ") + b.rssi + " dBm min " + b.rssiMin + " max " + b.rssiMax + " seen " + b.seenCount +
           "/" + scanTotalPasses;
    if (b.hasTxPower) out += String(" TX ") + b.txPower;
    out += "\n";
  }
  return out;
}

String RadioAuditActivity::makeCsvReport() const {
  String out =
      "type,index,severity,title,detail,ssid,bssid,address,rssi,rssi_min,rssi_max,seen_count,pass_count,channel,auth,"
      "name,tx_power,manufacturer\n";
  for (size_t i = 0; i < auditFindings.size(); i++) {
    const auto& f = auditFindings[i];
    out += String("finding,") + (i + 1) + "," + csvEscape(f.severity) + "," + csvEscape(f.title) + "," +
           csvEscape(f.detail) + ",,,,,,,,,,,,,\n";
  }
  for (size_t i = 0; i < wifiFindings.size(); i++) {
    const auto& w = wifiFindings[i];
    out += String("wifi,") + (i + 1) + ",,,," + csvEscape(w.ssid) + "," + csvEscape(w.bssid) + ",,";
    out += String(w.rssi) + "," + w.rssiMin + "," + w.rssiMax + "," + w.seenCount + "," + scanTotalPasses + ",";
    out += String(w.channel) + "," + csvEscape(w.auth) + ",,,\n";
  }
  for (size_t i = 0; i < bleFindings.size(); i++) {
    const auto& b = bleFindings[i];
    out += String("ble,") + (i + 1) + ",,,,,,," + csvEscape(b.address) + ",";
    out += String(b.rssi) + "," + b.rssiMin + "," + b.rssiMax + "," + b.seenCount + "," + scanTotalPasses + ",,,";
    out += csvEscape(b.name) + ",";
    out += (b.hasTxPower ? String(b.txPower) : String("")) + "," + csvEscape(b.manufacturerHex) + "\n";
  }
  return out;
}

String RadioAuditActivity::makeJsonReport() const {
  String out;
  out += "{\n";
  out += "  \"tool\": \"Radio Ink\",\n";
  out += "  \"scan_time\": ";
  out += jsonEscape(scanTime.empty() ? "n/a" : scanTime.c_str());
  out += ",\n";
  out += "  \"scan_mode\": ";
  out += jsonEscape(scanModeName().c_str());
  out += ",\n";
  out += "  \"scan_passes\": ";
  out += scanTotalPasses;
  out += ",\n";
  out += "  \"uptime_seconds\": ";
  out += millis() / 1000;
  out += ",\n";
  out += "  \"summary\": {\n";
  out += "    \"wifi_count\": ";
  out += wifiFindings.size();
  out += ",\n";
  out += "    \"ble_count\": ";
  out += bleFindings.size();
  out += ",\n";
  out += "    \"findings_count\": ";
  out += auditFindings.size();
  out += ",\n";
  out += "    \"risk\": ";
  out += jsonEscape(makeRiskSummary().c_str());
  out += "\n";
  out += "  },\n";
  out += "  \"findings\": [\n";
  for (size_t i = 0; i < auditFindings.size(); i++) {
    const auto& f = auditFindings[i];
    out += "    {\"index\": ";
    out += i + 1;
    out += ", \"severity\": ";
    out += jsonEscape(f.severity);
    out += ", \"title\": ";
    out += jsonEscape(f.title);
    out += ", \"detail\": ";
    out += jsonEscape(f.detail);
    out += "}";
    if (i + 1 < auditFindings.size()) out += ",";
    out += "\n";
  }
  out += "  ],\n";
  out += "  \"wifi\": [\n";
  for (size_t i = 0; i < wifiFindings.size(); i++) {
    const auto& w = wifiFindings[i];
    out += "    {\"index\": ";
    out += i + 1;
    out += ", \"ssid\": ";
    out += jsonEscape(w.ssid);
    out += ", \"bssid\": ";
    out += jsonEscape(w.bssid);
    out += ", \"rssi\": ";
    out += w.rssi;
    out += ", \"rssi_min\": ";
    out += w.rssiMin;
    out += ", \"rssi_max\": ";
    out += w.rssiMax;
    out += ", \"seen_count\": ";
    out += w.seenCount;
    out += ", \"channel\": ";
    out += w.channel;
    out += ", \"auth\": ";
    out += jsonEscape(w.auth);
    out += ", \"hidden\": ";
    out += w.hidden ? "true" : "false";
    out += "}";
    if (i + 1 < wifiFindings.size()) out += ",";
    out += "\n";
  }
  out += "  ],\n";
  out += "  \"ble\": [\n";
  for (size_t i = 0; i < bleFindings.size(); i++) {
    const auto& b = bleFindings[i];
    out += "    {\"index\": ";
    out += i + 1;
    out += ", \"address\": ";
    out += jsonEscape(b.address);
    out += ", \"name\": ";
    out += jsonEscape(b.name);
    out += ", \"rssi\": ";
    out += b.rssi;
    out += ", \"rssi_min\": ";
    out += b.rssiMin;
    out += ", \"rssi_max\": ";
    out += b.rssiMax;
    out += ", \"seen_count\": ";
    out += b.seenCount;
    out += ", \"tx_power\": ";
    if (b.hasTxPower) {
      out += b.txPower;
    } else {
      out += "null";
    }
    out += ", \"manufacturer\": ";
    out += jsonEscape(b.manufacturerHex);
    out += "}";
    if (i + 1 < bleFindings.size()) out += ",";
    out += "\n";
  }
  out += "  ]\n";
  out += "}\n";
  return out;
}

String RadioAuditActivity::makeRiskSummary() const {
  int openOrWep = 0;
  int weakWifi = 0;
  int hiddenWifi = 0;
  int closeBle = 0;

  for (const auto& w : wifiFindings) {
    if (w.auth == "OPEN" || w.auth == "WEP") openOrWep++;
    if (w.auth == "WEP" || w.auth == "WPA") weakWifi++;
    if (w.hidden) hiddenWifi++;
  }

  for (const auto& b : bleFindings) {
    if (b.rssi >= -55) closeBle++;
  }

  if (wifiFindings.empty() && bleFindings.empty()) {
    return "Risk: no scan data yet\n";
  }

  String out = "Risk: ";
  out += openOrWep;
  out += " open/WEP, ";
  out += weakWifi;
  out += " weak WPA, ";
  out += hiddenWifi;
  out += " hidden, ";
  out += closeBle;
  out += " close BLE\n";
  return out;
}

String RadioAuditActivity::scanModeName() const { return deepScanMode ? "deep" : "quick"; }

std::string RadioAuditActivity::authName(wifi_auth_mode_t auth) {
  switch (auth) {
    case WIFI_AUTH_OPEN:
      return "OPEN";
    case WIFI_AUTH_WEP:
      return "WEP";
    case WIFI_AUTH_WPA_PSK:
      return "WPA";
    case WIFI_AUTH_WPA2_PSK:
      return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:
      return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE:
      return "WPA2-EAP";
    case WIFI_AUTH_WPA3_PSK:
      return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK:
      return "WPA2/WPA3";
    default:
      return "UNKNOWN";
  }
}

String RadioAuditActivity::csvEscape(const std::string& value) {
  String out = "\"";
  for (char c : value) {
    if (c == '"') out += '"';
    out += c;
  }
  out += "\"";
  return out;
}

int RadioAuditActivity::averageRssi(int rssiSum, int seenCount) {
  if (seenCount <= 0) return 0;
  return rssiSum / seenCount;
}

String RadioAuditActivity::jsonEscape(const std::string& value) {
  String out = "\"";
  for (char c : value) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (static_cast<uint8_t>(c) < 0x20) {
          out += " ";
        } else {
          out += c;
        }
        break;
    }
  }
  out += "\"";
  return out;
}

void RadioAuditActivity::render(RenderLock&&) {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  const auto pageHeight = renderer.getScreenHeight();
  renderer.clearScreen();

  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;
  const int summaryX = metrics.contentSidePadding;

  if (locating) {
    renderLocator();
    return;
  }

  if (showingTarget) {
    const int itemCount = static_cast<int>(targetLines.size());
    GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight},
                   targetTitle.c_str(), status.c_str());

    if (itemCount == 0) {
      const auto height = renderer.getLineHeight(UI_10_FONT_ID);
      const auto top = contentTop + (pageHeight - contentTop - metrics.buttonHintsHeight - height) / 2;
      UITheme::drawCenteredText(renderer, Rect{0, contentTop, pageWidth, pageHeight - contentTop}, UI_10_FONT_ID, top,
                                "No data");
    } else {
      const int listHeight = pageHeight - contentTop - metrics.buttonHintsHeight - metrics.verticalSpacing;
      GUI.drawList(
          renderer, Rect{0, contentTop, pageWidth, listHeight}, itemCount, targetScroll,
          [this](int index) { return targetLines[index]; }, nullptr, nullptr,
          [this](int index) { return std::to_string(index + 1) + "/" + std::to_string(targetLines.size()); });
    }

    const auto labels = mappedInput.mapLabels("Back", targetLocatable ? "Locate" : "Back", "Up", "Down");
    UITheme::getInstance().suppressBrandLogoOnce();  // log view: no brand logo
    GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
    renderer.displayBuffer();
    return;
  }

  if (showingDetails || showingFindings) {
    const bool bleMode = showingBleDetails;
    const int itemCount =
        showingFindings ? static_cast<int>(auditFindings.size())
                        : (bleMode ? static_cast<int>(bleFindings.size()) : static_cast<int>(wifiFindings.size()));
    GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight},
                   showingFindings ? "Audit Findings" : (bleMode ? "BLE Results" : "WiFi Results"), status.c_str());

    if (itemCount == 0) {
      const auto height = renderer.getLineHeight(UI_10_FONT_ID);
      const auto top = contentTop + (pageHeight - contentTop - metrics.buttonHintsHeight - height) / 2;
      UITheme::drawCenteredText(renderer, Rect{0, contentTop, pageWidth, pageHeight - contentTop}, UI_10_FONT_ID, top,
                                "No results");
    } else {
      const int listHeight = pageHeight - contentTop - metrics.buttonHintsHeight - metrics.verticalSpacing;
      GUI.drawList(
          renderer, Rect{0, contentTop, pageWidth, listHeight}, itemCount, selectedFinding,
          [this, bleMode](int index) {
            if (showingFindings) {
              const auto& f = auditFindings[index];
              return f.severity + "  " + f.title;
            }
            if (bleMode) {
              const auto& b = bleFindings[index];
              if (!b.name.empty()) return b.name;
              return b.address;
            }
            const auto& w = wifiFindings[index];
            return w.ssid.empty() ? std::string("<hidden>") : w.ssid;
          },
          [this, bleMode](int index) {
            if (showingFindings) {
              return auditFindings[index].detail;
            }
            if (bleMode) {
              const auto& b = bleFindings[index];
              const std::string advType = decodeBleAdvert(b.manufacturerHex, b.serviceDataUuid, b.serviceDataHex);
              std::string out = advType.empty() ? b.address : (advType + "  " + std::to_string(b.rssi) + " dBm");
              if (advType.empty()) out += "  " + std::to_string(b.rssi) + " dBm";
              if (b.seenCount > 1 || deepScanMode) {
                out += "  seen " + std::to_string(b.seenCount) + "/" + std::to_string(scanTotalPasses);
              }
              if (b.hasTxPower) out += " TX " + std::to_string(b.txPower);
              return out;
            }
            const auto& w = wifiFindings[index];
            std::string out = w.bssid + "  " + std::to_string(w.rssi) + " dBm  CH" + std::to_string(w.channel) +
                              "  " + w.auth;
            if (w.seenCount > 1 || deepScanMode) {
              out += "  seen " + std::to_string(w.seenCount) + "/" + std::to_string(scanTotalPasses);
            }
            return out;
          },
          nullptr,
          [this, bleMode](int index) {
            if (showingFindings) return std::to_string(index + 1) + "/" + std::to_string(auditFindings.size());
            if (bleMode) return std::to_string(index + 1) + "/" + std::to_string(bleFindings.size());
            return std::to_string(index + 1) + "/" + std::to_string(wifiFindings.size());
          });
    }

    const bool findingHasTarget =
        showingFindings && selectedFinding < static_cast<int>(auditFindings.size()) &&
        (auditFindings[selectedFinding].wifiIndex >= 0 || auditFindings[selectedFinding].bleIndex >= 0);
    const char* selectLabel = showingFindings ? (findingHasTarget ? "Deep Scan" : "Close") : "Deep Scan";
    const auto labels = mappedInput.mapLabels("Back", selectLabel, "Up", "Down");
    UITheme::getInstance().suppressBrandLogoOnce();  // log view: no brand logo
    GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
    renderer.displayBuffer();
    return;
  }

  const String headerTitle = currentCategory < 0
                                 ? String("Radio Ink ") + RADIO_INK_VERSION
                                 : String("Radio Ink  \xC2\xBB  ") + ACTION_CATEGORIES[currentCategory].name;
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, headerTitle.c_str(),
                 status.c_str());

  int y = contentTop;
  // Sub-header counts strip.
  renderer.drawText(UI_12_FONT_ID, summaryX, y,
                    (String("APs ") + wifiFindings.size() + "   BLE " + bleFindings.size() + "   Findings " +
                     auditFindings.size())
                        .c_str(),
                    true, EpdFontFamily::BOLD);
  y += renderer.getLineHeight(UI_12_FONT_ID) + 8;
  renderer.drawText(SMALL_FONT_ID, summaryX, y,
                    (String("Mode: ") + (deepScanMode ? "Deep" : "Quick") + "  Passes: " + scanTotalPasses).c_str());
  y += renderer.getLineHeight(SMALL_FONT_ID) + 6;
  if (!scanTime.empty()) {
    renderer.drawText(SMALL_FONT_ID, summaryX, y, (String("Last scan: ") + scanTime.c_str()).c_str());
    y += renderer.getLineHeight(SMALL_FONT_ID) + 6;
  }
  const String risk = makeRiskSummary();
  renderer.drawText(SMALL_FONT_ID, summaryX, y,
                    renderer.truncatedText(SMALL_FONT_ID, risk.c_str(), pageWidth - summaryX * 2).c_str());
  y += renderer.getLineHeight(SMALL_FONT_ID) + 6;

  if (!wifiFindings.empty()) {
    const auto& w = wifiFindings[0];
    const String strongest = String("Strongest: ") + (w.ssid.empty() ? "<hidden>" : w.ssid.c_str());
    renderer.drawText(SMALL_FONT_ID, summaryX, y,
                      renderer.truncatedText(SMALL_FONT_ID, strongest.c_str(), pageWidth - summaryX * 2).c_str());
    y += renderer.getLineHeight(SMALL_FONT_ID) + 4;
    const String details = String("avg ") + w.rssi + " dBm, CH" + w.channel + ", " + w.auth.c_str() + ", seen " +
                           w.seenCount + "/" + scanTotalPasses;
    renderer.drawText(SMALL_FONT_ID, summaryX, y, details.c_str());
  }

  constexpr int visibleActionRows = 4;
  const int listHeight = metrics.menuRowHeight * visibleActionRows;
  const int listTop = pageHeight - metrics.buttonHintsHeight - metrics.verticalSpacing - listHeight;
  // List reserves a gutter on the right for the skull mark.
  const int listWidth = pageWidth - RADIOINK_SKULL_WIDTH - summaryX;
  const Rect listRect{0, listTop, listWidth, listHeight};
  if (currentCategory < 0) {
    // Top-level category list.
    GUI.drawList(renderer, listRect, CATEGORY_COUNT, selectedCategory,
                 [](int index) { return std::string(ACTION_CATEGORIES[index].name); }, nullptr,
                 [](int index) { return index == 2 ? UIIcon::File : UIIcon::Wifi; });
  } else {
    // Items within the selected category.
    const ActionCategory& cat = ACTION_CATEGORIES[currentCategory];
    GUI.drawList(renderer, listRect, cat.count, selectedItem,
                 [&cat](int index) { return std::string(ACTION_LABELS[cat.items[index]]); }, nullptr,
                 [&cat](int index) { return cat.items[index] >= 5 && cat.items[index] <= 7 ? UIIcon::File : UIIcon::Wifi; });
  }

  // The list reserves a right gutter (listWidth) for the skull mark, which the
  // Radio Ink theme stamps in drawButtonHints — no logo suppression here.
  const char* backLabel = currentCategory < 0 ? "Home" : "Back";
  const auto labels = mappedInput.mapLabels(backLabel, "Select", "Up", "Down");
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}
