#include "RadioAuditHelpers.h"

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// Pure, stateless helpers extracted from RadioAuditActivity.cpp: MAC/hex/OUI
// utilities, the BLE advertising decoder, and camera/tracker fingerprinting.
// No hardware or global capture state.
namespace ra {

// ---- MAC / hex utilities ----
bool macEq(const uint8_t* a, const uint8_t* b) {
  for (int i = 0; i < 6; i++)
    if (a[i] != b[i]) return false;
  return true;
}

// Group bit set => broadcast/multicast, not an individual station.
bool macIsGroup(const uint8_t* m) { return (m[0] & 0x01) != 0; }

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

std::string bytesToHex(const uint8_t* b, int n) {
  static const char hex[] = "0123456789abcdef";
  std::string s;
  s.reserve(n * 2);
  for (int i = 0; i < n; i++) {
    s += hex[(b[i] >> 4) & 0x0F];
    s += hex[b[i] & 0x0F];
  }
  return s;
}
std::string strToHex(const char* s) { return bytesToHex(reinterpret_cast<const uint8_t*>(s), strlen(s)); }

std::string humanSize(uint32_t bytes) {
  char buf[24];
  if (bytes < 1024) snprintf(buf, sizeof(buf), "%u B", bytes);
  else if (bytes < 1024u * 1024u) snprintf(buf, sizeof(buf), "%.1f KB", bytes / 1024.0);
  else snprintf(buf, sizeof(buf), "%.1f MB", bytes / (1024.0 * 1024.0));
  return buf;
}

// BLE company identifier (first 2 bytes of manufacturer data) -> vendor name.
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
    case 0x0171: return "Amazon";
    default: {
      char b[12];
      snprintf(b, sizeof(b), "0x%04X", id);
      return std::string(b);
    }
  }
}

std::string upperStr(std::string s) {
  for (auto& c : s) c = static_cast<char>(toupper(static_cast<unsigned char>(c)));
  return s;
}

std::string lowerStr(std::string s) {
  for (auto& c : s) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
  return s;
}

std::string cameraFingerprintReason(const std::string& label, const std::string& vendor) {
  const std::string haystack = lowerStr(label + " " + vendor);
  struct CameraToken {
    const char* token;
    const char* reason;
  };
  static constexpr CameraToken tokens[] = {
      {"camera", "name contains camera"},
      {"ipcam", "name contains ipcam"},
      {"ip cam", "name contains ip cam"},
      {"cctv", "name contains cctv"},
      {"nvr", "name contains nvr"},
      {"dvr", "name contains dvr"},
      {"doorbell", "name contains doorbell"},
      {"video doorbell", "video doorbell fingerprint"},
      {"webcam", "name contains webcam"},
      {"stick up cam", "Ring camera product fingerprint"},
      {"spotlight cam", "Ring camera product fingerprint"},
      {"floodlight cam", "Ring camera product fingerprint"},
      {"ring setup", "Ring setup fingerprint"},
      {"ring doorbell", "Ring doorbell fingerprint"},
      {"ring cam", "Ring camera fingerprint"},
      {"ring camera", "Ring camera fingerprint"},
      {"ring-", "Ring setup/device fingerprint"},
      {"ring_", "Ring setup/device fingerprint"},
      {"blink setup", "Blink setup fingerprint"},
      {"blink sync", "Blink Sync Module fingerprint"},
      {"sync module", "camera sync-module fingerprint"},
      {"blink camera", "Blink camera fingerprint"},
      {"blink-", "Blink setup/device fingerprint"},
      {"blink_", "Blink setup/device fingerprint"},
      {"immedia", "Blink/Immedia fingerprint"},
      {"hikvision", "Hikvision fingerprint"},
      {"dahua", "Dahua fingerprint"},
      {"axis", "Axis camera fingerprint"},
      {"reolink", "Reolink fingerprint"},
      {"amcrest", "Amcrest fingerprint"},
      {"foscam", "Foscam fingerprint"},
      {"lorex", "Lorex fingerprint"},
      {"ezviz", "EZVIZ fingerprint"},
      {"arlo", "Arlo fingerprint"},
      {"wyze", "Wyze fingerprint"},
      {"eufycam", "EufyCam fingerprint"},
      {"eufy cam", "EufyCam fingerprint"},
      {"tapo cam", "TP-Link Tapo camera fingerprint"},
      {"kasa cam", "TP-Link Kasa camera fingerprint"},
      {"unifi protect", "UniFi Protect fingerprint"},
      {"unifi video", "UniFi Video fingerprint"},
      {"gopro", "action-camera fingerprint"},
  };
  for (const auto& token : tokens)
    if (haystack.find(token.token) != std::string::npos) return token.reason;
  return "";
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
    // Camera/NVR vendors
    {0x00408C, "Axis"}, {0x4419B6, "Hikvision"}, {0xBCAD28, "Hikvision"}, {0x3CE36B, "Dahua"},
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
// Camera likelihood from a MAC/BLE vendor name (covers client stations whose
// name we can't see). Amazon = Ring/Blink (Amazon-owned); plus IP-cam makers.
std::string cameraVendorReason(const std::string& vendor) {
  const std::string v = lowerStr(vendor);
  if (v.empty()) return "";
  if (v == "amazon") return "Amazon device - possible Ring/Blink";
  if (v == "hikvision" || v == "dahua" || v == "axis") return vendor + " (camera vendor)";
  return "";
}

// Classify a BLE advert as a known item tracker (AirTag/Tile/SmartTag/etc.).
std::string trackerReason(const std::string& manufacturerHex, const std::string& svcUuid,
                          const std::string& svcDataHex, const std::string& name) {
  const std::string adv = decodeBleAdvert(manufacturerHex, svcUuid, svcDataHex);
  if (adv.find("FindMy") != std::string::npos || adv.find("AirTag") != std::string::npos)
    return "Apple FindMy / AirTag";
  const std::string uuid = upperStr(svcUuid);
  if (uuid.find("FEED") != std::string::npos || uuid.find("FEEC") != std::string::npos) return "Tile tracker";
  if (uuid.find("FD5A") != std::string::npos) return "Samsung SmartTag";
  const std::string n = lowerStr(name);
  if (n.find("tile") != std::string::npos) return "Tile tracker";
  if (n.find("smarttag") != std::string::npos || n.find("smart tag") != std::string::npos) return "Samsung SmartTag";
  if (n.find("chipolo") != std::string::npos) return "Chipolo tracker";
  if (n.find("airtag") != std::string::npos) return "Apple AirTag";
  return "";
}

}  // namespace ra
