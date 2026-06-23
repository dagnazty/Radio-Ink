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
      // Flock Safety ALPR / surveillance fingerprints (SSID names seen in the field).
      {"flock", "Flock Safety camera fingerprint"},
      {"flocksafety", "Flock Safety camera fingerprint"},
      {"flock safety", "Flock Safety camera fingerprint"},
      {"fs ext battery", "Flock Safety external battery fingerprint"},
      {"pigvision", "Flock Safety (Pigvision) fingerprint"},
      {"penguin", "Flock Safety (Penguin) fingerprint"},
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

// Camera vendor from the MAC OUI (first 3 octets). Catches cameras whose SSID is
// hidden or renamed -- especially Flock Safety, whose registered OUIs are listed
// here (ported from the C5-Midnight / sticks_and_stones Flock detectors). Returns
// a reason string, or "" if the OUI isn't a known dedicated-camera prefix.
std::string cameraMacReason(const std::string& mac) {
  unsigned int b0, b1, b2;
  if (sscanf(mac.c_str(), "%x:%x:%x", &b0, &b1, &b2) != 3) return "";
  const uint32_t oui = (b0 << 16) | (b1 << 8) | b2;
  struct OuiCam {
    uint32_t oui;
    const char* reason;
  };
  static constexpr OuiCam table[] = {
      // Flock Safety ALPR / surveillance registered OUIs.
      {0x588E81, "Flock Safety OUI"}, {0xEC1BBD, "Flock Safety OUI"}, {0x9035EA, "Flock Safety OUI"},
      {0x040D84, "Flock Safety OUI"}, {0xF082C0, "Flock Safety OUI"}, {0x1C34F1, "Flock Safety OUI"},
      {0x385B44, "Flock Safety OUI"}, {0x943469, "Flock Safety OUI"}, {0xB4E3F9, "Flock Safety OUI"},
      {0x70C94E, "Flock Safety OUI"}, {0x3C9180, "Flock Safety OUI"}, {0xD8F3BC, "Flock Safety OUI"},
      {0x803049, "Flock Safety OUI"}, {0x145AFC, "Flock Safety OUI"}, {0x744CA1, "Flock Safety OUI"},
      {0x083A88, "Flock Safety OUI"}, {0x9C2F9D, "Flock Safety OUI"}, {0x940853, "Flock Safety OUI"},
      {0xE4AAEA, "Flock Safety OUI"},
      // High-confidence dedicated camera makers (SSID-agnostic).
      {0x0018DD, "Hikvision OUI"}, {0x788B77, "Wyze OUI"}, {0x8C8590, "Reolink OUI"},
      // Official "Blink by Amazon" OUIs (camera-dedicated, unlike shared Amazon OUIs).
      {0x3CA070, "Blink OUI"}, {0x70AD43, "Blink OUI"}, {0x74AB93, "Blink OUI"},
      // Ring OUIs (hardcoded like C5-Midnight so Ring is found with no SD OUI DB).
      {0x501479, "Ring OUI"}, {0x086266, "Ring OUI"}, {0xB479A7, "Ring OUI"}, {0xDC4F22, "Ring OUI"},
      {0xFCE998, "Ring OUI"}, {0x74427F, "Ring OUI"}, {0x48022A, "Ring OUI"}, {0xAC9FC3, "Ring OUI"},
      {0x187F88, "Ring OUI"}, {0x343EA4, "Ring OUI"}, {0x54E019, "Ring OUI"}, {0x5C475E, "Ring OUI"},
      {0x649A63, "Ring OUI"}, {0x90486C, "Ring OUI"}, {0x9C7613, "Ring OUI"}, {0xCC3BFB, "Ring OUI"},
      {0xC4DBAD, "Ring OUI"}, {0x242BD6, "Ring OUI"},
      // Blink-specific Amazon OUIs (cameras + sync modules).
      {0x50DCE7, "Blink OUI"}, {0x6837E9, "Blink OUI"}, {0xA002DC, "Blink OUI"}, {0x38F73D, "Blink OUI"},
      {0x34D270, "Blink OUI"}, {0x74C63B, "Blink OUI"}, {0x18742E, "Blink OUI"}, {0xFC65DE, "Blink OUI"},
      // Shared Amazon OUIs (Ring/Blink among other Amazon gear -- lower confidence).
      {0x4473D6, "Amazon OUI (Ring/Blink?)"}, {0xE0B94D, "Amazon OUI (Ring/Blink?)"},
      {0xFCA183, "Amazon OUI (Ring/Blink?)"}, {0xF02F9E, "Amazon OUI (Ring/Blink?)"},
  };
  for (const auto& e : table)
    if (e.oui == oui) return e.reason;
  return "";
}

// macVendor() lives in RadioAuditActivity.cpp now: the OUI table moved off flash
// onto the SD card (/.radioink/oui.bin), so the lookup needs HalStorage and a
// file handle, which would violate this file's "pure, stateless, no hardware"
// contract. The declaration stays in RadioAuditHelpers.h for call sites.

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
  // Substring match: registry names arrive as "Amazon Technologies", "Ring LLC",
  // etc., so an exact compare would miss them (the old bug that hid Ring/Blink).
  struct VT {
    const char* token;
    const char* reason;
  };
  static constexpr VT toks[] = {
      {"amazon", "Amazon OUI - possible Ring/Blink"},
      {"ring", "Ring camera vendor"},
      {"blink", "Blink camera vendor"},
      {"wyze", "Wyze camera vendor"},
      {"hikvision", "Hikvision (camera vendor)"},
      {"dahua", "Dahua (camera vendor)"},
      {"axis", "Axis (camera vendor)"},
      {"reolink", "Reolink (camera vendor)"},
      {"amcrest", "Amcrest (camera vendor)"},
      {"arlo", "Arlo (camera vendor)"},
      {"eufy", "Eufy (camera vendor)"},
      {"foscam", "Foscam (camera vendor)"},
      {"lorex", "Lorex (camera vendor)"},
      {"ezviz", "EZVIZ (camera vendor)"},
  };
  for (const auto& t : toks)
    if (v.find(t.token) != std::string::npos) return t.reason;
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
