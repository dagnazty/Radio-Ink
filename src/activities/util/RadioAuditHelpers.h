#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Stateless helpers for the Radio Audit tool: case folding, MAC/OUI vendor
// lookup, BLE advertising-data decoding, and camera/tracker fingerprinting.
// Defined in RadioAuditHelpers.cpp; RadioAuditActivity.cpp pulls them in via
// `using namespace ra;` so call sites stay unqualified.
namespace ra {

// MAC / hex utilities.
bool macEq(const uint8_t* a, const uint8_t* b);
bool macIsGroup(const uint8_t* m);              // true if broadcast/multicast
bool parseBssid(const std::string& text, uint8_t out[6]);
std::string macToString(const uint8_t* m);
std::string bytesToHex(const uint8_t* b, int n);
std::string strToHex(const char* s);
std::string humanSize(uint32_t bytes);
std::string bleCompany(const std::string& hex);  // BLE company id -> vendor name

std::string upperStr(std::string s);
std::string lowerStr(std::string s);

// Camera/IoT fingerprints from an SSID/name + vendor string.
std::string cameraFingerprintReason(const std::string& label, const std::string& vendor);
// Camera likelihood from a MAC/BLE vendor name (Amazon=Ring/Blink, IP-cam makers).
std::string cameraVendorReason(const std::string& vendor);
// Camera vendor from a "AA:BB:CC:.." MAC OUI (Flock Safety + dedicated cam makers).
std::string cameraMacReason(const std::string& mac);

// Vendor from a "AA:BB:CC:.." MAC: a name, "randomized", or "" if unknown.
std::string macVendor(const std::string& mac);

std::vector<uint8_t> hexToBytes(const std::string& hex);
std::string eddystoneUrl(const std::vector<uint8_t>& d);
// Human-readable type of a BLE advert (iBeacon / Eddystone / Apple / etc.).
std::string decodeBleAdvert(const std::string& manufacturerHex, const std::string& svcUuid,
                            const std::string& svcDataHex);
// Known item-tracker classification (AirTag/FindMy / Tile / SmartTag / Chipolo).
std::string trackerReason(const std::string& manufacturerHex, const std::string& svcUuid,
                          const std::string& svcDataHex, const std::string& name);

}  // namespace ra
