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
std::string bleCompany(const std::string& hex);  // BLE company id -> vendor name (small built-in set)
// BLE company/vendor from manufacturer-data hex: SD database (gen_ble_companies.py)
// first, then the built-in set; never empty (falls back to "0xNNNN"). The SD-backed
// half is defined in RadioAuditActivity.cpp (needs HalStorage), like macVendor().
std::string bleVendorName(const std::string& manufacturerHex);
std::string bleCompanyById(uint16_t id);  // SD database only; "" if absent/unknown
// BLE GATT service name from a service-UUID string (16-bit short or 128-bit SIG
// base form); "" if not a SIG-assigned service. Flash-resident table.
std::string bleServiceName(const std::string& uuid);

std::string upperStr(std::string s);
std::string lowerStr(std::string s);

// Edit distance between two short strings (SSIDs are <=32 bytes, so the O(n*m)
// DP table is trivial). Used to flag look-alike SSIDs (evil-twin typosquats).
int levenshteinDistance(const std::string& a, const std::string& b);

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

// ---- Threat-sweep signature detectors (passive, all flash-resident) ----
// WiFi-side: Pwnagotchi presence beacon (DE:AD:BE:EF MAC / JSON-identity SSID).
std::string pwnagotchiReason(const std::string& ssid, const std::string& bssid);
// BLE-side: Flipper Zero (name), card-skimmer serial-BT modules (HC-05/06, HM-10,
// JDY, CC41 default names), and Meshtastic nodes (service UUID or name).
std::string bleThreatReason(const std::string& name, const std::string& manufacturerHex,
                            const std::string& svcUuid, const std::string& svcDataHex);
// Heuristic: a large RSSI swing across several sightings suggests a relay/spoof.
std::string bleRelayReason(int rssiMin, int rssiMax, int seenCount);

// BLE-broadcast drone Remote ID (ASTM F3411 / OpenDroneID): service UUID 0xFFFA
// or manufacturer company id 0xFFFA. "" if not an ODID advert.
std::string droneBleReason(const std::string& manufacturerHex, const std::string& svcUuid,
                           const std::string& svcDataUuid);

// Pairing/popup advert family abused by BLE-spam floods (Flipper Zero, phone
// apps): Apple proximity-pairing, Microsoft Swift Pair, Google Fast Pair,
// Samsung. Takes a decodeBleAdvert() result; returns the family or "".
std::string bleSpamFamily(const std::string& advType);

}  // namespace ra
