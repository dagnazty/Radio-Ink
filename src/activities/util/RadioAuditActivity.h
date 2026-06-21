#pragma once

#include <WiFi.h>

#include <string>
#include <vector>

#include "activities/Activity.h"
#include "util/ButtonNavigator.h"

#if defined(RADIO_AUDIT_ENABLE_BLE)
#include <BLEAdvertisedDevice.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#endif

class RadioAuditActivity final : public Activity {
  enum class State { IDLE, WIFI_SCANNING, BLE_SCANNING, DONE, SAVED, ERROR };

  struct WifiFinding {
    std::string ssid;
    std::string bssid;
    std::string auth;
    int32_t rssi = 0;
    int32_t rssiMin = 0;
    int32_t rssiMax = 0;
    int32_t rssiSum = 0;
    int32_t channel = 0;
    int32_t seenCount = 0;
    bool hidden = false;
  };

  struct BleFinding {
    std::string address;
    std::string name;
    std::string manufacturerHex;
    std::string serviceDataUuid;
    std::string serviceDataHex;
    int rssi = 0;
    int rssiMin = 0;
    int rssiMax = 0;
    int rssiSum = 0;
    int txPower = 0;
    int seenCount = 0;
    bool hasTxPower = false;
  };

  struct AuditFinding {
    std::string severity;
    std::string title;
    std::string detail;
    int wifiIndex = -1;  // >=0 if this finding maps to a Wi-Fi target
    int bleIndex = -1;   // >=0 if this finding maps to a BLE target
  };

  struct ProbeEntry {
    std::string client;
    std::string ssid;
    int rssi = 0;
  };

  ButtonNavigator buttonNavigator;
  State state = State::IDLE;
  int selectedAction = 0;
  int selectedFinding = 0;
  // Menu category navigation: currentCategory < 0 = top-level category list.
  int currentCategory = -1;
  int selectedCategory = 0;
  int selectedItem = 0;
  int scanCurrentPass = 0;
  int scanTotalPasses = 1;
  bool showingDetails = false;
  bool showingBleDetails = false;
  bool showingFindings = false;
  bool showingTarget = false;
  bool targetFromList = false;  // true if the detail view was opened from a results list
  bool deepScanMode = false;
  int targetScroll = 0;
  std::string targetTitle;
  std::vector<std::string> targetLines;
  std::string scanTime;  // RTC/uptime stamp captured when the last scan finished
  std::string status = "Ready";
  std::vector<std::string> watchlist;  // uppercased MACs / MAC-prefixes from watchlist.txt

  // The target currently shown in the detail view, so it can be located.
  bool targetLocatable = false;
  bool targetLocBle = false;
  uint8_t targetLocBssid[6] = {};
  int targetLocChannel = 0;
  std::string targetLocAddr;
  std::string targetLocName;

  // Live RSSI locator ("find it") state.
  bool locating = false;
  int locCurRssi = 0;
  int locBestRssi = 0;
  int locPrevRssi = 0;
  bool locHasSignal = false;
  uint32_t locLastSampleMs = 0;
  std::vector<WifiFinding> wifiFindings;
  std::vector<BleFinding> bleFindings;
  std::vector<AuditFinding> auditFindings;

#if defined(RADIO_AUDIT_ENABLE_BLE)
  BLEScan* bleScan = nullptr;
  bool bleReady = false;
#endif

  void startScan(bool deepScan);
  void startWifiScanPass();
  void processWifiScan();
  void startBleScan();
  void shutdownBleController();
  void resetWifiForScan();
  void finishScanPass();
  void mergeWifiFinding(WifiFinding&& finding);
  void mergeBleFinding(BleFinding&& finding);
  void rebuildAuditFindings();
  void addAuditFinding(const char* severity, const std::string& title, const std::string& detail, int wifiIndex = -1,
                       int bleIndex = -1);
  void showAuditFindings();
  void showWifiDetails();
  void showBleDetails();
  void deepScanWifiTarget(int index);
  void deepScanBleTarget(int index);
  void startProbeScan();
  void runAction(int action);
  void showChannelUsage();
  void loadWatchlist();
  void diffAndSaveSnapshot();
  void startLocator();
  void stopLocator();
  void locatorSample();
  void renderLocator();
  void exportText();
  void exportCsv();
  void exportJson();
  bool saveFile(const char* path, const String& content);
  String makeTimestampedPath(const char* ext) const;
  String makeTextReport() const;
  String makeCsvReport() const;
  String makeJsonReport() const;
  String makeRiskSummary() const;
  String scanModeName() const;
  static std::string authName(wifi_auth_mode_t auth);
  static int averageRssi(int rssiSum, int seenCount);
  static String csvEscape(const std::string& value);
  static String jsonEscape(const std::string& value);

 public:
  explicit RadioAuditActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : Activity("RadioInk", renderer, mappedInput) {}

  void onEnter() override;
  void onExit() override;
  void loop() override;
  void render(RenderLock&&) override;
  bool preventAutoSleep() override {
    return state == State::WIFI_SCANNING || state == State::BLE_SCANNING || locating;
  }
};
