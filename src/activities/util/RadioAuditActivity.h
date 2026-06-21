#pragma once

#include <HalStorage.h>
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
 public:
  // Leaf actions dispatched from the menu. The integer order MUST match
  // ACTION_LABELS in the .cpp; COUNT is the table size sentinel.
  enum class Action {
    QuickScan,
    DeepScan,
    WifiScan,
    BleScan,
    ClientRecon,
    ChannelUsage,
    AuditFindings,
    WifiResults,
    BleResults,
    CameraSweep,
    ExportText,
    ExportCsv,
    ExportJson,
    CapturePcap,
    BrowseFiles,
    CaptureHandshake,
    DeauthAttack,
    DeauthSelected,
    BeaconFlood,
    EvilTwin,
    TrackerSweep,
    BleSpoof,
    About,
    COUNT,
  };

 private:
  enum class State { IDLE, WIFI_SCANNING, BLE_SCANNING, CAPTURING, ATTACKING, DONE, SAVED, ERROR };
  enum class ScanScope { Both, WifiOnly, BleOnly };
  enum class CaptureMode { Pcap, Handshake };
  enum class AttackMode { Deauth, Beacon, BleSpoof };

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
    bool marked = false;  // selected as a deauth target ("Deauth selected")
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
  ScanScope scanScope = ScanScope::Both;
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
  std::vector<ProbeEntry> probeFindings;
  std::vector<ProbeEntry> clientFindings;  // associated WiFi stations seen during camera sweep

  // Live PCAP capture (promiscuous frames streamed to SD). The ring buffer and
  // promiscuous callback live in the .cpp anon namespace; these track the
  // open output file and channel-hop/flush timing for the activity loop.
  bool capturing = false;
  CaptureMode captureMode = CaptureMode::Pcap;
  HalFile captureFile;
  std::string capturePath;
  uint8_t captureChannel = 1;
  uint32_t captureLastHopMs = 0;
  uint32_t captureLastFlushMs = 0;
  uint32_t captureBytesWritten = 0;
  int hsPmkidCount = 0;  // PMKID lines written to the .22000 this session
  int hsEapolCount = 0;  // EAPOL (M1+M2) lines written this session

  // Active attack state (deauth / beacon flood).
  AttackMode attackMode = AttackMode::Deauth;
  uint32_t attackFrames = 0;          // frames transmitted this session
  uint32_t attackLastMs = 0;          // last burst timestamp
  int attackTargetIdx = 0;            // round-robin cursor into attackTargets
  std::vector<int> attackTargets;     // wifiFindings indices to deauth (focused/grouped/all)
  std::string attackScopeLabel;       // "all" / "selected" / SSID, for the screen
  int lastDeepScanWifiIndex = -1;     // wifiFindings index of the last WiFi deep scan
  bool captureChannelLocked = false;  // handshake capture: dwell vs hop
  std::string attackStatusLine;       // current target description for the screen

  // Action menu shown over a WiFi AP's deep-scan detail (mark / deauth / locate).
  bool targetMenuOpen = false;
  int targetMenuSel = 0;
  std::vector<int> targetMenuCodes;  // action codes for the visible menu rows

  // SD file browser for audit outputs (captures + reports under /.radioink).
  // Navigation is floored at the audit root; files are deletable, dirs descend.
  bool showingFiles = false;
  bool filesLockNextConfirm = false;  // swallow the Confirm release that opened the browser
  std::string filesDir;
  std::vector<std::string> fileEntries;  // names; directories end with '/'
  std::vector<uint32_t> fileSizes;       // bytes (0 for directories)
  int fileSelected = 0;

#if defined(RADIO_AUDIT_ENABLE_BLE)
  BLEScan* bleScan = nullptr;
  bool bleReady = false;
#endif

  void startScan(bool deepScan, ScanScope scope = ScanScope::Both);
  void beginScanPass();
  void startWifiScanPass();
  void processWifiScan();
  void startBleScan();
  void prepWifiSta();  // shutdown BLE + reset WiFi into clean STA mode
#if defined(RADIO_AUDIT_ENABLE_BLE)
  void absorbBleResults(BLEScanResults* results, int maxDevices);  // merge one scan window, capped
  bool runBleScan(bool active, int windows);  // WiFi-off + heap-guarded bounded BLE windows -> bleFindings
#endif
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
  void startCameraSweep();  // run a fresh WiFi+BLE scan, then show camera clues
  void showCameraSweep();
  void showAbout();  // credits + version page
  void startTrackerSweep();  // active BLE scan, then list AirTag/Tile/SmartTag trackers
#if defined(RADIO_AUDIT_ENABLE_BLE)
  void gattEnumerate();  // connect to the detail-view BLE device and dump services
#endif
  void deepScanWifiTarget(int index);
  void deepScanBleTarget(int index);
  void startProbeScan();
  void startPcapCapture();
  void stopPcapCapture();
  void renderCapture();
  void startHandshakeCapture();
  void stopHandshakeCapture();
  void processHandshakes();
  void renderHandshake();
  void openTargetMenu();              // build + show the deep-scan action menu
  std::string targetMenuLabel(int code) const;
  void runTargetMenuItem(int code);
  void renderTargetMenu();
#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
  // Active/transmitting features (compiled out of release builds).
  bool requireAuthorization();  // returns true if already authorized; else prompts and returns false
  void handshakeDeauthTarget();
  void beginDeauth(std::vector<int> targets, const std::string& label);  // focused/grouped/all deauth
  void startDeauthAttack();    // all visible APs
  void startDeauthSelected();  // only APs marked in the WiFi results list
  void startBeaconFlood();
  void startEvilTwin();        // rogue AP + captive portal (launches EvilTwinActivity)
  void startBleSpoof();        // flood the air with phantom BLE advertisements
  void stopAttack();
  void renderAttack();
#endif
  void startFilesBrowser();
  void loadFilesList();
  void renderFiles();
  void runAction(Action action);
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
    return state == State::WIFI_SCANNING || state == State::BLE_SCANNING || state == State::CAPTURING ||
           state == State::ATTACKING || locating;
  }
};
