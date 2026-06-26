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
    ExportWigle,
    CapturePcap,
    CaptureHandshake,
    DeauthAttack,
    DeauthSelected,
    BeaconFlood,
    EvilTwin,
    TrackerSweep,
    DeauthDetector,
    BleSpoof,
    Karma,
    DeauthCameras,
    ThreatSweep,
    AntiStalk,
    DroneScan,
    ReportViewer,
    ShareWeb,
    Guardian,
    ScheduledLog,
    About,
    COUNT,
  };

 private:
  enum class State {
    IDLE,
    WIFI_SCANNING,
    BLE_SCANNING,
    CAPTURING,
    ATTACKING,
    STALKING,
    GUARDIAN,
    LOG_SETUP,
    LOGGING,
    DONE,
    SAVED,
    ERROR
  };
  enum class ScanScope { Both, WifiOnly, BleOnly };
  enum class CaptureMode { Pcap, Handshake, DeauthDetect, DroneScan };
  enum class AttackMode { Deauth, Beacon, BleSpoof, Karma, CameraDeauth };

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
    bool wps = false;     // WPS advertised in the AP's scan record (PIN-attack surface)
    bool marked = false;  // selected as a deauth target ("Deauth selected")
  };

  struct BleFinding {
    std::string address;
    std::string name;
    std::string manufacturerHex;
    std::string serviceUuid;      // advertised primary service UUID (e.g. Meshtastic)
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
    std::string apBssid;  // for camera-sweep clients: the AP they're associated to
    int rssi = 0;
    int channel = 0;  // channel the station was heard on (camera sweep)
  };

  // A camera hit from the sweep, selectable for Locate / Deauth.
  struct CameraTarget {
    enum class Kind { WifiAp, Client, Ble };
    Kind kind = Kind::Client;
    std::string mac;      // AP BSSID / client MAC / BLE address
    std::string label;    // SSID or device name
    std::string reason;   // why it was flagged
    uint8_t macBytes[6] = {};
    uint8_t apBytes[6] = {};  // for clients: the AP they're associated to (directed deauth)
    bool hasAp = false;
    int channel = 0;
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
  bool showingCameraList = false;  // selectable list of camera hits from the sweep
  bool targetFromList = false;     // true if the detail view was opened from a results list
  bool targetFromCameraList = false;  // detail was opened from the camera list (Back returns there)
  std::vector<CameraTarget> cameraTargets;
  int cameraSel = 0;
  // Camera target currently in the detail view (for directed deauth).
  bool targetIsCamera = false;
  bool targetCamHasAp = false;
  uint8_t targetCamMac[6] = {};
  uint8_t targetCamAp[6] = {};
  int targetCamChannel = 0;
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
  int ddAlertCount = 0;  // deauth-flood sources flagged this session

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

  // Anti-Stalk Watch: a device that keeps reappearing across repeated BLE passes
  // as you move is a possible follower. Tracked across passes by BLE address.
  struct StalkEntry {
    std::string addr;
    std::string label;  // device name or resolved vendor
    std::string kind;   // tracker classification, if any
    int passesSeen = 0;
    int passesMissed = 0;
    int rssi = 0;
    bool tracker = false;
    bool watchlisted = false;
    bool seenThisPass = false;
  };
  std::vector<StalkEntry> stalkTable;
  int stalkPassCount = 0;
  uint32_t stalkLastPassMs = 0;

  // Guardian Mode: aggregated live threat list (rebuilt each round) + the worst
  // severity seen this session, for the persistent alert banner.
  std::vector<std::string> guardianThreats;
  int guardianRound = 0;
  uint32_t guardianLastMs = 0;
  int guardianAlertPeak = 0;  // 0 = all clear, 1 = caution, 2 = alert

  // Scheduled Log: unattended periodic scan -> SD CSV (reuses captureFile/path).
  int logCycles = 0;
  int logEntries = 0;
  uint32_t logLastMs = 0;
  int logIntervalSel = 1;          // index into the interval presets (default 30 s)
  uint32_t logIntervalMs = 30000;  // chosen scan interval, set from the setup screen
  int logSetupField = 0;           // which setup row is selected (0 interval, 1 run-time, 2 radios)
  int logDurationSel = 0;          // run-time preset index (0 = until stopped)
  int logRadioSel = 0;             // 0 = WiFi+BLE, 1 = WiFi only, 2 = BLE only
  uint32_t logStartMs = 0;         // when logging began (for the auto-stop duration)

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
  // Flood-safe scan for the Threat Sweep: passive scan + a per-advert callback
  // that merges each device then erases it from the BLE result map, so a BLE-spam
  // flood can't accumulate hundreds of parsed adverts and exhaust scan-time heap.
  bool runBleScanStreaming(int windows);
 public:
  // Sink for the streaming callback (one parsed advert). Public only so the
  // anonymous-namespace callback object in the .cpp can reach it.
  void ingestStreamedAdvert(BLEAdvertisedDevice& device);

 private:
#endif
  void shutdownBleController();
  void resetWifiForScan();
  void finishScanPass();
  void mergeWifiFinding(WifiFinding&& finding);
  void mergeBleFinding(BleFinding&& finding);
  void rebuildAuditFindings();
  // Count BLE pairing-popup adverts in bleFindings (Apple/SwiftPair/FastPair/
  // Samsung); sets dominantFamily to the most common. Used to flag BLE spam.
  int bleSpamAdvertCount(std::string& dominantFamily) const;
  void addAuditFinding(const char* severity, const std::string& title, const std::string& detail, int wifiIndex = -1,
                       int bleIndex = -1);
  void showAuditFindings();
  void showWifiDetails();
  void showBleDetails();
  void startCameraSweep();  // run a fresh WiFi+BLE scan, then show camera clues
  void showCameraSweep();
  void buildCameraTargets();  // collect camera hits into the selectable list
  void renderCameraList();
  void openCameraDetail(int idx);  // detail + Locate/Deauth for the picked camera
#if defined(RADIO_AUDIT_ENABLE_ACTIVE)
  void startCameraDeauth();  // directed deauth of the selected camera off its AP
#endif
  void showAbout();  // credits + version page
  void startTrackerSweep();  // active BLE scan, then list AirTag/Tile/SmartTag trackers
  void startAntiStalk();     // repeated BLE passes; flag devices that follow across passes
  void antiStalkPass();      // one BLE pass: update the persistence table
  void stopAntiStalk();      // end the watch, show a summary of followers
  void renderAntiStalk();    // live persistence view
  bool isWatchlisted(const std::string& mac) const;  // MAC/prefix match against watchlist.txt
  void startGuardian();      // set-and-forget monitor: unifies the passive detectors
  void guardianPass();       // one round: BLE threats + followers, then a deauth-flood window
  void stopGuardian();
  void renderGuardian();     // live threat dashboard (ALL CLEAR / active threats)
  void showLogSetup();       // interval picker shown before logging starts
  void renderLogSetup();
  void startScheduledLog();  // unattended: scan WiFi+BLE on an interval, append to SD with timestamps
  void scanLogPass();        // one logging cycle
  void stopScheduledLog();
  void renderScheduledLog();
  void startThreatSweep();   // WiFi+BLE scan, then list Flipper/Pwnagotchi/skimmer/Meshtastic/relay/Axon hits
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
  void startDeauthDetect();    // passive deauth/disassoc flood monitor
  void stopDeauthDetect();
  void processDeauthDetect();  // write alert lines for sources over threshold
  void renderDeauthDetect();
  void startDroneScan();       // passive OpenDroneID (Remote ID) beacon monitor
  void stopDroneScan();
  void renderDroneScan();
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
  void startDeauthCameras();   // only APs fingerprinted as cameras (Flock etc.)
  void startBeaconFlood();
  void startEvilTwin();        // rogue AP + captive portal (launches EvilTwinActivity)
  void startBleSpoof();        // flood the air with phantom BLE advertisements
  void startKarma();           // harvest probe-request PNLs + beacon them back
  void stopAttack();
  void renderAttack();
#endif
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
  void exportWigle();
  bool saveFile(const char* path, const String& content);
  String makeTimestampedPath(const char* ext) const;
  String makeTextReport() const;
  String makeCsvReport() const;
  String makeJsonReport() const;
  String makeWigleReport() const;
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
           state == State::ATTACKING || state == State::STALKING || state == State::GUARDIAN ||
           state == State::LOGGING || locating;
  }
};
