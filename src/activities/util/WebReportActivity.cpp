#include "WebReportActivity.h"

#include <algorithm>

#include <GfxRenderer.h>
#include <HalStorage.h>
#include <Logging.h>
#include <WiFi.h>

#include "MappedInputManager.h"
#include "components/UITheme.h"
#include "fontIds.h"
#include "util/QrUtils.h"

namespace {
constexpr const char* AP_SSID = "Radio-Ink-Report";
constexpr const char* AP_PASS = "radioink";  // WPA2 (>= 8 chars); baked into the join QR
constexpr uint8_t AP_CHANNEL = 1;
constexpr int DNS_PORT = 53;
constexpr int AP_MAX_CLIENTS = 4;

// Minimal HTML escape so SSIDs/values in the report can't break the page.
std::string htmlEscape(const std::string& in) {
  std::string out;
  out.reserve(in.size() + 16);
  for (const char c : in) {
    switch (c) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      default: out += c; break;
    }
  }
  return out;
}
}  // namespace

WebReportActivity::WebReportActivity(GfxRenderer& renderer, MappedInputManager& mappedInput, std::string reportText)
    : Activity("WebReport", renderer, mappedInput) {
  pageHtml =
      "<!DOCTYPE html><html><head><meta name=viewport content='width=device-width,initial-scale=1'>"
      "<title>Radio Ink - Findings</title><style>body{font-family:-apple-system,system-ui,sans-serif;"
      "background:#111;color:#eee;margin:0;padding:16px}h2{color:#fff;margin:0 0 12px}"
      "pre{white-space:pre-wrap;word-break:break-word;font-size:13px;line-height:1.45;background:#1c1c1c;"
      "padding:12px;border-radius:8px;margin:0}</style></head><body><h2>Radio Ink &mdash; Findings</h2><pre>" +
      htmlEscape(reportText) + "</pre></body></html>";
  // WIFI: join payload -> iOS offers "Join 'Radio-Ink-Report'" when scanned.
  joinPayload = std::string("WIFI:T:WPA;S:") + AP_SSID + ";P:" + AP_PASS + ";;";
}

void WebReportActivity::onEnter() {
  Activity::onEnter();
  startPortal();
  requestUpdate();
}

void WebReportActivity::startPortal() {
  WiFi.mode(WIFI_AP);
  delay(100);
  apStarted = WiFi.softAP(AP_SSID, AP_PASS, AP_CHANNEL, false, AP_MAX_CLIENTS);
  if (!apStarted) {
    LOG_ERR("WEBRPT", "softAP failed for '%s'", AP_SSID);
    return;
  }
  delay(100);
  const IPAddress ip = WiFi.softAPIP();
  char b[16];
  snprintf(b, sizeof(b), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
  apIp = b;

  // Resolve every domain to us so the phone's captive-portal probe hits our page.
  dns.reset(new (std::nothrow) DNSServer());
  if (dns) {
    dns->setErrorReplyCode(DNSReplyCode::NoError);
    dns->start(DNS_PORT, "*", ip);
  }

  server.reset(new (std::nothrow) WebServer(80));
  if (server) {
    server->on("/", HTTP_ANY, [this] { servePage(); });
    server->onNotFound([this] { servePage(); });  // captive-portal catch-all (incl. iOS hotspot-detect)
    server->begin();
  }
  LOG_DBG("WEBRPT", "Report portal up: SSID='%s' IP=%s heap=%u", AP_SSID, apIp.c_str(),
          static_cast<unsigned>(ESP.getFreeHeap()));
}

void WebReportActivity::servePage() {
  if (server) server->send(200, "text/html", pageHtml.c_str());
}

void WebReportActivity::loop() {
  if (apStarted) {
    if (dns) dns->processNextRequest();
    if (server) server->handleClient();
  }
  if (mappedInput.wasPressed(MappedInputManager::Button::Back) ||
      mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
    // Running the SoftAP drives free heap to a few KB, which fragments it past the
    // point a later BLE scan can claim a contiguous ~65 KB block -- and the C3 has
    // no runtime heap defrag, so only a reboot restores it. Restart on exit so BLE
    // (and everything else) works immediately afterward, instead of silently
    // failing until the user power-cycles.
    if (server) {
      server->stop();
      server.reset();
    }
    if (dns) {
      dns->stop();
      dns.reset();
    }
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_OFF);
    renderer.clearScreen();
    renderer.drawCenteredText(UI_12_FONT_ID, renderer.getScreenHeight() / 2 - 10, "Restarting to free memory...", true,
                              EpdFontFamily::BOLD);
    renderer.displayBuffer(HalDisplay::FULL_REFRESH);
    delay(600);
    ESP.restart();
  }
  (void)lastUiMs;
  (void)qrShown;
}

void WebReportActivity::render(RenderLock&&) {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  const auto pageHeight = renderer.getScreenHeight();
  renderer.clearScreen();

  const std::string subtitle = apStarted ? "Scan to view" : "AP failed";
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, "Share Findings (web)",
                 subtitle.c_str());

  const int x = metrics.contentSidePadding;
  int y = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;

  // Join QR (top). Sized as a square that leaves room for the text below.
  const int qrSize = std::min(pageWidth - x * 2, (pageHeight - y) * 3 / 5);
  const Rect qrBounds((pageWidth - qrSize) / 2, y, qrSize, qrSize);
  if (apStarted) QrUtils::drawQrCode(renderer, qrBounds, joinPayload);
  y += qrSize + metrics.verticalSpacing;

  renderer.drawCenteredText(UI_12_FONT_ID, y, "Scan: join Wi-Fi, page opens", true, EpdFontFamily::BOLD);
  y += renderer.getLineHeight(UI_12_FONT_ID) + 8;
  renderer.drawCenteredText(SMALL_FONT_ID, y, (String("Net: ") + AP_SSID + "   Pass: " + AP_PASS).c_str(), true);
  y += renderer.getLineHeight(SMALL_FONT_ID) + 4;
  if (apStarted)
    renderer.drawCenteredText(SMALL_FONT_ID, y, (String("Or browse to  http://") + apIp.c_str()).c_str(), true);

  const auto labels = mappedInput.mapLabels("Stop", "", "", "");
  UITheme::getInstance().suppressBrandLogoOnce();  // keep the skull off the QR
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  // Full refresh once: a fast/partial refresh ghosts the QR and breaks scanning.
  renderer.displayBuffer(HalDisplay::FULL_REFRESH);
}

void WebReportActivity::onExit() {
  Activity::onExit();
  // Free the captive-portal services first so their sockets release.
  if (server) {
    server->stop();
    server.reset();
  }
  if (dns) {
    dns->stop();
    dns.reset();
  }
  // Clear the AP but keep the radio in AP mode, so the WiFi.mode(WIFI_OFF) below
  // performs a real AP->OFF transition that calls esp_wifi_deinit() and frees the
  // ~65 KB WiFi driver block. (softAPdisconnect(TRUE) pre-sets the mode to OFF,
  // making WiFi.mode(WIFI_OFF) a no-op that SKIPS the deinit -> the driver memory
  // is never returned -> the heap stays fragmented and a later BLE scan can't get
  // a contiguous block until the device is rebooted.)
  WiFi.softAPdisconnect(false);
  apStarted = false;
  WiFi.mode(WIFI_OFF);  // AP -> OFF: triggers esp_wifi_deinit(), defragmenting the heap
  delay(250);
  LOG_DBG("WEBRPT", "AP down, free=%u maxblk=%u", static_cast<unsigned>(ESP.getFreeHeap()),
          static_cast<unsigned>(ESP.getMaxAllocHeap()));
}
