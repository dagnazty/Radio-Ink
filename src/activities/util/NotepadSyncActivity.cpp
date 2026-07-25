#include "NotepadSyncActivity.h"

#include <GfxRenderer.h>
#include <HalStorage.h>
#include <Logging.h>
#include <WiFi.h>

#include <algorithm>

#include "MappedInputManager.h"
#include "components/UITheme.h"
#include "fontIds.h"
#include "util/QrUtils.h"

namespace {
constexpr const char* NOTES_PATH = "/notes.txt";
constexpr const char* AP_SSID = "Radio-Ink-Notes";
constexpr const char* AP_PASS = "radioink";  // WPA2 (>= 8 chars); baked into the join QR
constexpr uint8_t AP_CHANNEL = 1;
constexpr int DNS_PORT = 53;
constexpr int AP_MAX_CLIENTS = 4;

std::string htmlEscape(const String& in) {
  std::string out;
  out.reserve(in.length() + 16);
  for (size_t i = 0; i < in.length(); i++) {
    const char c = in[i];
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

void NotepadSyncActivity::onEnter() {
  Activity::onEnter();
  joinPayload = std::string("WIFI:T:WPA;S:") + AP_SSID + ";P:" + AP_PASS + ";;";
  startPortal();
  requestUpdate();
}

void NotepadSyncActivity::startPortal() {
  WiFi.mode(WIFI_AP);
  delay(100);
  apStarted = WiFi.softAP(AP_SSID, AP_PASS, AP_CHANNEL, false, AP_MAX_CLIENTS);
  if (!apStarted) {
    LOG_ERR("NOTESYNC", "softAP failed for '%s'", AP_SSID);
    return;
  }
  delay(100);
  const IPAddress ip = WiFi.softAPIP();
  char b[16];
  snprintf(b, sizeof(b), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
  apIp = b;

  dns.reset(new (std::nothrow) DNSServer());
  if (dns) {
    dns->setErrorReplyCode(DNSReplyCode::NoError);
    dns->start(DNS_PORT, "*", ip);
  }

  server.reset(new (std::nothrow) WebServer(80));
  if (server) {
    server->on("/", HTTP_GET, [this] { serveEditor(); });
    server->on("/save", HTTP_POST, [this] { handleSave(); });
    server->onNotFound([this] { serveEditor(); });  // captive-portal catch-all
    server->begin();
  }
  LOG_DBG("NOTESYNC", "Notes portal up: SSID='%s' IP=%s heap=%u", AP_SSID, apIp.c_str(),
          static_cast<unsigned>(ESP.getFreeHeap()));
}

void NotepadSyncActivity::serveEditor() {
  if (!server) return;
  const String notes = Storage.readFile(NOTES_PATH);
  std::string page =
      "<!DOCTYPE html><html><head><meta name=viewport content='width=device-width,initial-scale=1'>"
      "<title>Radio Ink - Notes</title><style>body{font-family:-apple-system,system-ui,sans-serif;"
      "background:#111;color:#eee;margin:0;padding:16px}h2{color:#fff;margin:0 0 6px}"
      "p.h{color:#aaa;font-size:12px;line-height:1.4;margin:0 0 12px}"
      "textarea{width:100%;box-sizing:border-box;min-height:60vh;background:#1c1c1c;color:#eee;border:1px solid #333;"
      "border-radius:8px;padding:12px;font:13px/1.5 ui-monospace,Menlo,Consolas,monospace}"
      "button{margin-top:12px;padding:12px 20px;font-size:16px;background:#2a6;color:#fff;border:0;border-radius:8px}"
      "code{color:#7cf}</style></head><body><h2>Radio Ink &mdash; Notes</h2>"
      "<p class=h>One page per <code>@note Title</code> or <code>@list Title</code> header. Note lines below a "
      "<code>@note</code> are free text; under <code>@list</code> use <code>[ ] item</code> / <code>[x] item</code>. "
      "Edit freely, then Save.</p>"
      "<form method=POST action=/save><textarea name=notes>" +
      htmlEscape(notes) +
      "</textarea><br><button type=submit>Save to device</button></form></body></html>";
  server->send(200, "text/html", page.c_str());
}

void NotepadSyncActivity::handleSave() {
  if (!server) return;
  const String body = server->arg("notes");
  const bool ok = Storage.writeFile(NOTES_PATH, body);
  if (ok) saveCount++;
  else LOG_ERR("NOTESYNC", "Failed to write %s", NOTES_PATH);
  requestUpdate();  // refresh the on-device save counter

  const std::string page =
      std::string("<!DOCTYPE html><html><head><meta name=viewport content='width=device-width,initial-scale=1'>"
                  "<meta http-equiv=refresh content='1;url=/'>"
                  "<title>Saved</title><style>body{font-family:-apple-system,system-ui,sans-serif;background:#111;"
                  "color:#eee;margin:0;padding:24px;text-align:center}a{color:#7cf}</style></head><body><h2>") +
      (ok ? "Saved &check;" : "Save failed") + "</h2><p><a href=/>Back to notes</a></p></body></html>";
  server->send(200, "text/html", page.c_str());
}

void NotepadSyncActivity::loop() {
  if (apStarted) {
    if (dns) dns->processNextRequest();
    if (server) server->handleClient();
  }
  if (mappedInput.wasPressed(MappedInputManager::Button::Back) ||
      mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
    rebootToFreeHeap("Restarting to free memory...");
  }
}

void NotepadSyncActivity::rebootToFreeHeap(const char* msg) {
  // A SoftAP fragments the heap past BLE's contiguous need; the C3 has no runtime
  // defrag, so reboot on exit to restore it (see WebReportActivity for the detail).
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
  renderer.drawCenteredText(UI_12_FONT_ID, renderer.getScreenHeight() / 2 - 10, msg, true, EpdFontFamily::BOLD);
  renderer.displayBuffer(HalDisplay::FULL_REFRESH);
  delay(600);
  ESP.restart();
}

void NotepadSyncActivity::render(RenderLock&&) {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  const auto pageHeight = renderer.getScreenHeight();
  renderer.clearScreen();

  const std::string subtitle = apStarted ? (saveCount > 0 ? (String("Saved x") + saveCount).c_str() : "Scan to edit")
                                         : "AP failed";
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, "Sync Notes (web)",
                 subtitle.c_str());

  const int x = metrics.contentSidePadding;
  int y = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;

  const int qrSize = std::min(pageWidth - x * 2, (pageHeight - y) * 3 / 5);
  const Rect qrBounds((pageWidth - qrSize) / 2, y, qrSize, qrSize);
  if (apStarted) QrUtils::drawQrCode(renderer, qrBounds, joinPayload);
  y += qrSize + metrics.verticalSpacing;

  renderer.drawCenteredText(UI_12_FONT_ID, y, "Scan: join Wi-Fi, edit notes", true, EpdFontFamily::BOLD);
  y += renderer.getLineHeight(UI_12_FONT_ID) + 8;
  renderer.drawCenteredText(SMALL_FONT_ID, y, (String("Net: ") + AP_SSID + "   Pass: " + AP_PASS).c_str(), true);
  y += renderer.getLineHeight(SMALL_FONT_ID) + 4;
  if (apStarted)
    renderer.drawCenteredText(SMALL_FONT_ID, y, (String("Or browse to  http://") + apIp.c_str()).c_str(), true);

  const auto labels = mappedInput.mapLabels("Stop", "", "", "");
  UITheme::getInstance().suppressBrandLogoOnce();
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer(HalDisplay::FULL_REFRESH);
}

void NotepadSyncActivity::onExit() {
  Activity::onExit();
  if (server) {
    server->stop();
    server.reset();
  }
  if (dns) {
    dns->stop();
    dns.reset();
  }
  WiFi.softAPdisconnect(false);
  apStarted = false;
  WiFi.mode(WIFI_OFF);
  delay(250);
}
