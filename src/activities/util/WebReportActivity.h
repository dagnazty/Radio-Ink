#pragma once

#include <DNSServer.h>
#include <WebServer.h>

#include <memory>
#include <string>

#include "activities/Activity.h"

// Web Report: stands up a WPA2 SoftAP + captive-portal web server that serves the
// current scan's findings as an HTML page, and shows a Wi-Fi-join QR. Scan the QR
// on a phone -> join the AP -> the captive portal auto-opens the report like a
// website. Benign (serves your own report) -- ships in all builds, not gated.
class WebReportActivity final : public Activity {
 public:
  WebReportActivity(GfxRenderer& renderer, MappedInputManager& mappedInput, std::string reportText);

  void onEnter() override;
  void onExit() override;
  void loop() override;
  void render(RenderLock&&) override;
  bool preventAutoSleep() override { return apStarted; }
  bool skipLoopDelay() override { return apStarted; }

 private:
  void startPortal();
  void servePage();  // the report page (also the captive-portal catch-all)

  std::string pageHtml;  // prebuilt HTML page served on every request
  std::unique_ptr<WebServer> server;
  std::unique_ptr<DNSServer> dns;
  bool apStarted = false;
  std::string apIp;
  std::string joinPayload;  // WIFI:... QR payload
  bool qrShown = false;     // render the (full-refresh) QR only once
  uint32_t lastUiMs = 0;
};
