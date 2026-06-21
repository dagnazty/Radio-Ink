#pragma once

#include <DNSServer.h>
#include <WebServer.h>

#include <memory>
#include <string>

#include "activities/Activity.h"

// Evil-twin / captive-portal: stands up an OPEN access point cloning a target
// SSID, redirects all DNS to ourselves, and serves a credential-capture login
// page. Authorized testing only — gated behind RADIO_AUDIT_ENABLE_ACTIVE at the
// call site. Captured credentials are written to /.radioink/loot/.
class EvilTwinActivity final : public Activity {
 public:
  EvilTwinActivity(GfxRenderer& renderer, MappedInputManager& mappedInput, std::string ssid);

  void onEnter() override;
  void onExit() override;
  void loop() override;
  void render(RenderLock&&) override;
  bool preventAutoSleep() override { return apStarted; }
  bool skipLoopDelay() override { return apStarted; }

 private:
  void startPortal();
  void servePortal();  // GET: the fake login page (also the captive-portal catch-all)
  void handleSubmit();  // POST /login: capture credentials
  void saveCredential(const String& user, const String& pass, const String& host);

  std::string targetSsid;
  std::unique_ptr<WebServer> server;
  std::unique_ptr<DNSServer> dns;
  bool apStarted = false;
  std::string apIp;
  std::string lootPath;
  std::string lootBuffer;  // full loot file content, rewritten on each capture
  int capturedCount = 0;
  std::string lastCapture;
  uint32_t lastUiMs = 0;
};
