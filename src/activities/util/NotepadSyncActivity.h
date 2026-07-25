#pragma once

#include <DNSServer.h>
#include <WebServer.h>

#include <memory>
#include <string>

#include "activities/Activity.h"

// Notepad Wi-Fi sync: stands up a WPA2 SoftAP + captive-portal web server that
// serves the notepad file (`/notes.txt`) in an editable textarea, so you can add /
// remove / edit notes from a phone or PC, then Save writes it back to SD. Shows a
// Wi-Fi-join QR like the Web Report. Reboots on exit — a SoftAP fragments the heap
// past the contiguous block BLE needs and the C3 has no runtime defrag, so only a
// restart restores it (same lesson as WebReportActivity).
class NotepadSyncActivity final : public Activity {
 public:
  NotepadSyncActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : Activity("NotepadSync", renderer, mappedInput) {}

  void onEnter() override;
  void onExit() override;
  void loop() override;
  void render(RenderLock&&) override;
  bool preventAutoSleep() override { return apStarted; }
  bool skipLoopDelay() override { return apStarted; }

 private:
  void startPortal();
  void serveEditor();  // GET: textarea prefilled with /notes.txt (also captive catch-all)
  void handleSave();   // POST: write the textarea back to /notes.txt
  void rebootToFreeHeap(const char* msg);

  std::unique_ptr<WebServer> server;
  std::unique_ptr<DNSServer> dns;
  bool apStarted = false;
  std::string apIp;
  std::string joinPayload;  // WIFI:... QR payload
  int saveCount = 0;        // saves performed this session (shown on-device)
};
