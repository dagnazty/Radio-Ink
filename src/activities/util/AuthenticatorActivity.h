#pragma once

#include <GfxRenderer.h>

#include <cstdint>
#include <string>
#include <vector>

#include "activities/util/ToolActivityBase.h"
#include "util/ButtonNavigator.h"

// On-device TOTP authenticator (RFC 6238): stores base32 secrets and generates
// 6-digit time-based codes via mbedtls HMAC-SHA1, using the DS3231 RTC for time
// (set it first with Radio Ink → Network → NTP Time Sync). Secrets live in a
// readable `/totp.txt`, one "label:BASE32SECRET" per line (the label is split off
// at the last ':', so labels may themselves contain colons).
class AuthenticatorActivity final : public ToolActivityBase {
 public:
  AuthenticatorActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : ToolActivityBase("Authenticator", renderer, mappedInput, ToolItem::AUTHENTICATOR) {}

  void onEnter() override;
  void onExit() override;
  void loop() override;
  void render(RenderLock&&) override;

 private:
  struct Entry {
    std::string label;
    std::string secret;  // base32, as stored
    std::string code;    // current 6-digit code ("------" if no valid time)
  };

  std::vector<Entry> entries;
  int selected = 0;
  bool haveTime = false;     // RTC produced a valid epoch on the last refresh
  uint32_t lastPeriod = 0;   // epoch/30 of the last code computation
  uint32_t lastCheckMs = 0;  // millis() of the last RTC poll (throttles I2C reads)
  int secondsLeft = 0;       // seconds until the current codes roll over
  bool menuOpen = false;     // per-entry action menu (Delete)
  int menuSel = 0;
  bool dirty = false;
  ButtonNavigator buttonNavigator;  // per-instance: no latched state across entries

  // Pending add: label captured, secret keyboard next.
  std::string pendingLabel;

  void load();
  void save();
  void refreshCodes(bool force);  // recompute all codes if the 30s window changed
  void addEntry();                // chained keyboard: label then secret
  void deleteEntry(int idx);

  // Returns the 6-digit code for a base32 secret at the given epoch, or false.
  static bool computeTotp(const std::string& base32Secret, uint32_t epoch, char out[7]);
  static int base32Decode(const std::string& in, uint8_t* out, int outCap);

  void renderList();
  void renderMenu();
};
