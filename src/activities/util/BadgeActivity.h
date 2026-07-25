#pragma once

#include <GfxRenderer.h>

#include <string>

#include "activities/util/ToolActivityBase.h"
#include "util/ButtonNavigator.h"

// Digital badge: a full-screen identity card — Radio Ink skull, a big name/handle,
// a subtitle (role/affiliation), and a scannable QR carrying a URL or contact.
// Press Left for a full-screen QR (easy to scan); Confirm to edit the fields.
// Config persists to a readable `/badge.txt` (name / subtitle / QR on three lines).
//
// (The C3 has no NFC radio, so the QR stands in for a tap — a phone scans it.)
class BadgeActivity final : public ToolActivityBase {
 public:
  BadgeActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : ToolActivityBase("Badge", renderer, mappedInput, ToolItem::BADGE) {}

  void onEnter() override;
  void onExit() override;
  void loop() override;
  void render(RenderLock&&) override;

 private:
  std::string name;
  std::string subtitle;
  std::string qr;  // URL, or a vCard/MECARD contact string

  bool bigQr = false;     // full-screen QR mode for easy scanning
  bool menuOpen = false;  // edit menu overlay
  int menuSel = 0;
  bool dirty = false;
  ButtonNavigator buttonNavigator;  // per-instance: no latched state across entries

  void load();
  void save();
  void editField(int which);  // 0 name, 1 subtitle, 2 QR
  void renderBadge();
  void renderBigQr();
  void renderMenu();
};
