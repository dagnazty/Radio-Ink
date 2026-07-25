#pragma once

#include <GfxRenderer.h>

#include <string>

#include "activities/util/ToolActivityBase.h"

// Type any text and see it as a full-screen, scannable QR code -- for quickly
// sharing a WiFi PSK, a URL, or anything else, separate from Badge's fixed one.
class QrGenActivity final : public ToolActivityBase {
 public:
  QrGenActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : ToolActivityBase("QrGen", renderer, mappedInput, ToolItem::QR_GEN) {}

  void onEnter() override;
  void loop() override;
  void render(RenderLock&&) override;

 private:
  std::string text;

  void promptText();
};
