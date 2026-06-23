#pragma once

#include "activities/Activity.h"

// Simple "About Radio Ink" screen reached from the home menu: version + credits.
// Back (or Confirm) returns home.
class AboutActivity final : public Activity {
 public:
  explicit AboutActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : Activity("About", renderer, mappedInput) {}

  void onEnter() override;
  void loop() override;
  void render(RenderLock&&) override;
};
