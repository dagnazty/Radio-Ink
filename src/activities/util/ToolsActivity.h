#pragma once

#include <GfxRenderer.h>

#include "activities/Activity.h"
#include "activities/ActivityManager.h"  // ToolItem
#include "util/ButtonNavigator.h"

// The "Tools" submenu off the home screen: groups the small utility apps
// (Notepad, Badge, Authenticator, Clock) so the home menu stays short. Picking a
// row launches that tool; the tool's Back returns here with the row preselected.
class ToolsActivity final : public Activity {
 public:
  ToolsActivity(GfxRenderer& renderer, MappedInputManager& mappedInput, ToolItem initial = ToolItem::NONE);

  void onEnter() override;
  void loop() override;
  void render(RenderLock&&) override;

 private:
  ButtonNavigator buttonNavigator;
  int selected = 0;

  void launch(int idx);
};
