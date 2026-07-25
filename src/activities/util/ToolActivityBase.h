#pragma once

#include <GfxRenderer.h>

#include <string>

#include "activities/Activity.h"
#include "activities/ActivityManager.h"   // ToolItem
#include "components/themes/BaseTheme.h"  // Rect

// Shared chrome + back-navigation for the small "tools" utilities (Notepad, Badge,
// Authenticator, Clock, Password Gen, Hash Calculator, Encode/Decode, QR Generator).
//
// Each tool still owns its own content drawing and input handling; this base only
// removes the boilerplate every tool repeated verbatim:
//   - Back → return to the Tools submenu with this tool's row preselected.
//   - clearScreen + header at the top of render().
//   - brand-logo suppression + mapped button hints + displayBuffer at the end.
//   - the content rectangle between the header and the hint bar.
class ToolActivityBase : public Activity {
 public:
  ToolActivityBase(std::string name, GfxRenderer& renderer, MappedInputManager& mappedInput, ToolItem item)
      : Activity(std::move(name), renderer, mappedInput), toolItem(item) {}

 protected:
  const ToolItem toolItem;

  // If Back was pressed, navigate to the Tools menu (this tool preselected) and
  // return true so the caller can early-out. Returns false otherwise.
  bool handleToolBack();

  // Rectangle available for content, between the header and the button-hint bar.
  Rect toolContentRect() const;

  // clearScreen + draw the header. Call at the top of render().
  void beginToolRender(const char* title, const char* subtitle = nullptr);

  // Suppress the home-screen brand logo for this frame, draw mapped button hints,
  // then flush the buffer. Call at the end of render().
  void endToolRender(const char* back, const char* confirm, const char* previous, const char* next,
                     HalDisplay::RefreshMode mode = HalDisplay::FAST_REFRESH);
};
