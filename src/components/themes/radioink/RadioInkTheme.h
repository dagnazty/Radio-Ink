#pragma once

#include "components/themes/lyra/LyraTheme.h"

class GfxRenderer;

// Radio Ink theme: Lyra look + the Radio Hell skull stamped on every page
// (drawn in drawButtonHints, the last call before displayBuffer, so body
// content never covers it). Pages that opt out via
// UITheme::suppressBrandLogoOnce() — e.g. the Radio Ink data/log views — and
// the book reading view (which has no button hints) get no logo.
class RadioInkTheme : public LyraTheme {
 public:
  void drawButtonHints(GfxRenderer& renderer, const char* btn1, const char* btn2, const char* btn3,
                       const char* btn4) const override;
  // Hacker x hiphop: inverted selection bar + "> " prompt marker + bold.
  void drawButtonMenu(GfxRenderer& renderer, Rect rect, int buttonCount, int selectedIndex,
                      const std::function<std::string(int index)>& buttonLabel,
                      const std::function<UIIcon(int index)>& rowIcon) const override;
  // Bracketed brand/title (top-left) + heavy rule, keeping the clock/battery.
  void drawHeader(const GfxRenderer& renderer, Rect rect, const char* title, const char* subtitle) const override;
  // Inverted "> " selection bar for lists (settings, Radio Ink categories, etc.).
  void drawList(const GfxRenderer& renderer, Rect rect, int itemCount, int selectedIndex,
                const std::function<std::string(int index)>& rowTitle,
                const std::function<std::string(int index)>& rowSubtitle,
                const std::function<UIIcon(int index)>& rowIcon, const std::function<std::string(int index)>& rowValue,
                bool highlightValue, const std::function<bool(int index)>& rowDimmed = nullptr) const override;
  // Inverted black active tab (sharp, white bold) instead of the gray box.
  void drawTabBar(const GfxRenderer& renderer, Rect rect, const std::vector<TabInfo>& tabs,
                  bool selected) const override;
};
