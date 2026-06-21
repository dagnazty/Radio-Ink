#include "RadioInkTheme.h"

#include <GfxRenderer.h>
#include <HalClock.h>

#include <string>

#include "RadioInkSettings.h"
#include "components/UITheme.h"
#include "components/themes/lyra/LyraTheme.h"
#include "fontIds.h"
#include "images/RadioInkSkull.h"

void RadioInkTheme::drawButtonHints(GfxRenderer& renderer, const char* btn1, const char* btn2, const char* btn3,
                                    const char* btn4) const {
  LyraTheme::drawButtonHints(renderer, btn1, btn2, btn3, btn4);

  // One-shot opt-out for data/log views; consumed (reset) every call.
  if (UITheme::getInstance().consumeBrandLogoSuppressed()) return;

  const ThemeMetrics& m = UITheme::getInstance().getMetrics();
  const int x = renderer.getScreenWidth() - RADIOINK_SKULL_WIDTH - m.contentSidePadding / 2;
  const int y = renderer.getScreenHeight() - m.buttonHintsHeight - m.verticalSpacing - RADIOINK_SKULL_HEIGHT;
  renderer.drawImage(RadioInkSkull, x, y, RADIOINK_SKULL_WIDTH, RADIOINK_SKULL_HEIGHT);
}

void RadioInkTheme::drawHeader(const GfxRenderer& renderer, Rect rect, const char* title, const char* subtitle) const {
  renderer.fillRect(rect.x, rect.y, rect.width, rect.height, false);
  const int pad = LyraMetrics::values.contentSidePadding;

  // Battery + clock (top-right), driven by the device-wide Status Bar settings.
  const bool showBattery = SETTINGS.statusBarBattery;
  const bool showBatteryPercentage =
      SETTINGS.hideBatteryPercentage != RadioInkSettings::HIDE_BATTERY_PERCENTAGE::HIDE_ALWAYS;
  const int batteryX = rect.x + rect.width - 12 - LyraMetrics::values.batteryWidth;
  if (showBattery) {
    drawBatteryRight(renderer,
                     Rect{batteryX, rect.y + 5, LyraMetrics::values.batteryWidth, LyraMetrics::values.batteryHeight},
                     showBatteryPercentage);
  }
  int rightReserve = showBattery ? 60 : 20;
  if (SETTINGS.statusBarClock && halClock.isAvailable()) {
    char timeBuf[10];
    if (halClock.formatTime(timeBuf, sizeof(timeBuf), SETTINGS.clockUtcOffsetQ, SETTINGS.clockFormat == 1)) {
      const int clockWidth = renderer.getTextWidth(SMALL_FONT_ID, timeBuf);
      const int anchor = showBattery ? (batteryX - 50) : (rect.x + rect.width - pad);
      renderer.drawText(SMALL_FONT_ID, anchor - clockWidth, rect.y + 7, timeBuf);
      rightReserve += clockWidth + 12;
    }
  }

  // Bracketed brand/title, top-left, bold. Home (no title) shows the brand.
  const std::string brand = std::string("[ ") + (title ? title : "RADIO INK") + " ]";
  const int maxW = rect.width - pad * 2 - rightReserve;
  const auto shown = renderer.truncatedText(UI_12_FONT_ID, brand.c_str(), maxW, EpdFontFamily::BOLD);
  renderer.drawText(UI_12_FONT_ID, rect.x + pad, rect.y + 7, shown.c_str(), true, EpdFontFamily::BOLD);

  // Heavy rule under the header band.
  renderer.drawLine(rect.x, rect.y + rect.height - 3, rect.x + rect.width - 1, rect.y + rect.height - 3, 3, true);

  if (subtitle) {
    const auto ts = renderer.truncatedText(SMALL_FONT_ID, subtitle, rect.width - pad * 2, EpdFontFamily::REGULAR);
    const int tw = renderer.getTextWidth(SMALL_FONT_ID, ts.c_str());
    renderer.drawText(SMALL_FONT_ID, rect.x + rect.width - pad - tw, rect.y + 32, ts.c_str(), true);
  }
}

void RadioInkTheme::drawButtonMenu(GfxRenderer& renderer, Rect rect, int buttonCount, int selectedIndex,
                                   const std::function<std::string(int index)>& buttonLabel,
                                   const std::function<UIIcon(int index)>& /*rowIcon*/) const {
  const ThemeMetrics& m = LyraMetrics::values;
  const int lineHeight = renderer.getLineHeight(UI_12_FONT_ID);
  for (int i = 0; i < buttonCount; ++i) {
    const int rowY = rect.y + i * (m.menuRowHeight + m.menuSpacing);
    const int rowX = rect.x + m.contentSidePadding;
    const int rowW = rect.width - m.contentSidePadding * 2;
    const bool selected = (selectedIndex == i);

    if (selected) renderer.fillRect(rowX, rowY, rowW, m.menuRowHeight, true);  // inverted block

    const std::string label = std::string(selected ? "> " : "  ") + buttonLabel(i);
    const int textY = rowY + (m.menuRowHeight - lineHeight) / 2;
    // White ink on the inverted bar, black ink otherwise; bold for the hiphop weight.
    renderer.drawText(UI_12_FONT_ID, rowX + 12, textY, label.c_str(), !selected, EpdFontFamily::BOLD);
  }
}

void RadioInkTheme::drawTabBar(const GfxRenderer& renderer, Rect rect, const std::vector<TabInfo>& tabs,
                              bool /*selected*/) const {
  constexpr int HPAD = 8;
  int x = rect.x + LyraMetrics::values.contentSidePadding;
  for (const auto& tab : tabs) {
    const int textWidth = renderer.getTextWidth(UI_10_FONT_ID, tab.label, EpdFontFamily::BOLD);
    const int boxW = textWidth + 2 * HPAD;
    if (tab.selected) renderer.fillRect(x, rect.y, boxW, rect.height - 3, true);  // inverted black, sharp
    renderer.drawText(UI_10_FONT_ID, x + HPAD, rect.y + 6, tab.label, !tab.selected, EpdFontFamily::BOLD);
    x += boxW + LyraMetrics::values.tabSpacing;
  }
  // Heavy rule under the tab bar.
  renderer.drawLine(rect.x, rect.y + rect.height - 1, rect.x + rect.width - 1, rect.y + rect.height - 1, 2, true);
}

void RadioInkTheme::drawList(const GfxRenderer& renderer, Rect rect, int itemCount, int selectedIndex,
                             const std::function<std::string(int index)>& rowTitle,
                             const std::function<std::string(int index)>& rowSubtitle,
                             const std::function<UIIcon(int index)>& /*rowIcon*/,
                             const std::function<std::string(int index)>& rowValue, bool /*highlightValue*/,
                             const std::function<bool(int index)>& rowDimmed) const {
  const ThemeMetrics& m = LyraMetrics::values;
  constexpr int HPAD = 8;
  constexpr int MAX_VALUE_W = 200;
  const int rowHeight = (rowSubtitle != nullptr) ? m.listWithSubtitleRowHeight : m.listRowHeight;
  const int pageItems = rect.height / rowHeight;
  if (pageItems <= 0) return;
  const int totalPages = (itemCount + pageItems - 1) / pageItems;

  int contentWidth = rect.width - 1;
  if (totalPages > 1) {
    const int scrollBarHeight = (rect.height * pageItems) / itemCount;
    const int currentPage = selectedIndex / pageItems;
    const int scrollBarY = rect.y + ((rect.height - scrollBarHeight) * currentPage) / (totalPages - 1);
    const int scrollBarX = rect.x + rect.width - m.scrollBarRightOffset;
    renderer.drawLine(scrollBarX, rect.y, scrollBarX, rect.y + rect.height, true);
    renderer.fillRect(scrollBarX - m.scrollBarWidth, scrollBarY, m.scrollBarWidth, scrollBarHeight, true);
    contentWidth = rect.width - (m.scrollBarWidth + m.scrollBarRightOffset);
  }

  // Inverted selection bar (sharp black) instead of the gray rounded box.
  if (selectedIndex >= 0) {
    const int sy = rect.y + (selectedIndex % pageItems) * rowHeight;
    renderer.fillRect(rect.x + m.contentSidePadding, sy, contentWidth - m.contentSidePadding * 2, rowHeight, true);
  }

  const int textX = rect.x + m.contentSidePadding + HPAD;
  const int pageStartIndex = selectedIndex / pageItems * pageItems;
  for (int i = pageStartIndex; i < itemCount && i < pageStartIndex + pageItems; i++) {
    const int itemY = rect.y + (i % pageItems) * rowHeight;
    const bool sel = (i == selectedIndex);
    int rowTextWidth = contentWidth - m.contentSidePadding * 2 - HPAD * 2;

    int valueWidth = 0;
    std::string valueText;
    if (rowValue != nullptr) {
      valueText = renderer.truncatedText(UI_10_FONT_ID, rowValue(i).c_str(), MAX_VALUE_W);
      valueWidth = renderer.getTextWidth(UI_10_FONT_ID, valueText.c_str());
      rowTextWidth -= valueWidth + HPAD;
    }

    const std::string label = std::string(sel ? "> " : "") + rowTitle(i);
    const auto item = renderer.truncatedText(UI_10_FONT_ID, label.c_str(), rowTextWidth);
    renderer.drawText(UI_10_FONT_ID, textX, itemY + 7, item.c_str(), !sel,
                      sel ? EpdFontFamily::BOLD : EpdFontFamily::REGULAR);

    if (rowDimmed && rowDimmed(i) && !sel) {
      const int titleWidth = renderer.getTextWidth(UI_10_FONT_ID, item.c_str());
      const int lineH = renderer.getLineHeight(UI_10_FONT_ID);
      for (int py = itemY + 7; py < itemY + 7 + lineH; py++)
        for (int px = textX; px < textX + titleWidth; px++)
          if ((px + py) % 2 == 0) renderer.drawPixel(px, py, false);
    }

    if (rowSubtitle != nullptr) {
      const auto sub = renderer.truncatedText(SMALL_FONT_ID, rowSubtitle(i).c_str(), rowTextWidth);
      renderer.drawText(SMALL_FONT_ID, textX, itemY + 30, sub.c_str(), !sel);
    }

    if (!valueText.empty()) {
      const int valueY = (rowSubtitle != nullptr) ? itemY + 16 : itemY + 6;
      renderer.drawText(UI_10_FONT_ID, rect.x + contentWidth - m.contentSidePadding - valueWidth, valueY,
                        valueText.c_str(), !sel);
    }
  }
}
