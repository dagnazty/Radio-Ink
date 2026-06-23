#include "AboutActivity.h"

#include <Arduino.h>
#include <GfxRenderer.h>
#include <HalGPIO.h>

#include <cstdio>

#include "MappedInputManager.h"
#include "components/UITheme.h"
#include "fontIds.h"

#ifndef RADIOINK_VERSION
#define RADIOINK_VERSION "dev"
#endif

void AboutActivity::onEnter() {
  Activity::onEnter();
  requestUpdate();
}

void AboutActivity::loop() {
  if (mappedInput.wasPressed(MappedInputManager::Button::Back) ||
      mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
    onGoHome();
  }
}

void AboutActivity::render(RenderLock&&) {
  const auto& m = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  renderer.clearScreen();

  GUI.drawHeader(renderer, Rect{0, m.topPadding, pageWidth, m.headerHeight}, "About Radio Ink");

  int y = m.topPadding + m.headerHeight + m.verticalSpacing * 2;
  const int x = m.contentSidePadding;
  auto line = [&](const char* text, int fontId, bool bold = false, int extra = 4) {
    renderer.drawText(fontId, x, y, text, true, bold ? EpdFontFamily::BOLD : EpdFontFamily::REGULAR);
    y += renderer.getLineHeight(fontId) + extra;
  };

  line("Radio Ink", UI_12_FONT_ID, true);
  line("Version: " RADIOINK_VERSION, SMALL_FONT_ID, false, 12);
  line("Created by dag nazty", UI_12_FONT_ID, true);
  line("https://dagnazty.dev", SMALL_FONT_ID, false, 12);
  line("RF audit / pentest firmware", SMALL_FONT_ID);
  line("for the Xteink X-series (ESP32-C3).", SMALL_FONT_ID);
  line("Authorized testing only.", SMALL_FONT_ID, false, 12);

  char diag[48];
  snprintf(diag, sizeof(diag), "Device: %s   Free heap: %u KB", gpio.deviceIsX3() ? "X3" : "X4",
           static_cast<unsigned>(ESP.getFreeHeap() / 1024));
  line(diag, SMALL_FONT_ID);

  const auto labels = mappedInput.mapLabels("Back", "", "", "");
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}
