#include "BootActivity.h"

#include <GfxRenderer.h>
#include <I18n.h>

#include "fontIds.h"
#include "images/Logo240.h"

void BootActivity::onEnter() {
  Activity::onEnter();

  const auto pageWidth = renderer.getScreenWidth();
  const auto pageHeight = renderer.getScreenHeight();

  renderer.clearScreen();
  renderer.drawImage(Logo240, (pageWidth - 240) / 2, (pageHeight - 240) / 2, 240, 240);
  renderer.drawCenteredText(UI_10_FONT_ID, pageHeight / 2 + 135, tr(STR_RADIOINK), true, EpdFontFamily::BOLD);
  renderer.drawCenteredText(SMALL_FONT_ID, pageHeight / 2 + 160, tr(STR_BOOTING));
  renderer.drawCenteredText(SMALL_FONT_ID, pageHeight - 30, RADIOINK_VERSION);
  renderer.displayBuffer();
}
