#include "QrGenActivity.h"

#include <GfxRenderer.h>
#include <I18n.h>

#include <algorithm>

#include "MappedInputManager.h"
#include "activities/ActivityResult.h"
#include "activities/util/KeyboardEntryActivity.h"
#include "components/UITheme.h"
#include "fontIds.h"
#include "util/QrUtils.h"

void QrGenActivity::onEnter() {
  Activity::onEnter();
  if (text.empty()) {
    promptText();
  } else {
    requestUpdate();
  }
}

void QrGenActivity::promptText() {
  startActivityForResult(
      std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, tr(STR_QR_TEXT), text, 200, InputType::Text, true),
      [this](const ActivityResult& result) {
        if (!result.isCancelled) {
          const auto& kb = std::get<KeyboardResult>(result.data);
          if (!kb.text.empty()) text = kb.text;
        } else if (text.empty()) {
          activityManager.goToTools(toolItem);
          return;
        }
        requestUpdate();
      });
}

void QrGenActivity::loop() {
  using Button = MappedInputManager::Button;
  if (handleToolBack()) {
    return;
  }
  if (mappedInput.wasPressed(Button::Confirm) || mappedInput.wasPressed(Button::Right)) {
    promptText();
  }
}

void QrGenActivity::render(RenderLock&&) {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto W = renderer.getScreenWidth();
  const auto H = renderer.getScreenHeight();
  renderer.clearScreen();

  if (text.empty()) {
    UITheme::drawCenteredText(renderer, Rect{0, 0, W, H}, UI_10_FONT_ID, static_cast<int>(H) / 2,
                              tr(STR_QR_PRESS_TEXT));
    endToolRender(tr(STR_BTN_BACK), tr(STR_ENTER_TEXT), "", "");
    return;
  }

  const int top = metrics.topPadding + metrics.verticalSpacing;
  const int avail = static_cast<int>(H) - top - metrics.buttonHintsHeight - metrics.verticalSpacing;
  const int qrSize = std::min(static_cast<int>(W) - metrics.contentSidePadding * 2, avail);
  QrUtils::drawQrCode(renderer, Rect{(static_cast<int>(W) - qrSize) / 2, top, qrSize, qrSize}, text);

  // Full refresh: a partial/fast refresh ghosts the QR so phones can't decode it.
  endToolRender(tr(STR_BTN_BACK), tr(STR_NEW_TEXT), "", "", HalDisplay::FULL_REFRESH);
}
