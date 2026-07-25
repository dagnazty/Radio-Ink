#include "HashCalcActivity.h"

#include <GfxRenderer.h>
#include <I18n.h>
#include <mbedtls/md.h>

#include <cstdio>

#include "MappedInputManager.h"
#include "activities/ActivityResult.h"
#include "activities/util/KeyboardEntryActivity.h"
#include "components/UITheme.h"
#include "fontIds.h"

namespace {
std::string digestHex(mbedtls_md_type_t type, const std::string& text) {
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(type);
  if (!info) return "";
  uint8_t out[32];  // SHA-256 is the largest digest used here
  if (mbedtls_md(info, reinterpret_cast<const uint8_t*>(text.data()), text.size(), out) != 0) return "";
  char hex[65];
  const int n = mbedtls_md_get_size(info);
  for (int i = 0; i < n; i++) snprintf(hex + i * 2, 3, "%02x", out[i]);
  return std::string(hex, static_cast<size_t>(n) * 2);
}
}  // namespace

void HashCalcActivity::onEnter() {
  Activity::onEnter();
  recompute();
  requestUpdate();
}

void HashCalcActivity::recompute() {
  md5Hex = digestHex(MBEDTLS_MD_MD5, input);
  sha1Hex = digestHex(MBEDTLS_MD_SHA1, input);
  sha256Hex = digestHex(MBEDTLS_MD_SHA256, input);
}

void HashCalcActivity::promptInput() {
  startActivityForResult(
      std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, tr(STR_TEXT_TO_HASH), input, 200, InputType::Text),
      [this](const ActivityResult& result) {
        if (!result.isCancelled) {
          input = std::get<KeyboardResult>(result.data).text;
          recompute();
        }
        requestUpdate();
      });
}

void HashCalcActivity::loop() {
  using Button = MappedInputManager::Button;
  if (handleToolBack()) {
    return;
  }
  if (mappedInput.wasPressed(Button::Confirm) || mappedInput.wasPressed(Button::Right)) {
    promptInput();
  }
}

void HashCalcActivity::render(RenderLock&&) {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto W = renderer.getScreenWidth();
  const auto H = renderer.getScreenHeight();
  beginToolRender(tr(STR_HASH_CALC));
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;

  const int x = metrics.contentSidePadding;
  const int lineH = renderer.getLineHeight(UI_10_FONT_ID);
  int y = contentTop;

  if (input.empty()) {
    UITheme::drawCenteredText(renderer, Rect{0, contentTop, W, static_cast<int>(H) - contentTop}, UI_10_FONT_ID,
                              contentTop + lineH, tr(STR_HASH_ENTER_HINT));
  } else {
    std::string shown = input.size() > 40 ? input.substr(0, 37) + "..." : input;
    renderer.drawText(UI_10_FONT_ID, x, y, (std::string(tr(STR_TEXT_PREFIX)) + shown).c_str(), true,
                      EpdFontFamily::BOLD);
    y += lineH + 10;

    renderer.drawText(UI_10_FONT_ID, x, y, "MD5:", true, EpdFontFamily::BOLD);
    y += lineH;
    renderer.drawText(UI_10_FONT_ID, x, y, md5Hex.c_str(), true);
    y += lineH + 8;

    renderer.drawText(UI_10_FONT_ID, x, y, "SHA-1:", true, EpdFontFamily::BOLD);
    y += lineH;
    renderer.drawText(UI_10_FONT_ID, x, y, sha1Hex.c_str(), true);
    y += lineH + 8;

    renderer.drawText(UI_10_FONT_ID, x, y, "SHA-256:", true, EpdFontFamily::BOLD);
    y += lineH;
    // Split the 64-char digest across two lines, but guard substr(32): a short/empty
    // string (mbedtls failure) would make substr(32) throw, which aborts under -fno-exceptions.
    renderer.drawText(UI_10_FONT_ID, x, y, sha256Hex.substr(0, 32).c_str(), true);
    y += lineH;
    if (sha256Hex.size() > 32) {
      renderer.drawText(UI_10_FONT_ID, x, y, sha256Hex.substr(32).c_str(), true);
    }
  }

  endToolRender(tr(STR_BTN_BACK), tr(STR_ENTER_TEXT), "", "");
}
