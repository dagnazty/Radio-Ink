#include "PasswordGenActivity.h"

#include <GfxRenderer.h>
#include <I18n.h>
#include <esp_random.h>

#include <cmath>
#include <cstdio>
#include <cstring>

#include "MappedInputManager.h"
#include "components/UITheme.h"
#include "fontIds.h"

namespace {
constexpr const char* SET_LETTERS_DIGITS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
constexpr const char* SET_LETTERS_DIGITS_SYMBOLS =
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+";
constexpr const char* SET_DIGITS = "0123456789";
}  // namespace

void PasswordGenActivity::onEnter() {
  Activity::onEnter();
  regenerate();
  requestUpdate();
}

const char* PasswordGenActivity::charsetLabel() const {
  switch (charset) {
    case Charset::LettersDigits:
      return tr(STR_PW_LETTERS_DIGITS);
    case Charset::LettersDigitsSymbols:
      return tr(STR_PW_LETTERS_DIGITS_SYMBOLS);
    default:
      return tr(STR_PW_DIGITS_ONLY);
  }
}

double PasswordGenActivity::entropyBits() const {
  const char* set = charset == Charset::LettersDigits ? SET_LETTERS_DIGITS
                    : charset == Charset::DigitsOnly  ? SET_DIGITS
                                                      : SET_LETTERS_DIGITS_SYMBOLS;
  return length * (std::log(static_cast<double>(strlen(set))) / std::log(2.0));
}

void PasswordGenActivity::regenerate() {
  const char* set = charset == Charset::LettersDigits ? SET_LETTERS_DIGITS
                    : charset == Charset::DigitsOnly  ? SET_DIGITS
                                                      : SET_LETTERS_DIGITS_SYMBOLS;
  const size_t setLen = strlen(set);
  generated.clear();
  generated.reserve(length);
  for (int i = 0; i < length; i++) generated += set[esp_random() % setLen];
}

void PasswordGenActivity::loop() {
  using Button = MappedInputManager::Button;

  if (handleToolBack()) {
    return;
  }
  if (mappedInput.wasPressed(Button::Confirm)) {
    regenerate();
    requestUpdate();
    return;
  }
  if (mappedInput.wasPressed(Button::Up) && length < MAX_LEN) {
    length++;
    regenerate();
    requestUpdate();
    return;
  }
  if (mappedInput.wasPressed(Button::Down) && length > MIN_LEN) {
    length--;
    regenerate();
    requestUpdate();
    return;
  }
  if (mappedInput.wasPressed(Button::Left) || mappedInput.wasPressed(Button::Right)) {
    const int dir = mappedInput.wasPressed(Button::Right) ? 1 : -1;
    const int n = static_cast<int>(Charset::COUNT);
    charset = static_cast<Charset>((static_cast<int>(charset) + dir + n) % n);
    regenerate();
    requestUpdate();
  }
}

void PasswordGenActivity::render(RenderLock&&) {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto W = renderer.getScreenWidth();
  const auto H = renderer.getScreenHeight();

  char sub[24];
  snprintf(sub, sizeof(sub), tr(STR_PW_CHARS_FMT), length);
  beginToolRender(tr(STR_PASSWORD_GEN), sub);

  const int midY = static_cast<int>(H) / 2;
  // Word-wrap the generated string across a couple of lines at a fixed font so
  // longer passphrases (up to MAX_LEN chars) still fit the screen width.
  constexpr int GEN_FONT_ID = NOTOSANS_16_FONT_ID;
  const int maxW = static_cast<int>(W) - 2 * metrics.contentSidePadding;
  std::string line1 = generated, line2;
  while (!line1.empty() && renderer.getTextWidth(GEN_FONT_ID, line1.c_str()) > maxW) {
    line2 = line1.back() + line2;
    line1.pop_back();
  }
  const int lineH = renderer.getLineHeight(GEN_FONT_ID);
  const int genY = line2.empty() ? midY - lineH : midY - lineH * 3 / 2;
  renderer.drawCenteredText(GEN_FONT_ID, genY, line1.c_str(), true, EpdFontFamily::BOLD);
  if (!line2.empty()) renderer.drawCenteredText(GEN_FONT_ID, genY + lineH, line2.c_str(), true, EpdFontFamily::BOLD);

  char info[48];
  snprintf(info, sizeof(info), tr(STR_PW_INFO_FMT), charsetLabel(), static_cast<int>(entropyBits()));
  renderer.drawCenteredText(UI_10_FONT_ID, midY + lineH * 2, info, true);
  renderer.drawCenteredText(UI_10_FONT_ID, midY + lineH * 2 + renderer.getLineHeight(UI_10_FONT_ID) + 6,
                            tr(STR_PW_HINT), true);

  endToolRender(tr(STR_BTN_BACK), tr(STR_NEW), tr(STR_CHARSET), tr(STR_CHARSET));
}
