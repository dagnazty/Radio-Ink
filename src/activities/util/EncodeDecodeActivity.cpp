#include "EncodeDecodeActivity.h"

#include <GfxRenderer.h>
#include <I18n.h>
#include <Memory.h>
#include <mbedtls/base64.h>

#include <cctype>
#include <cstdio>

#include "MappedInputManager.h"
#include "activities/ActivityResult.h"
#include "activities/util/KeyboardEntryActivity.h"
#include "components/UITheme.h"
#include "fontIds.h"

namespace {
int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

std::string hexEncode(const std::string& s) {
  std::string out;
  out.reserve(s.size() * 2);
  char b[3];
  for (unsigned char c : s) {
    snprintf(b, sizeof(b), "%02x", c);
    out += b;
  }
  return out;
}

bool hexDecode(const std::string& s, std::string& out) {
  out.clear();
  if (s.empty() || s.size() % 2 != 0) return false;
  out.reserve(s.size() / 2);
  for (size_t i = 0; i < s.size(); i += 2) {
    const int h = hexVal(s[i]), l = hexVal(s[i + 1]);
    if (h < 0 || l < 0) return false;
    out += static_cast<char>((h << 4) | l);
  }
  return true;
}

std::string urlEncode(const std::string& s) {
  std::string out;
  out.reserve(s.size() * 3);
  char b[4];
  for (unsigned char c : s) {
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      out += static_cast<char>(c);
    } else {
      snprintf(b, sizeof(b), "%%%02X", c);
      out += b;
    }
  }
  return out;
}

bool urlDecode(const std::string& s, std::string& out) {
  out.clear();
  out.reserve(s.size());
  for (size_t i = 0; i < s.size(); i++) {
    if (s[i] == '%') {
      if (i + 2 >= s.size()) return false;
      const int h = hexVal(s[i + 1]), l = hexVal(s[i + 2]);
      if (h < 0 || l < 0) return false;
      out += static_cast<char>((h << 4) | l);
      i += 2;
    } else {
      out += s[i];
    }
  }
  return true;
}

bool base64Encode(const std::string& s, std::string& out) {
  const size_t cap = ((s.size() + 2) / 3) * 4 + 4;
  auto buf = makeUniqueNoThrow<uint8_t[]>(cap);
  if (!buf) return false;
  size_t olen = 0;
  if (mbedtls_base64_encode(buf.get(), cap, &olen, reinterpret_cast<const uint8_t*>(s.data()), s.size()) != 0)
    return false;
  out.assign(reinterpret_cast<char*>(buf.get()), olen);
  return true;
}

bool base64Decode(const std::string& s, std::string& out) {
  const size_t cap = s.size() + 4;
  auto buf = makeUniqueNoThrow<uint8_t[]>(cap);
  if (!buf) return false;
  size_t olen = 0;
  if (mbedtls_base64_decode(buf.get(), cap, &olen, reinterpret_cast<const uint8_t*>(s.data()), s.size()) != 0)
    return false;
  out.assign(reinterpret_cast<char*>(buf.get()), olen);
  return true;
}

// Greedy width-based wrap for a monospace-ish utility readout; returns the y
// position after the last drawn line.
int drawWrapped(GfxRenderer& renderer, int x, int y, int maxW, int lineH, const std::string& text) {
  std::string remaining = text;
  while (!remaining.empty()) {
    std::string line = remaining;
    while (line.size() > 1 && renderer.getTextWidth(UI_10_FONT_ID, line.c_str()) > maxW) line.pop_back();
    renderer.drawText(UI_10_FONT_ID, x, y, line.c_str(), true);
    y += lineH;
    remaining = remaining.substr(line.size());
  }
  return y;
}
}  // namespace

void EncodeDecodeActivity::onEnter() {
  Activity::onEnter();
  recompute();
  requestUpdate();
}

const char* EncodeDecodeActivity::modeLabel() const {
  switch (mode) {
    case Mode::Base64Encode:
      return tr(STR_ED_B64_ENCODE);
    case Mode::Base64Decode:
      return tr(STR_ED_B64_DECODE);
    case Mode::HexEncode:
      return tr(STR_ED_HEX_ENCODE);
    case Mode::HexDecode:
      return tr(STR_ED_HEX_DECODE);
    case Mode::UrlEncode:
      return tr(STR_ED_URL_ENCODE);
    default:
      return tr(STR_ED_URL_DECODE);
  }
}

void EncodeDecodeActivity::recompute() {
  outputValid = true;
  switch (mode) {
    case Mode::Base64Encode:
      outputValid = base64Encode(input, output);
      break;
    case Mode::Base64Decode:
      outputValid = base64Decode(input, output);
      break;
    case Mode::HexEncode:
      output = hexEncode(input);
      break;
    case Mode::HexDecode:
      outputValid = hexDecode(input, output);
      break;
    case Mode::UrlEncode:
      output = urlEncode(input);
      break;
    default:
      outputValid = urlDecode(input, output);
      break;
  }
  if (!outputValid) output.clear();
}

void EncodeDecodeActivity::promptInput() {
  startActivityForResult(
      std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, tr(STR_INPUT_TEXT), input, 200, InputType::Text),
      [this](const ActivityResult& result) {
        if (!result.isCancelled) {
          input = std::get<KeyboardResult>(result.data).text;
          recompute();
        }
        requestUpdate();
      });
}

void EncodeDecodeActivity::loop() {
  using Button = MappedInputManager::Button;
  if (handleToolBack()) {
    return;
  }
  if (mappedInput.wasPressed(Button::Confirm)) {
    promptInput();
    return;
  }
  if (mappedInput.wasPressed(Button::Left) || mappedInput.wasPressed(Button::Right)) {
    const int dir = mappedInput.wasPressed(Button::Right) ? 1 : -1;
    const int n = static_cast<int>(Mode::COUNT);
    mode = static_cast<Mode>((static_cast<int>(mode) + dir + n) % n);
    recompute();
    requestUpdate();
  }
}

void EncodeDecodeActivity::render(RenderLock&&) {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto W = renderer.getScreenWidth();
  const auto H = renderer.getScreenHeight();
  beginToolRender(tr(STR_ENCODE_DECODE), modeLabel());
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;

  const int x = metrics.contentSidePadding;
  const int maxW = static_cast<int>(W) - 2 * x;
  const int lineH = renderer.getLineHeight(UI_10_FONT_ID);
  int y = contentTop;

  if (input.empty()) {
    UITheme::drawCenteredText(renderer, Rect{0, contentTop, W, static_cast<int>(H) - contentTop}, UI_10_FONT_ID,
                              contentTop + lineH, tr(STR_ED_PRESS_INPUT));
  } else {
    renderer.drawText(UI_10_FONT_ID, x, y, tr(STR_ED_INPUT_LABEL), true, EpdFontFamily::BOLD);
    y += lineH;
    y = drawWrapped(renderer, x, y, maxW, lineH, input) + 8;

    renderer.drawText(UI_10_FONT_ID, x, y, tr(STR_ED_OUTPUT_LABEL), true, EpdFontFamily::BOLD);
    y += lineH;
    if (!outputValid) {
      renderer.drawText(UI_10_FONT_ID, x, y, tr(STR_ED_INVALID), true);
    } else {
      drawWrapped(renderer, x, y, maxW, lineH, output);
    }
  }

  endToolRender(tr(STR_BTN_BACK), tr(STR_ENTER_TEXT), tr(STR_MODE), tr(STR_MODE));
}
