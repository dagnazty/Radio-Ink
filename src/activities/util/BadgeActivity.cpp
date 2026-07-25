#include "BadgeActivity.h"

#include <GfxRenderer.h>
#include <HalStorage.h>
#include <I18n.h>
#include <Logging.h>

#include <algorithm>

#include "MappedInputManager.h"
#include "activities/ActivityResult.h"
#include "activities/util/KeyboardEntryActivity.h"
#include "components/UITheme.h"
#include "fontIds.h"
#include "images/RadioInkSkull.h"
#include "util/ButtonNavigator.h"
#include "util/QrUtils.h"

namespace {
constexpr const char* BADGE_PATH = "/badge.txt";
constexpr int NAME_FONT_ID = NOTOSANS_18_FONT_ID;
constexpr int SUB_FONT_ID = NOTOSANS_14_FONT_ID;
constexpr int MENU_COUNT = 4;  // Edit name, Edit subtitle, Edit QR, Cancel
}  // namespace

void BadgeActivity::onEnter() {
  Activity::onEnter();
  load();
  bigQr = false;
  menuOpen = false;
  dirty = false;
  requestUpdate();
}

void BadgeActivity::onExit() {
  if (dirty) save();
  Activity::onExit();
}

void BadgeActivity::load() {
  const String content = Storage.readFile(BADGE_PATH);
  if (content.length() == 0) {
    // First-run defaults (editable on-device).
    name = "dag nazty";
    subtitle = "Radio Ink";
    qr = "https://dagnazty.dev";
    return;
  }
  // Three lines: name / subtitle / QR.
  std::string fields[3];
  int idx = 0;
  int start = 0;
  const int len = content.length();
  while (start <= len && idx < 3) {
    const int nl = content.indexOf('\n', start);
    const int end = (nl < 0) ? len : nl;
    String line = content.substring(start, end);
    while (line.length() && line[line.length() - 1] == '\r') line.remove(line.length() - 1);
    fields[idx++] = line.c_str();
    if (nl < 0) break;
    start = nl + 1;
  }
  name = fields[0];
  subtitle = fields[1];
  qr = fields[2];
}

void BadgeActivity::save() {
  String out;
  out.reserve(name.size() + subtitle.size() + qr.size() + 4);
  out += name.c_str();
  out += '\n';
  out += subtitle.c_str();
  out += '\n';
  out += qr.c_str();
  out += '\n';
  if (!Storage.writeFile(BADGE_PATH, out)) LOG_ERR("BADGE", "Failed to save %s", BADGE_PATH);
  dirty = false;
}

void BadgeActivity::editField(int which) {
  const char* title = which == 0 ? tr(STR_FIELD_NAME) : which == 1 ? tr(STR_FIELD_SUBTITLE) : tr(STR_FIELD_QR_LINK);
  const std::string& cur = which == 0 ? name : which == 1 ? subtitle : qr;
  const InputType type = which == 2 ? InputType::Url : InputType::Text;
  startActivityForResult(std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, title, cur, 200, type, true),
                         [this, which](const ActivityResult& result) {
                           if (!result.isCancelled) {
                             const auto& kb = std::get<KeyboardResult>(result.data);
                             if (which == 0)
                               name = kb.text;
                             else if (which == 1)
                               subtitle = kb.text;
                             else
                               qr = kb.text;
                             save();
                           }
                           requestUpdate();
                         });
}

void BadgeActivity::loop() {
  using Button = MappedInputManager::Button;

  if (menuOpen) {
    if (mappedInput.wasPressed(Button::Back)) {
      menuOpen = false;
      requestUpdate();
      return;
    }
    if (mappedInput.wasPressed(Button::Confirm)) {
      menuOpen = false;
      if (menuSel < 3)
        editField(menuSel);  // else Cancel
      else
        requestUpdate();
      return;
    }
    buttonNavigator.onNext([this] {
      menuSel = ButtonNavigator::nextIndex(menuSel, MENU_COUNT);
      requestUpdate();
    });
    buttonNavigator.onPrevious([this] {
      menuSel = ButtonNavigator::previousIndex(menuSel, MENU_COUNT);
      requestUpdate();
    });
    return;
  }

  if (bigQr) {
    if (mappedInput.wasPressed(Button::Back) || mappedInput.wasPressed(Button::Confirm) ||
        mappedInput.wasPressed(Button::Left)) {
      bigQr = false;
      requestUpdate();
    }
    return;
  }

  if (handleToolBack()) {
    return;
  }
  if (mappedInput.wasPressed(Button::Confirm)) {
    menuOpen = true;
    menuSel = 0;
    requestUpdate();
    return;
  }
  if (mappedInput.wasPressed(Button::Left) && !qr.empty()) {
    bigQr = true;
    requestUpdate();
  }
}

void BadgeActivity::render(RenderLock&&) {
  if (menuOpen) {
    renderMenu();
    return;
  }
  if (bigQr) {
    renderBigQr();
    return;
  }
  renderBadge();
}

void BadgeActivity::renderBadge() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto W = renderer.getScreenWidth();
  const auto H = renderer.getScreenHeight();
  renderer.clearScreen();

  int y = metrics.topPadding + metrics.verticalSpacing;

  // Skull (white backing first, so a partial-refresh frame can't smear it).
  const int sx = (W - RADIOINK_SKULL_WIDTH) / 2;
  renderer.fillRect(sx, y, RADIOINK_SKULL_WIDTH, RADIOINK_SKULL_HEIGHT, false);
  renderer.drawImage(RadioInkSkull, sx, y, RADIOINK_SKULL_WIDTH, RADIOINK_SKULL_HEIGHT);
  y += RADIOINK_SKULL_HEIGHT + metrics.verticalSpacing;

  // Name (large) + subtitle.
  renderer.drawCenteredText(NAME_FONT_ID, y, name.empty() ? tr(STR_RADIOINK) : name.c_str(), true, EpdFontFamily::BOLD);
  y += renderer.getLineHeight(NAME_FONT_ID) + 6;
  if (!subtitle.empty()) {
    renderer.drawCenteredText(SUB_FONT_ID, y, subtitle.c_str(), true);
    y += renderer.getLineHeight(SUB_FONT_ID);
  }
  y += metrics.verticalSpacing;

  // QR fills the remaining space above the hint bar.
  const int avail = H - y - metrics.buttonHintsHeight - metrics.verticalSpacing;
  const int qrSize = std::min(static_cast<int>(W) - metrics.contentSidePadding * 2, avail);
  if (!qr.empty() && qrSize > 40) {
    QrUtils::drawQrCode(renderer, Rect{(static_cast<int>(W) - qrSize) / 2, y, qrSize, qrSize}, qr);
  }

  // Full refresh: a partial/fast refresh ghosts the QR so phones can't decode it.
  // (endToolRender suppresses the home brand logo; the badge draws its own skull.)
  endToolRender(tr(STR_BTN_BACK), tr(STR_EDIT), qr.empty() ? "" : tr(STR_BIG_QR), "", HalDisplay::FULL_REFRESH);
}

void BadgeActivity::renderBigQr() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto W = renderer.getScreenWidth();
  const auto H = renderer.getScreenHeight();
  renderer.clearScreen();

  const int top = metrics.topPadding + metrics.verticalSpacing;
  const int avail = H - top - metrics.buttonHintsHeight - metrics.verticalSpacing;
  const int qrSize = std::min(static_cast<int>(W) - metrics.contentSidePadding * 2, avail);
  if (!qr.empty() && qrSize > 40) {
    QrUtils::drawQrCode(renderer, Rect{(static_cast<int>(W) - qrSize) / 2, top, qrSize, qrSize}, qr);
  }

  endToolRender(tr(STR_BTN_BACK), "", "", "", HalDisplay::FULL_REFRESH);
}

void BadgeActivity::renderMenu() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  const auto pageHeight = renderer.getScreenHeight();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;
  beginToolRender(tr(STR_BADGE_EDIT));

  const int listHeight = pageHeight - contentTop - metrics.buttonHintsHeight - metrics.verticalSpacing;
  GUI.drawList(
      renderer, Rect{0, contentTop, pageWidth, listHeight}, MENU_COUNT, menuSel,
      [](int i) -> std::string {
        switch (i) {
          case 0:
            return tr(STR_EDIT_NAME);
          case 1:
            return tr(STR_EDIT_SUBTITLE);
          case 2:
            return tr(STR_EDIT_QR_LINK);
          default:
            return tr(STR_CANCEL);
        }
      },
      nullptr, nullptr);

  endToolRender(tr(STR_BTN_BACK), tr(STR_SELECT), tr(STR_DIR_UP), tr(STR_DIR_DOWN));
}
