#include "ToolsActivity.h"

#include <GfxRenderer.h>
#include <I18n.h>

#include "MappedInputManager.h"
#include "components/UITheme.h"
#include "fontIds.h"

namespace {
struct ToolDef {
  StrId labelId;
  UIIcon icon;
  ToolItem item;
};
constexpr ToolDef TOOLS[] = {
    {StrId::STR_NOTEPAD, UIIcon::Note, ToolItem::NOTEPAD},
    {StrId::STR_BADGE, UIIcon::Bookmark, ToolItem::BADGE},
    {StrId::STR_AUTHENTICATOR, UIIcon::Lock, ToolItem::AUTHENTICATOR},
    {StrId::STR_CLOCK, UIIcon::Clock, ToolItem::CLOCK},
    {StrId::STR_CALENDAR, UIIcon::Calendar, ToolItem::CALENDAR},
    {StrId::STR_READ_LATER, UIIcon::Article, ToolItem::READ_LATER},
    {StrId::STR_NEWS, UIIcon::Rss, ToolItem::NEWS},
    {StrId::STR_FLASHCARDS, UIIcon::Cards, ToolItem::FLASHCARDS},
    {StrId::STR_CALCULATOR, UIIcon::Calculator, ToolItem::CALCULATOR},
    {StrId::STR_PASSWORD_GEN, UIIcon::Key, ToolItem::PASSWORD_GEN},
    {StrId::STR_HASH_CALC, UIIcon::Hash, ToolItem::HASH_CALC},
    {StrId::STR_ENCODE_DECODE, UIIcon::Transfer, ToolItem::ENCODE_DECODE},
    {StrId::STR_QR_GENERATOR, UIIcon::QrCode, ToolItem::QR_GEN},
};
constexpr int TOOL_COUNT = sizeof(TOOLS) / sizeof(TOOLS[0]);
}  // namespace

ToolsActivity::ToolsActivity(GfxRenderer& renderer, MappedInputManager& mappedInput, ToolItem initial)
    : Activity("Tools", renderer, mappedInput) {
  for (int i = 0; i < TOOL_COUNT; i++)
    if (TOOLS[i].item == initial) {
      selected = i;
      break;
    }
}

void ToolsActivity::onEnter() {
  Activity::onEnter();
  requestUpdate();
}

void ToolsActivity::launch(int idx) {
  switch (TOOLS[idx].item) {
    case ToolItem::NOTEPAD:
      activityManager.goToNotepad();
      return;
    case ToolItem::BADGE:
      activityManager.goToBadge();
      return;
    case ToolItem::AUTHENTICATOR:
      activityManager.goToAuthenticator();
      return;
    case ToolItem::CLOCK:
      activityManager.goToClock();
      return;
    case ToolItem::CALENDAR:
      activityManager.goToCalendar();
      return;
    case ToolItem::READ_LATER:
      activityManager.goToReadLater();
      return;
    case ToolItem::NEWS:
      activityManager.goToNews();
      return;
    case ToolItem::FLASHCARDS:
      activityManager.goToFlashcards();
      return;
    case ToolItem::CALCULATOR:
      activityManager.goToCalculator();
      return;
    case ToolItem::PASSWORD_GEN:
      activityManager.goToPasswordGen();
      return;
    case ToolItem::HASH_CALC:
      activityManager.goToHashCalc();
      return;
    case ToolItem::ENCODE_DECODE:
      activityManager.goToEncodeDecode();
      return;
    case ToolItem::QR_GEN:
      activityManager.goToQrGen();
      return;
    default:
      return;
  }
}

void ToolsActivity::loop() {
  using Button = MappedInputManager::Button;
  if (mappedInput.wasPressed(Button::Back)) {
    onGoHome(HomeMenuItem::TOOLS);
    return;
  }
  if (mappedInput.wasPressed(Button::Confirm)) {
    launch(selected);
    return;
  }
  buttonNavigator.onNext([this] {
    selected = ButtonNavigator::nextIndex(selected, TOOL_COUNT);
    requestUpdate();
  });
  buttonNavigator.onPrevious([this] {
    selected = ButtonNavigator::previousIndex(selected, TOOL_COUNT);
    requestUpdate();
  });
}

void ToolsActivity::render(RenderLock&&) {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  const auto pageHeight = renderer.getScreenHeight();
  renderer.clearScreen();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;

  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, tr(STR_TOOLS), nullptr);

  const int menuHeight = pageHeight - contentTop - metrics.buttonHintsHeight - metrics.verticalSpacing;
  GUI.drawButtonMenu(
      renderer, Rect{0, contentTop, pageWidth, menuHeight}, TOOL_COUNT, selected,
      [](int i) { return std::string(I18N.get(TOOLS[i].labelId)); }, [](int i) { return TOOLS[i].icon; });

  const auto labels = mappedInput.mapLabels(tr(STR_BTN_BACK), tr(STR_SELECT), tr(STR_DIR_UP), tr(STR_DIR_DOWN));
  UITheme::getInstance().suppressBrandLogoOnce();
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}
