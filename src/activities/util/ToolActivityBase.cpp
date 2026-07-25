#include "ToolActivityBase.h"

#include "MappedInputManager.h"
#include "components/UITheme.h"

bool ToolActivityBase::handleToolBack() {
  if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
    activityManager.goToTools(toolItem);
    return true;
  }
  return false;
}

Rect ToolActivityBase::toolContentRect() const {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const int width = static_cast<int>(renderer.getScreenWidth());
  const int height = static_cast<int>(renderer.getScreenHeight());
  const int top = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;
  const int contentHeight = height - top - metrics.buttonHintsHeight - metrics.verticalSpacing;
  return Rect{0, top, width, contentHeight};
}

void ToolActivityBase::beginToolRender(const char* title, const char* subtitle) {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const int width = static_cast<int>(renderer.getScreenWidth());
  renderer.clearScreen();
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, width, metrics.headerHeight}, title, subtitle);
}

void ToolActivityBase::endToolRender(const char* back, const char* confirm, const char* previous, const char* next,
                                     HalDisplay::RefreshMode mode) {
  const auto labels = mappedInput.mapLabels(back, confirm, previous, next);
  UITheme::getInstance().suppressBrandLogoOnce();
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer(mode);
}
