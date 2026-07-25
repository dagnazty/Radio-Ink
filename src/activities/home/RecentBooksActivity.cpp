#include "RecentBooksActivity.h"

#include <GfxRenderer.h>
#include <HalStorage.h>
#include <I18n.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <memory>

#include "MappedInputManager.h"
#include "RecentBooksStore.h"
#include "activities/util/ConfirmationActivity.h"
#include "components/UITheme.h"
#include "fontIds.h"

namespace {
// Hold threshold for the long-press "remove from list" action (firmware convention).
constexpr unsigned long LONG_PRESS_MS = 1000;
constexpr uint8_t LIBRARY_VIEW_COUNT = 3;
constexpr uint8_t LIBRARY_VIEW_CONTINUE = 0;
constexpr uint8_t LIBRARY_VIEW_FINISHED = 1;
constexpr uint8_t LIBRARY_VIEW_ALL = 2;
constexpr char READ_FOLDER[] = "/read";

constexpr std::array<StrId, LIBRARY_VIEW_COUNT> LIBRARY_VIEW_LABELS = {
    StrId::STR_LIBRARY_CONTINUE,
    StrId::STR_LIBRARY_FINISHED,
    StrId::STR_LIBRARY_ALL,
};

char asciiLower(char c) {
  return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
}

bool startsWithReadFolder(const std::string& path) {
  constexpr size_t readFolderLen = sizeof(READ_FOLDER) - 1;
  if (path.size() <= readFolderLen || path[readFolderLen] != '/') {
    return false;
  }
  for (size_t i = 0; i < readFolderLen; i++) {
    if (asciiLower(path[i]) != READ_FOLDER[i]) {
      return false;
    }
  }
  return true;
}
}  // namespace

void RecentBooksActivity::loadLibraryBooks() {
  allBooks = RECENT_BOOKS.getBooks();
  rebuildVisibleBooks();
}

void RecentBooksActivity::rebuildVisibleBooks() {
  visibleBooks.clear();
  visibleBooks.reserve(allBooks.size());

  for (const auto& book : allBooks) {
    const bool finished = startsWithReadFolder(book.path);
    if (selectedView == LIBRARY_VIEW_ALL || (selectedView == LIBRARY_VIEW_FINISHED && finished) ||
        (selectedView == LIBRARY_VIEW_CONTINUE && !finished)) {
      visibleBooks.push_back(book);
    }
  }

  if (visibleBooks.empty()) {
    selectorIndex = 0;
  } else if (selectorIndex > static_cast<int>(visibleBooks.size())) {
    selectorIndex = static_cast<int>(visibleBooks.size());
  }
}

void RecentBooksActivity::rebuildViewTabs() {
  viewTabs.clear();
  viewTabs.reserve(LIBRARY_VIEW_COUNT);
  for (uint8_t i = 0; i < LIBRARY_VIEW_COUNT; i++) {
    viewTabs.push_back({I18N.get(LIBRARY_VIEW_LABELS[i]), selectedView == i});
  }
}

void RecentBooksActivity::selectNextView() {
  selectedView = (selectedView + 1) % LIBRARY_VIEW_COUNT;
  selectorIndex = 0;
  rebuildVisibleBooks();
  rebuildViewTabs();
  requestUpdate();
}

void RecentBooksActivity::onEnter() {
  Activity::onEnter();

  // Prune entries whose backing files are gone; this is one of two interaction
  // points where the persistent store gets cleaned (the other is addBook).
  if (RECENT_BOOKS.pruneMissing()) {
    RECENT_BOOKS.saveToFile();
  }

  // Load data
  loadLibraryBooks();
  rebuildViewTabs();

  selectorIndex = 0;
  requestUpdate();
}

void RecentBooksActivity::onExit() {
  Activity::onExit();
  allBooks.clear();
  visibleBooks.clear();
  viewTabs.clear();
}

void RecentBooksActivity::loop() {
  const int pageItems = UITheme::getInstance().getNumberOfItemsPerPage(renderer, true, true, true, true);

  // After a long-press has fired, swallow input until Confirm is physically released
  // (so the release doesn't also open the book; re-arm only once the button is up).
  if (longPressFired) {
    if (!mappedInput.isPressed(MappedInputManager::Button::Confirm)) {
      longPressFired = false;
    }
    return;
  }

  // Long-press Confirm on the selected book: prompt to remove it from the list.
  // Fires when the hold times out while still held (firmware hold-to-act pattern,
  // cf. FileBrowserActivity BACK long-press).
  if (selectorIndex > 0 && selectorIndex <= static_cast<int>(visibleBooks.size()) &&
      mappedInput.isPressed(MappedInputManager::Button::Confirm) && mappedInput.getHeldTime() >= LONG_PRESS_MS) {
    longPressFired = true;
    const int bookIndex = selectorIndex - 1;
    promptRemoveBook(visibleBooks[bookIndex].path, visibleBooks[bookIndex].title);
    return;
  }

  if (mappedInput.wasReleased(MappedInputManager::Button::Confirm)) {
    if (selectorIndex == 0) {
      selectNextView();
      return;
    }
    if (selectorIndex <= static_cast<int>(visibleBooks.size())) {
      const int bookIndex = selectorIndex - 1;
      LOG_DBG("RBA", "Selected recent book: %s", visibleBooks[bookIndex].path.c_str());
      onSelectBook(visibleBooks[bookIndex].path);
      return;
    }
  }

  if (mappedInput.wasReleased(MappedInputManager::Button::Back)) {
    onGoHome();
  }

  int listSize = static_cast<int>(visibleBooks.size()) + 1;

  buttonNavigator.onNextRelease([this, listSize] {
    selectorIndex = ButtonNavigator::nextIndex(static_cast<int>(selectorIndex), listSize);
    requestUpdate();
  });

  buttonNavigator.onPreviousRelease([this, listSize] {
    selectorIndex = ButtonNavigator::previousIndex(static_cast<int>(selectorIndex), listSize);
    requestUpdate();
  });

  buttonNavigator.onNextContinuous([this, listSize, pageItems] {
    selectorIndex = ButtonNavigator::nextPageIndex(static_cast<int>(selectorIndex), listSize, pageItems);
    requestUpdate();
  });

  buttonNavigator.onPreviousContinuous([this, listSize, pageItems] {
    selectorIndex = ButtonNavigator::previousPageIndex(static_cast<int>(selectorIndex), listSize, pageItems);
    requestUpdate();
  });
}

void RecentBooksActivity::promptRemoveBook(const std::string& path, const std::string& title) {
  auto handler = [this, path](const ActivityResult& res) {
    if (res.isCancelled) {
      LOG_DBG("RBA", "Remove from recents cancelled");
      return;
    }
    if (RECENT_BOOKS.removeByPath(path)) {
      LOG_DBG("RBA", "Removed from recents: %s", path.c_str());
      loadLibraryBooks();
      if (visibleBooks.empty()) {
        selectorIndex = 0;
      } else if (selectorIndex > static_cast<int>(visibleBooks.size())) {
        selectorIndex = static_cast<int>(visibleBooks.size());
      }
      requestUpdate(true);
    }
  };

  startActivityForResult(
      std::make_unique<ConfirmationActivity>(renderer, mappedInput, tr(STR_REMOVE_FROM_RECENTS), title),
      std::move(handler));
}

void RecentBooksActivity::render(RenderLock&&) {
  renderer.clearScreen();

  const auto pageWidth = renderer.getScreenWidth();
  const auto pageHeight = renderer.getScreenHeight();
  const auto& metrics = UITheme::getInstance().getMetrics();

  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, tr(STR_MENU_RECENT_BOOKS));

  GUI.drawTabBar(renderer, Rect{0, metrics.topPadding + metrics.headerHeight, pageWidth, metrics.tabBarHeight}, viewTabs,
                 selectorIndex == 0);

  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.tabBarHeight + metrics.verticalSpacing;
  const int contentHeight = pageHeight - contentTop - metrics.buttonHintsHeight - metrics.verticalSpacing;

  if (visibleBooks.empty()) {
    renderer.drawText(UI_10_FONT_ID, metrics.contentSidePadding, contentTop + 20, tr(STR_NO_BOOKS_IN_VIEW));
  } else {
    GUI.drawList(
        renderer, Rect{0, contentTop, pageWidth, contentHeight}, visibleBooks.size(), selectorIndex - 1,
        [this](int index) { return visibleBooks[index].title; },
        [this](int index) { return visibleBooks[index].author; },
        [this](int index) { return UITheme::getFileIcon(visibleBooks[index].path); });
  }

  // Help text
  const char* confirmLabel =
      selectorIndex == 0 ? I18N.get(LIBRARY_VIEW_LABELS[(selectedView + 1) % LIBRARY_VIEW_COUNT]) : tr(STR_OPEN);
  const auto labels = mappedInput.mapLabels(tr(STR_HOME), confirmLabel, tr(STR_DIR_UP), tr(STR_DIR_DOWN));
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);

  renderer.displayBuffer();
}
