#pragma once
#include <I18n.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "RecentBooksStore.h"
#include "activities/Activity.h"
#include "components/themes/BaseTheme.h"
#include "util/ButtonNavigator.h"

class RecentBooksActivity final : public Activity {
 private:
  ButtonNavigator buttonNavigator;

  int selectorIndex = 0;
  uint8_t selectedView = 0;

  // Set when a long-press has fired; input is swallowed until Confirm is released
  // again so the release doesn't also open the book.
  bool longPressFired = false;

  std::vector<RecentBook> allBooks;
  std::vector<RecentBook> visibleBooks;
  std::vector<TabInfo> viewTabs;

  // Data loading
  void loadLibraryBooks();
  void rebuildVisibleBooks();
  void rebuildViewTabs();
  void selectNextView();

  // Show an OK/Cancel prompt to remove the given book from the Recent Books list.
  void promptRemoveBook(const std::string& path, const std::string& title);

 public:
  explicit RecentBooksActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : Activity("RecentBooks", renderer, mappedInput) {}
  void onEnter() override;
  void onExit() override;
  void loop() override;
  void render(RenderLock&&) override;
};
