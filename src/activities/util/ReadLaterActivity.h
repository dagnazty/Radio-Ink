#pragma once

#include <GfxRenderer.h>

#include <string>
#include <vector>

#include "activities/util/ToolActivityBase.h"
#include "util/ButtonNavigator.h"

// "Read later": fetch a web page over Wi-Fi, reduce it to plain text, and save it
// to /articles on the SD card so it can be read offline in the normal reader.
//
// This is deliberately not a browser. The radio comes up when the user asks for a
// URL, one page is fetched and written to disk, and the radio goes back off. What
// is left behind is a text file like any other book.
class ReadLaterActivity final : public ToolActivityBase {
 public:
  ReadLaterActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : ToolActivityBase("ReadLater", renderer, mappedInput, ToolItem::READ_LATER) {}

  void onEnter() override;
  void loop() override;
  void render(RenderLock&&) override;

 private:
  enum class View { List, Fetching, Message, ConfirmDelete };

  View view = View::List;
  ButtonNavigator buttonNavigator;

  std::vector<std::string> articles;  // file names under /articles
  int selected = 0;

  std::string pendingUrl;
  // Set once the "Fetching..." frame has been drawn; the next loop tick runs the
  // blocking download so the status is on screen while it happens.
  bool fetchQueued = false;
  std::string message;

  void scanArticles();
  void promptUrl();
  void beginFetch();
  void runFetch();
  void openSelected();
  void deleteSelected();

  void renderList();
  void renderStatus(const char* title, const char* body);
};
