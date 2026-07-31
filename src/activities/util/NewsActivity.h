#pragma once

#include <GfxRenderer.h>

#include <string>
#include <vector>

#include "activities/util/ToolActivityBase.h"
#include "network/ArticleExtractor.h"
#include "util/ButtonNavigator.h"

// News / RSS reader. Subscriptions live in a plain /feeds.txt on the SD card, one
// per line as either "https://example.com/feed" or "Name|https://example.com/feed".
//
// Nothing polls: a feed is fetched only when the user opens it. Headlines are held
// in RAM for the session, and opening one runs it through the same HTML-to-text
// pipeline as Read Later, so the article lands in /articles and opens in the
// normal reader. The radio is shut down again on the way out.
class NewsActivity final : public ToolActivityBase {
 public:
  NewsActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : ToolActivityBase("News", renderer, mappedInput, ToolItem::NEWS) {}

  void onEnter() override;
  void onExit() override;
  void loop() override;
  void render(RenderLock&&) override;

 private:
  enum class View { FeedList, Fetching, ItemList, Message };
  // What the next loop tick should do once the "Fetching..." frame is on screen.
  enum class Pending { None, Feed, Article };

  struct Feed {
    std::string name;
    std::string url;
  };

  View view = View::FeedList;
  Pending pending = Pending::None;
  ButtonNavigator buttonNavigator;

  std::vector<Feed> feeds;
  int selectedFeed = 0;

  std::vector<ArticleExtractor::FeedItem> items;
  int selectedItem = 0;

  std::string message;
  bool radioUp = false;  // true once associated, so the second fetch can skip the picker

  static constexpr size_t MAX_ITEMS = 24;

  void loadFeeds();
  void promptAddFeed();
  void saveFeeds();
  void beginFetch(Pending what);
  void runFeedFetch();
  void runArticleFetch();
  void shutdownRadio();

  void renderFeedList();
  void renderItemList();
  void renderStatus(const char* body);
};
