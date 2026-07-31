#include "NewsActivity.h"

#include <GfxRenderer.h>
#include <HalStorage.h>
#include <I18n.h>
#include <Logging.h>
#include <WiFi.h>

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "MappedInputManager.h"
#include "activities/ActivityResult.h"
#include "activities/network/WifiSelectionActivity.h"
#include "activities/util/KeyboardEntryActivity.h"
#include "components/UITheme.h"
#include "fontIds.h"

namespace {
constexpr const char* MODULE = "News";
constexpr const char* FEEDS_PATH = "/feeds.txt";
constexpr const char* ARTICLE_DIR = "/articles";
constexpr const char* ARTICLE_SUFFIX = ".txt";
constexpr size_t URL_MAX = 250;
constexpr size_t READ_CHUNK = 256;
}  // namespace

void NewsActivity::onEnter() {
  Activity::onEnter();
  loadFeeds();
  requestUpdate();
}

void NewsActivity::onExit() {
  shutdownRadio();
  Activity::onExit();
}

void NewsActivity::shutdownRadio() {
  if (!radioUp) return;
  WiFi.disconnect(true, false);
  WiFi.mode(WIFI_OFF);
  radioUp = false;
}

void NewsActivity::loadFeeds() {
  feeds.clear();

  HalFile file;
  if (!Storage.openFileForRead(MODULE, FEEDS_PATH, file)) {
    LOG_INF(MODULE, "No %s yet", FEEDS_PATH);
    return;
  }

  std::string line;
  line.reserve(URL_MAX + 64);
  uint8_t chunk[READ_CHUNK];
  int readCount;

  auto commit = [this](std::string& text) {
    while (!text.empty() && (text.back() == '\r' || text.back() == ' ')) text.pop_back();
    if (text.empty() || text[0] == '#') {  // blank line or comment
      text.clear();
      return;
    }
    // "Name|url" if a pipe is present, otherwise the URL doubles as the label.
    const size_t pipe = text.find('|');
    if (pipe == std::string::npos) {
      feeds.push_back({text, text});
    } else {
      feeds.push_back({text.substr(0, pipe), text.substr(pipe + 1)});
    }
    text.clear();
  };

  while ((readCount = file.read(chunk, sizeof(chunk))) > 0) {
    for (int i = 0; i < readCount; i++) {
      const char c = static_cast<char>(chunk[i]);
      if (c == '\n') {
        commit(line);
      } else if (line.size() < URL_MAX + 64) {
        line += c;
      }
    }
  }
  commit(line);  // final line without a trailing newline
}

void NewsActivity::saveFeeds() {
  HalFile file;
  if (!Storage.openFileForWrite(MODULE, FEEDS_PATH, file)) {
    LOG_ERR(MODULE, "Cannot write %s", FEEDS_PATH);
    return;
  }
  for (const Feed& feed : feeds) {
    const std::string line = (feed.name == feed.url ? feed.url : feed.name + "|" + feed.url) + "\n";
    file.write(line.data(), line.size());
  }
  file.flush();
}

void NewsActivity::promptAddFeed() {
  startActivityForResult(std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, tr(STR_NEWS_ADD_FEED), "",
                                                                 URL_MAX, InputType::Url, false),
                         [this](const ActivityResult& activityResult) {
                           if (activityResult.isCancelled) {
                             requestUpdate();
                             return;
                           }
                           const auto& keyboard = std::get<KeyboardResult>(activityResult.data);
                           if (!keyboard.text.empty()) {
                             feeds.push_back({keyboard.text, keyboard.text});
                             selectedFeed = static_cast<int>(feeds.size()) - 1;
                             saveFeeds();
                           }
                           requestUpdate();
                         });
}

void NewsActivity::beginFetch(Pending what) {
  if (WiFi.status() == WL_CONNECTED) {
    radioUp = true;
    pending = what;
    view = View::Fetching;
    requestUpdate();
    return;
  }

  WiFi.mode(WIFI_STA);
  startActivityForResult(std::make_unique<WifiSelectionActivity>(renderer, mappedInput),
                         [this, what](const ActivityResult& activityResult) {
                           if (activityResult.isCancelled || WiFi.status() != WL_CONNECTED) {
                             message = tr(STR_NEWS_NOT_CONNECTED);
                             view = View::Message;
                             requestUpdate();
                             return;
                           }
                           radioUp = true;
                           pending = what;
                           view = View::Fetching;
                           requestUpdate();
                         });
}

void NewsActivity::runFeedFetch() {
  pending = Pending::None;

  if (!ArticleExtractor::fetchFeed(feeds[selectedFeed].url, items, MAX_ITEMS)) {
    message = tr(STR_NEWS_FEED_FAILED);
    view = View::Message;
    requestUpdate();
    return;
  }

  selectedItem = 0;
  view = View::ItemList;
  requestUpdate();
}

void NewsActivity::runArticleFetch() {
  pending = Pending::None;

  Storage.ensureDirectoryExists(ARTICLE_DIR);

  const ArticleExtractor::FeedItem& item = items[selectedItem];
  const std::string tempPath = std::string(ARTICLE_DIR) + "/.fetching" + ARTICLE_SUFFIX;
  std::string documentTitle;

  if (!ArticleExtractor::fetchToText(item.link, tempPath, documentTitle)) {
    message = tr(STR_NEWS_ARTICLE_FAILED);
    view = View::Message;
    requestUpdate();
    return;
  }

  // Prefer the headline from the feed: it is cleaner than most <title> tags,
  // which tend to carry the site name too.
  const std::string slug = ArticleExtractor::slugify(item.title.empty() ? documentTitle : item.title);
  std::string finalPath = std::string(ARTICLE_DIR) + "/" + slug + ARTICLE_SUFFIX;
  for (int suffix = 2; Storage.exists(finalPath.c_str()) && suffix < 100; suffix++) {
    char numbered[64];
    snprintf(numbered, sizeof(numbered), "%s-%d%s", slug.c_str(), suffix, ARTICLE_SUFFIX);
    finalPath = std::string(ARTICLE_DIR) + "/" + numbered;
  }

  if (!Storage.rename(tempPath.c_str(), finalPath.c_str())) {
    LOG_ERR(MODULE, "Rename %s -> %s failed", tempPath.c_str(), finalPath.c_str());
    message = tr(STR_NEWS_ARTICLE_FAILED);
    view = View::Message;
    requestUpdate();
    return;
  }

  // Saved and about to be read: drop the radio before handing off to the reader.
  shutdownRadio();
  activityManager.goToReader(finalPath);
}

void NewsActivity::loop() {
  using Button = MappedInputManager::Button;

  if (view == View::Fetching) {
    if (pending == Pending::Feed) {
      runFeedFetch();
    } else if (pending == Pending::Article) {
      runArticleFetch();
    }
    return;
  }

  if (view == View::Message) {
    if (mappedInput.wasPressed(Button::Back) || mappedInput.wasPressed(Button::Confirm)) {
      view = items.empty() ? View::FeedList : View::ItemList;
      requestUpdate();
    }
    return;
  }

  if (view == View::ItemList) {
    if (mappedInput.wasPressed(Button::Back)) {
      items.clear();
      view = View::FeedList;
      requestUpdate();
      return;
    }
    if (mappedInput.wasPressed(Button::Confirm) && !items.empty()) {
      beginFetch(Pending::Article);
      return;
    }
    if (items.empty()) return;

    buttonNavigator.onNext([this] {
      selectedItem = ButtonNavigator::nextIndex(selectedItem, static_cast<int>(items.size()));
      requestUpdate();
    });
    buttonNavigator.onPrevious([this] {
      selectedItem = ButtonNavigator::previousIndex(selectedItem, static_cast<int>(items.size()));
      requestUpdate();
    });
    return;
  }

  // View::FeedList
  if (handleToolBack()) return;

  if (mappedInput.wasPressed(Button::Left)) {
    promptAddFeed();
    return;
  }
  if (mappedInput.wasPressed(Button::Confirm)) {
    if (feeds.empty()) {
      promptAddFeed();
    } else {
      beginFetch(Pending::Feed);
    }
    return;
  }
  if (mappedInput.wasPressed(Button::Right) && !feeds.empty()) {
    feeds.erase(feeds.begin() + selectedFeed);
    if (selectedFeed >= static_cast<int>(feeds.size())) selectedFeed = std::max(0, static_cast<int>(feeds.size()) - 1);
    saveFeeds();
    requestUpdate();
    return;
  }
  if (feeds.empty()) return;

  buttonNavigator.onNext([this] {
    selectedFeed = ButtonNavigator::nextIndex(selectedFeed, static_cast<int>(feeds.size()));
    requestUpdate();
  });
  buttonNavigator.onPrevious([this] {
    selectedFeed = ButtonNavigator::previousIndex(selectedFeed, static_cast<int>(feeds.size()));
    requestUpdate();
  });
}

void NewsActivity::renderStatus(const char* body) {
  const auto W = renderer.getScreenWidth();
  const auto H = renderer.getScreenHeight();

  beginToolRender(tr(STR_NEWS));
  UITheme::drawCenteredText(renderer, Rect{0, 0, W, H}, UI_12_FONT_ID, static_cast<int>(H) / 2, body);
  endToolRender(tr(STR_BTN_BACK), "", "", "");
}

void NewsActivity::renderFeedList() {
  const auto W = renderer.getScreenWidth();
  const auto H = renderer.getScreenHeight();
  const auto& metrics = UITheme::getInstance().getMetrics();

  beginToolRender(tr(STR_NEWS));

  if (feeds.empty()) {
    const Rect full{0, 0, W, H};
    UITheme::drawCenteredText(renderer, full, UI_12_FONT_ID, static_cast<int>(H) / 2 - 12, tr(STR_NEWS_NO_FEEDS));
    UITheme::drawCenteredText(renderer, full, UI_10_FONT_ID, static_cast<int>(H) / 2 + 14, tr(STR_NEWS_FEEDS_HINT));
    endToolRender(tr(STR_BTN_BACK), tr(STR_NEWS_ADD), "", "");
    return;
  }

  const Rect content = toolContentRect();
  const int lineHeight = renderer.getLineHeight(UI_12_FONT_ID) + metrics.verticalSpacing / 2;
  const int visibleRows = std::max(1, content.height / lineHeight);
  const int firstRow =
      std::max(0, std::min(selectedFeed - visibleRows / 2, static_cast<int>(feeds.size()) - visibleRows));

  int y = content.y + metrics.verticalSpacing;
  for (int i = firstRow; i < static_cast<int>(feeds.size()) && i < firstRow + visibleRows; i++) {
    std::string label = feeds[i].name;
    if (i == selectedFeed) label = "> " + label;
    while (label.size() > 1 && renderer.getTextWidth(UI_12_FONT_ID, label.c_str()) > content.width) label.pop_back();
    renderer.drawText(UI_12_FONT_ID, content.x, y, label.c_str(), true,
                      i == selectedFeed ? EpdFontFamily::BOLD : EpdFontFamily::REGULAR);
    y += lineHeight;
  }

  endToolRender(tr(STR_BTN_BACK), tr(STR_OPEN), tr(STR_NEWS_ADD), tr(STR_DELETE));
}

void NewsActivity::renderItemList() {
  const auto& metrics = UITheme::getInstance().getMetrics();

  char subtitle[48];
  snprintf(subtitle, sizeof(subtitle), "%s", feeds[selectedFeed].name.c_str());
  beginToolRender(tr(STR_NEWS), subtitle);

  const Rect content = toolContentRect();
  const int lineHeight = renderer.getLineHeight(UI_12_FONT_ID) + metrics.verticalSpacing / 2;
  const int visibleRows = std::max(1, content.height / lineHeight);
  const int firstRow =
      std::max(0, std::min(selectedItem - visibleRows / 2, static_cast<int>(items.size()) - visibleRows));

  int y = content.y + metrics.verticalSpacing;
  for (int i = firstRow; i < static_cast<int>(items.size()) && i < firstRow + visibleRows; i++) {
    std::string label = items[i].title;
    if (i == selectedItem) label = "> " + label;
    while (label.size() > 1 && renderer.getTextWidth(UI_12_FONT_ID, label.c_str()) > content.width) label.pop_back();
    renderer.drawText(UI_12_FONT_ID, content.x, y, label.c_str(), true,
                      i == selectedItem ? EpdFontFamily::BOLD : EpdFontFamily::REGULAR);
    y += lineHeight;
  }

  endToolRender(tr(STR_BTN_BACK), tr(STR_NEWS_READ), "", "");
}

void NewsActivity::render(RenderLock&&) {
  switch (view) {
    case View::FeedList:
      renderFeedList();
      break;
    case View::Fetching:
      renderStatus(pending == Pending::Article ? tr(STR_NEWS_FETCHING_ARTICLE) : tr(STR_NEWS_FETCHING_FEED));
      break;
    case View::ItemList:
      renderItemList();
      break;
    case View::Message:
      renderStatus(message.c_str());
      break;
  }
}
