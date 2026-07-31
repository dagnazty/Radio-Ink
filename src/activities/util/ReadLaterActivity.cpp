#include "ReadLaterActivity.h"

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
#include "network/ArticleExtractor.h"

namespace {
constexpr const char* MODULE = "ReadLater";
constexpr const char* ARTICLE_DIR = "/articles";
constexpr const char* ARTICLE_SUFFIX = ".txt";
constexpr size_t NAME_BUFFER_SIZE = 128;
constexpr size_t URL_MAX = 250;

bool hasSuffix(const std::string& value, const char* suffix) {
  const size_t suffixLen = strlen(suffix);
  return value.size() > suffixLen && value.compare(value.size() - suffixLen, suffixLen, suffix) == 0;
}
}  // namespace

void ReadLaterActivity::onEnter() {
  Activity::onEnter();
  scanArticles();
  requestUpdate();
}

void ReadLaterActivity::scanArticles() {
  articles.clear();

  HalFile root = Storage.open(ARTICLE_DIR);
  if (!root || !root.isDirectory()) return;  // nothing saved yet
  root.rewindDirectory();

  char nameBuffer[NAME_BUFFER_SIZE];
  for (auto file = root.openNextFile(); file; file = root.openNextFile()) {
    if (file.isDirectory()) continue;
    file.getName(nameBuffer, sizeof(nameBuffer));
    std::string name(nameBuffer);
    if (name.empty() || name[0] == '.') continue;
    if (hasSuffix(name, ARTICLE_SUFFIX)) articles.push_back(std::move(name));
  }

  std::sort(articles.begin(), articles.end());
  if (selected >= static_cast<int>(articles.size())) selected = std::max(0, static_cast<int>(articles.size()) - 1);
}

void ReadLaterActivity::promptUrl() {
  startActivityForResult(std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, tr(STR_RL_ENTER_URL), "",
                                                                 URL_MAX, InputType::Url, false),
                         [this](const ActivityResult& activityResult) {
                           if (activityResult.isCancelled) {
                             requestUpdate();
                             return;
                           }
                           const auto& keyboard = std::get<KeyboardResult>(activityResult.data);
                           if (keyboard.text.empty()) {
                             requestUpdate();
                             return;
                           }
                           pendingUrl = keyboard.text;
                           beginFetch();
                         });
}

void ReadLaterActivity::beginFetch() {
  // Already associated (another tool left Wi-Fi up): go straight to the fetch.
  if (WiFi.status() == WL_CONNECTED) {
    view = View::Fetching;
    fetchQueued = true;
    requestUpdate();
    return;
  }

  WiFi.mode(WIFI_STA);
  startActivityForResult(std::make_unique<WifiSelectionActivity>(renderer, mappedInput),
                         [this](const ActivityResult& activityResult) {
                           if (activityResult.isCancelled || WiFi.status() != WL_CONNECTED) {
                             message = tr(STR_RL_NOT_CONNECTED);
                             view = View::Message;
                             requestUpdate();
                             return;
                           }
                           view = View::Fetching;
                           fetchQueued = true;
                           requestUpdate();
                         });
}

void ReadLaterActivity::runFetch() {
  fetchQueued = false;

  Storage.ensureDirectoryExists(ARTICLE_DIR);

  // Write to a temporary name first: the real name comes from the document title,
  // which is only known once the response has been parsed.
  const std::string tempPath = std::string(ARTICLE_DIR) + "/.fetching" + ARTICLE_SUFFIX;
  std::string title;
  const bool ok = ArticleExtractor::fetchToText(pendingUrl, tempPath, title);

  // One page, then the radio goes back off -- no background Wi-Fi.
  WiFi.disconnect(true, false);
  WiFi.mode(WIFI_OFF);

  if (!ok) {
    message = tr(STR_RL_FETCH_FAILED);
    view = View::Message;
    requestUpdate();
    return;
  }

  // Name the file after the page title, de-duplicating against what is already saved.
  const std::string slug = ArticleExtractor::slugify(title.empty() ? pendingUrl : title);
  std::string finalPath = std::string(ARTICLE_DIR) + "/" + slug + ARTICLE_SUFFIX;
  for (int suffix = 2; Storage.exists(finalPath.c_str()) && suffix < 100; suffix++) {
    char numbered[64];
    snprintf(numbered, sizeof(numbered), "%s-%d%s", slug.c_str(), suffix, ARTICLE_SUFFIX);
    finalPath = std::string(ARTICLE_DIR) + "/" + numbered;
  }

  if (!Storage.rename(tempPath.c_str(), finalPath.c_str())) {
    LOG_ERR(MODULE, "Rename %s -> %s failed", tempPath.c_str(), finalPath.c_str());
    message = tr(STR_RL_SAVE_FAILED);
    view = View::Message;
    requestUpdate();
    return;
  }

  LOG_INF(MODULE, "Saved %s", finalPath.c_str());
  scanArticles();

  // Select what was just saved so Confirm opens it straight away.
  const std::string savedName = finalPath.substr(strlen(ARTICLE_DIR) + 1);
  const auto found = std::find(articles.begin(), articles.end(), savedName);
  if (found != articles.end()) selected = static_cast<int>(found - articles.begin());

  view = View::List;
  requestUpdate();
}

void ReadLaterActivity::openSelected() {
  if (articles.empty()) return;
  activityManager.goToReader(std::string(ARTICLE_DIR) + "/" + articles[selected]);
}

void ReadLaterActivity::deleteSelected() {
  if (articles.empty()) return;
  const std::string path = std::string(ARTICLE_DIR) + "/" + articles[selected];
  if (!Storage.remove(path.c_str())) LOG_ERR(MODULE, "Delete failed: %s", path.c_str());
  scanArticles();
  view = View::List;
  requestUpdate();
}

void ReadLaterActivity::loop() {
  using Button = MappedInputManager::Button;

  if (view == View::Fetching) {
    // The status frame has been drawn; now do the blocking download.
    if (fetchQueued) runFetch();
    return;
  }

  if (view == View::Message) {
    if (mappedInput.wasPressed(Button::Back) || mappedInput.wasPressed(Button::Confirm)) {
      view = View::List;
      requestUpdate();
    }
    return;
  }

  if (view == View::ConfirmDelete) {
    if (mappedInput.wasPressed(Button::Confirm)) {
      deleteSelected();
      return;
    }
    if (mappedInput.wasPressed(Button::Back)) {
      view = View::List;
      requestUpdate();
    }
    return;
  }

  // View::List
  if (handleToolBack()) return;

  if (mappedInput.wasPressed(Button::Left)) {
    promptUrl();
    return;
  }
  if (mappedInput.wasPressed(Button::Confirm)) {
    if (articles.empty()) {
      promptUrl();
    } else {
      openSelected();
    }
    return;
  }
  if (mappedInput.wasPressed(Button::Right) && !articles.empty()) {
    view = View::ConfirmDelete;
    requestUpdate();
    return;
  }
  if (articles.empty()) return;

  buttonNavigator.onNext([this] {
    selected = ButtonNavigator::nextIndex(selected, static_cast<int>(articles.size()));
    requestUpdate();
  });
  buttonNavigator.onPrevious([this] {
    selected = ButtonNavigator::previousIndex(selected, static_cast<int>(articles.size()));
    requestUpdate();
  });
}

void ReadLaterActivity::renderStatus(const char* title, const char* body) {
  const auto W = renderer.getScreenWidth();
  const auto H = renderer.getScreenHeight();

  beginToolRender(title);
  UITheme::drawCenteredText(renderer, Rect{0, 0, W, H}, UI_12_FONT_ID, static_cast<int>(H) / 2, body);
  endToolRender(tr(STR_BTN_BACK), "", "", "");
}

void ReadLaterActivity::renderList() {
  const auto W = renderer.getScreenWidth();
  const auto H = renderer.getScreenHeight();
  const auto& metrics = UITheme::getInstance().getMetrics();

  beginToolRender(tr(STR_READ_LATER));

  if (articles.empty()) {
    const Rect full{0, 0, W, H};
    UITheme::drawCenteredText(renderer, full, UI_12_FONT_ID, static_cast<int>(H) / 2 - 12, tr(STR_RL_EMPTY));
    UITheme::drawCenteredText(renderer, full, UI_10_FONT_ID, static_cast<int>(H) / 2 + 14, tr(STR_RL_EMPTY_HINT));
    endToolRender(tr(STR_BTN_BACK), tr(STR_RL_ADD), "", "");
    return;
  }

  const Rect content = toolContentRect();
  const int lineHeight = renderer.getLineHeight(UI_12_FONT_ID) + metrics.verticalSpacing / 2;
  const int visibleRows = std::max(1, content.height / lineHeight);
  const int firstRow =
      std::max(0, std::min(selected - visibleRows / 2, static_cast<int>(articles.size()) - visibleRows));

  int y = content.y + metrics.verticalSpacing;
  for (int i = firstRow; i < static_cast<int>(articles.size()) && i < firstRow + visibleRows; i++) {
    // Show the slug without its extension; that is the article title as saved.
    std::string label = articles[i].substr(0, articles[i].size() - strlen(ARTICLE_SUFFIX));
    if (i == selected) label = "> " + label;
    while (label.size() > 1 && renderer.getTextWidth(UI_12_FONT_ID, label.c_str()) > content.width) label.pop_back();
    renderer.drawText(UI_12_FONT_ID, content.x, y, label.c_str(), true,
                      i == selected ? EpdFontFamily::BOLD : EpdFontFamily::REGULAR);
    y += lineHeight;
  }

  endToolRender(tr(STR_BTN_BACK), tr(STR_OPEN), tr(STR_RL_ADD), tr(STR_DELETE));
}

void ReadLaterActivity::render(RenderLock&&) {
  switch (view) {
    case View::List:
      renderList();
      break;
    case View::Fetching:
      renderStatus(tr(STR_READ_LATER), tr(STR_RL_FETCHING));
      break;
    case View::Message:
      renderStatus(tr(STR_READ_LATER), message.c_str());
      break;
    case View::ConfirmDelete:
      renderStatus(tr(STR_READ_LATER), tr(STR_RL_CONFIRM_DELETE));
      break;
  }
}
