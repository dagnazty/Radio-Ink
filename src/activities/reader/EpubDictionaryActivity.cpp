#include "EpubDictionaryActivity.h"

#include <Arduino.h>
#include <GfxRenderer.h>
#include <HalStorage.h>
#include <Logging.h>
#include <Memory.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <utility>

#include "MappedInputManager.h"
#include "components/UITheme.h"
#include "fontIds.h"

namespace {
constexpr char DICTIONARY_FLAT_PATH[] = "/dictionary.tsv";
constexpr char DICTIONARY_SHARD_DIR[] = "/dictionary";
constexpr size_t MAX_DICTIONARY_LINE_BYTES = 640;

bool isAsciiAlpha(const char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }

bool isAsciiDigit(const char c) { return c >= '0' && c <= '9'; }

char toAsciiLower(const char c) {
  if (c >= 'A' && c <= 'Z') {
    return static_cast<char>(c - 'A' + 'a');
  }
  return c;
}

void normalizeLookupWord(const char* raw, const size_t rawLen, char* out, const size_t outSize) {
  if (!out || outSize == 0) {
    return;
  }
  out[0] = '\0';
  if (!raw) {
    return;
  }

  size_t outLen = 0;
  for (size_t i = 0; i < rawLen && raw[i] != '\0' && outLen + 1 < outSize; i++) {
    const char c = raw[i];
    if (isAsciiAlpha(c) || isAsciiDigit(c)) {
      out[outLen++] = toAsciiLower(c);
    } else if ((c == '\'' || c == '-') && outLen > 0) {
      out[outLen++] = c;
    }
  }

  while (outLen > 0 && (out[outLen - 1] == '\'' || out[outLen - 1] == '-')) {
    outLen--;
  }
  out[outLen] = '\0';
}

bool copyDefinitionIfLineMatches(const char* line, const char* word, char* definition, const size_t definitionSize) {
  const char* tab = strchr(line, '\t');
  if (!tab) {
    return false;
  }

  char normalizedKey[DictionaryWordList::MAX_WORD_BYTES];
  normalizeLookupWord(line, static_cast<size_t>(tab - line), normalizedKey, sizeof(normalizedKey));
  if (strcmp(normalizedKey, word) != 0) {
    return false;
  }

  snprintf(definition, definitionSize, "%s", tab + 1);
  return true;
}

bool openDictionaryFileForWord(const char* word, HalFile& file) {
  if (word && word[0] != '\0') {
    const char shard = toAsciiLower(word[0]);
    if (isAsciiAlpha(shard) || isAsciiDigit(shard)) {
      char shardPath[24];
      snprintf(shardPath, sizeof(shardPath), "%s/%c.tsv", DICTIONARY_SHARD_DIR, shard);
      if (Storage.exists(shardPath) && Storage.openFileForRead("DIC", shardPath, file)) {
        return true;
      }
    }
  }

  return Storage.exists(DICTIONARY_FLAT_PATH) && Storage.openFileForRead("DIC", DICTIONARY_FLAT_PATH, file);
}
}  // namespace

bool DictionaryWordList::addRawWord(const std::string& raw) {
  if (count >= MAX_WORDS) {
    return false;
  }

  char normalized[MAX_WORD_BYTES];
  normalizeLookupWord(raw.c_str(), raw.size(), normalized, sizeof(normalized));
  if (strlen(normalized) < 2) {
    return false;
  }

  for (size_t i = 0; i < count; i++) {
    if (strcmp(words[i], normalized) == 0) {
      return false;
    }
  }

  snprintf(words[count], sizeof(words[count]), "%s", normalized);
  count++;
  return true;
}

EpubDictionaryActivity::EpubDictionaryActivity(GfxRenderer& renderer, MappedInputManager& mappedInput,
                                               const DictionaryWordList& words)
    : Activity("EpubDictionary", renderer, mappedInput), words(words) {}

void EpubDictionaryActivity::onEnter() {
  Activity::onEnter();
  selectedIndex = 0;
  viewMode = ViewMode::WordList;
  requestUpdate();
}

void EpubDictionaryActivity::onExit() { Activity::onExit(); }

void EpubDictionaryActivity::loop() {
  if (mappedInput.wasReleased(MappedInputManager::Button::Back)) {
    if (viewMode == ViewMode::Definition) {
      viewMode = ViewMode::WordList;
      requestUpdate();
      return;
    }
    ActivityResult result;
    result.isCancelled = true;
    setResult(std::move(result));
    finish();
    return;
  }

  if (viewMode == ViewMode::Definition) {
    if (mappedInput.wasReleased(MappedInputManager::Button::Confirm)) {
      viewMode = ViewMode::WordList;
      requestUpdate();
    }
    return;
  }

  if (mappedInput.wasReleased(MappedInputManager::Button::Confirm)) {
    lookupSelectedWord();
    viewMode = ViewMode::Definition;
    requestUpdate();
    return;
  }

  buttonNavigator.onNext([this] {
    if (words.count > 0) {
      selectedIndex = ButtonNavigator::nextIndex(selectedIndex, static_cast<int>(words.count));
      requestUpdate();
    }
  });

  buttonNavigator.onPrevious([this] {
    if (words.count > 0) {
      selectedIndex = ButtonNavigator::previousIndex(selectedIndex, static_cast<int>(words.count));
      requestUpdate();
    }
  });
}

void EpubDictionaryActivity::lookupSelectedWord() {
  definitionText[0] = '\0';
  selectedWord[0] = '\0';
  lookupStatus = LookupStatus::NotFound;

  if (selectedIndex < 0 || selectedIndex >= static_cast<int>(words.count)) {
    return;
  }

  snprintf(selectedWord, sizeof(selectedWord), "%s", words.words[selectedIndex]);

  HalFile file;
  if (!openDictionaryFileForWord(selectedWord, file)) {
    lookupStatus = LookupStatus::MissingFile;
    return;
  }

  // Read in blocks rather than one HalStorage-mutex-locked byte at a time: a shard
  // is tens/hundreds of KB, so per-byte file.read() means that many locked SD round
  // trips per lookup. Both buffers are on the heap (only one lookup runs at a time)
  // to stay well under the small activity-task stack.
  constexpr size_t kBlockBytes = 512;
  auto block = makeUniqueNoThrow<char[]>(kBlockBytes);
  auto line = makeUniqueNoThrow<char[]>(MAX_DICTIONARY_LINE_BYTES);
  if (!block || !line) {
    LOG_ERR("DICT", "OOM: lookup buffers");
    return;
  }

  size_t lineLen = 0;

  while (true) {
    const int n = file.read(block.get(), kBlockBytes);
    if (n <= 0) {
      break;
    }

    for (int i = 0; i < n; i++) {
      const char c = block[i];
      if (c == '\r') {
        continue;
      }

      if (c == '\n') {
        line[lineLen] = '\0';
        if (copyDefinitionIfLineMatches(line.get(), selectedWord, definitionText, sizeof(definitionText))) {
          lookupStatus = LookupStatus::Found;
          return;
        }
        lineLen = 0;
        continue;
      }

      // The key sits at the line start (before the tab); any chars past the buffer
      // are definition tail that copyDefinitionIfLineMatches would truncate anyway,
      // so drop them silently instead of discarding the whole (matchable) line.
      if (lineLen + 1 < MAX_DICTIONARY_LINE_BYTES) {
        line[lineLen++] = c;
      }
    }
    delay(1);  // yield once per block, not per byte
  }

  line[lineLen] = '\0';
  if (copyDefinitionIfLineMatches(line.get(), selectedWord, definitionText, sizeof(definitionText))) {
    lookupStatus = LookupStatus::Found;
  }
}

void EpubDictionaryActivity::render(RenderLock&&) {
  if (viewMode == ViewMode::Definition) {
    renderDefinition();
  } else {
    renderWordList();
  }
}

void EpubDictionaryActivity::renderWordList() {
  renderer.clearScreen();

  const auto metrics = UITheme::getInstance().getMetrics();
  Rect screen = UITheme::getInstance().getScreenSafeArea(renderer, true, false);
  GUI.drawHeader(renderer, Rect{screen.x, screen.y + metrics.topPadding, screen.width, metrics.headerHeight},
                 tr(STR_DICTIONARY));

  const int contentTop =
      screen.y + metrics.topPadding + metrics.headerHeight + metrics.tabBarHeight + metrics.verticalSpacing;
  const int contentHeight = screen.height - contentTop - metrics.verticalSpacing;

  GUI.drawSubHeader(
      renderer,
      Rect{screen.x, screen.y + metrics.topPadding + metrics.headerHeight, screen.width, metrics.tabBarHeight},
      tr(STR_SELECT_WORD), nullptr);

  if (words.count == 0) {
    renderer.drawCenteredText(UI_10_FONT_ID, contentTop + 30, tr(STR_NO_WORDS_ON_PAGE));
  } else {
    GUI.drawList(
        renderer, Rect{screen.x, contentTop, screen.width, contentHeight}, static_cast<int>(words.count), selectedIndex,
        [this](int index) { return std::string(words.words[index]); }, nullptr, nullptr, nullptr, false);
  }

  const auto labels = mappedInput.mapLabels(tr(STR_BACK), tr(STR_SELECT), tr(STR_DIR_UP), tr(STR_DIR_DOWN));
  UITheme::getInstance().suppressBrandLogoOnce();
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}

void EpubDictionaryActivity::renderDefinition() {
  renderer.clearScreen();

  const auto metrics = UITheme::getInstance().getMetrics();
  Rect screen = UITheme::getInstance().getScreenSafeArea(renderer, true, false);
  GUI.drawHeader(renderer, Rect{screen.x, screen.y + metrics.topPadding, screen.width, metrics.headerHeight},
                 selectedWord[0] ? selectedWord : tr(STR_DICTIONARY));

  const int contentTop = screen.y + metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;
  const int contentX = screen.x + metrics.contentSidePadding;
  const int contentWidth = screen.width - metrics.contentSidePadding * 2;
  const int lineHeight = renderer.getLineHeight(UI_10_FONT_ID) + 4;
  const int maxLines = std::max(1, (screen.height - contentTop - metrics.verticalSpacing) / lineHeight);

  const char* body = definitionText;
  if (lookupStatus == LookupStatus::MissingFile) {
    body = tr(STR_DICTIONARY_FILE_MISSING);
    renderer.drawText(UI_10_FONT_ID, contentX, contentTop + lineHeight, tr(STR_DICTIONARY_FILE_HINT));
  } else if (lookupStatus == LookupStatus::NotFound || definitionText[0] == '\0') {
    body = tr(STR_DEFINITION_NOT_FOUND);
  }

  const auto lines = renderer.wrappedText(UI_10_FONT_ID, body, contentWidth, maxLines);
  for (size_t i = 0; i < lines.size(); i++) {
    renderer.drawText(UI_10_FONT_ID, contentX, contentTop + static_cast<int>(i) * lineHeight, lines[i].c_str());
  }

  const auto labels = mappedInput.mapLabels(tr(STR_BACK), tr(STR_SELECT), "", "");
  UITheme::getInstance().suppressBrandLogoOnce();
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}
