#include "FlashcardsActivity.h"

#include <GfxRenderer.h>
#include <HalClock.h>
#include <HalStorage.h>
#include <I18n.h>
#include <Logging.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "MappedInputManager.h"
#include "components/UITheme.h"
#include "fontIds.h"

namespace {
constexpr const char* MODULE = "Flashcards";
constexpr const char* DECK_DIR = "/flashcards";
constexpr const char* DECK_SUFFIX = ".tsv";
constexpr uint32_t SECONDS_PER_DAY = 86400;
constexpr size_t NAME_BUFFER_SIZE = 128;
// SD reads are chunked rather than byte-at-a-time; a card line is normally well
// under this, and anything longer is truncated at MAX_FIELD_LEN.
constexpr size_t READ_CHUNK = 256;

bool hasSuffix(const std::string& value, const char* suffix) {
  const size_t suffixLen = strlen(suffix);
  return value.size() > suffixLen && value.compare(value.size() - suffixLen, suffixLen, suffix) == 0;
}

// Greedy word wrap. Falls back to breaking mid-word only when a single word is
// itself wider than the line.
void drawWrappedCentered(GfxRenderer& renderer, int fontId, int centreX, int y, int maxWidth, const std::string& text,
                         EpdFontFamily::Style style) {
  std::string remaining = text;
  const int lineHeight = renderer.getLineHeight(fontId);
  while (!remaining.empty()) {
    std::string line = remaining;
    size_t consumed = remaining.size();
    while (renderer.getTextWidth(fontId, line.c_str()) > maxWidth && line.size() > 1) {
      const size_t space = line.find_last_of(' ');
      if (space == std::string::npos) {
        line.pop_back();
        consumed = line.size();
      } else {
        line.erase(space);
        consumed = space + 1;  // skip the space itself on the next line
      }
    }
    const int width = renderer.getTextWidth(fontId, line.c_str());
    renderer.drawText(fontId, centreX - width / 2, y, line.c_str(), true, style);
    y += lineHeight;
    remaining = consumed >= remaining.size() ? std::string() : remaining.substr(consumed);
  }
}
}  // namespace

void FlashcardsActivity::onEnter() {
  Activity::onEnter();
  clockValid = halClock.getUnixTime(nowEpoch);
  scanDecks();
  requestUpdate();
}

void FlashcardsActivity::onExit() {
  saveSchedule();
  Activity::onExit();
}

void FlashcardsActivity::scanDecks() {
  decks.clear();

  HalFile root = Storage.open(DECK_DIR);
  if (!root || !root.isDirectory()) {
    LOG_INF(MODULE, "No %s directory", DECK_DIR);
    return;
  }
  root.rewindDirectory();

  char nameBuffer[NAME_BUFFER_SIZE];
  for (auto file = root.openNextFile(); file; file = root.openNextFile()) {
    if (file.isDirectory()) continue;
    file.getName(nameBuffer, sizeof(nameBuffer));
    std::string name(nameBuffer);
    if (name.empty() || name[0] == '.') continue;
    if (hasSuffix(name, DECK_SUFFIX)) decks.push_back(std::move(name));
  }

  std::sort(decks.begin(), decks.end());
}

bool FlashcardsActivity::openDeck(const std::string& name) {
  deckPath = std::string(DECK_DIR) + "/" + name;
  schedPath = deckPath.substr(0, deckPath.size() - strlen(DECK_SUFFIX)) + ".sched";

  cards.clear();
  queue.clear();
  queuePos = 0;
  scheduleDirty = false;
  reviewedCount = 0;
  againCount = 0;

  HalFile file;
  if (!Storage.openFileForRead(MODULE, deckPath, file)) {
    LOG_ERR(MODULE, "Cannot open deck %s", deckPath.c_str());
    return false;
  }

  // Index line starts. Only offsets are kept -- card text stays on the card.
  cards.reserve(64);
  uint32_t offset = 0;
  bool atLineStart = true;
  bool lineHasTab = false;
  uint32_t lineStart = 0;

  uint8_t chunk[READ_CHUNK];
  int readCount;
  while ((readCount = file.read(chunk, sizeof(chunk))) > 0) {
    for (int i = 0; i < readCount; i++) {
      const char c = static_cast<char>(chunk[i]);
      if (atLineStart) {
        lineStart = offset;
        lineHasTab = false;
        atLineStart = false;
      }
      if (c == '\t') {
        lineHasTab = true;
      } else if (c == '\n') {
        // A card needs both a front and a back; anything else is a comment or blank.
        if (lineHasTab && static_cast<int>(cards.size()) < MAX_CARDS) {
          Card card;
          card.offset = lineStart;
          cards.push_back(card);
        }
        atLineStart = true;
      }
      offset++;
    }
    if (static_cast<int>(cards.size()) >= MAX_CARDS) break;
  }
  // Final line without a trailing newline.
  if (!atLineStart && lineHasTab && static_cast<int>(cards.size()) < MAX_CARDS) {
    Card card;
    card.offset = lineStart;
    cards.push_back(card);
  }

  if (cards.empty()) {
    LOG_ERR(MODULE, "Deck %s has no valid cards", deckPath.c_str());
    return false;
  }

  loadSchedule();
  buildQueue();
  return true;
}

void FlashcardsActivity::loadSchedule() {
  HalFile file;
  if (!Storage.openFileForRead(MODULE, schedPath, file)) return;  // first run, no sidecar yet

  // Lines are "index due interval ease". Unknown indices are ignored so a deck
  // can be edited without invalidating the whole schedule.
  std::string line;
  line.reserve(64);
  uint8_t chunk[READ_CHUNK];
  int readCount;
  while ((readCount = file.read(chunk, sizeof(chunk))) > 0) {
    for (int i = 0; i < readCount; i++) {
      const char c = static_cast<char>(chunk[i]);
      if (c != '\n') {
        if (line.size() < 64) line += c;
        continue;
      }
      unsigned index = 0, due = 0, interval = 0, ease = 0;
      if (sscanf(line.c_str(), "%u %u %u %u", &index, &due, &interval, &ease) == 4 && index < cards.size()) {
        cards[index].dueEpoch = due;
        cards[index].intervalDays = static_cast<uint16_t>(interval);
        cards[index].easeX100 = static_cast<uint16_t>(ease ? ease : 250);
      }
      line.clear();
    }
  }
}

void FlashcardsActivity::saveSchedule() {
  if (!scheduleDirty || cards.empty() || schedPath.empty()) return;

  Storage.ensureDirectoryExists(DECK_DIR);

  HalFile file;
  if (!Storage.openFileForWrite(MODULE, schedPath, file)) {
    LOG_ERR(MODULE, "Cannot write %s", schedPath.c_str());
    return;
  }

  // One write at exit rather than one per card: SD sectors have a finite erase count.
  char line[64];
  for (size_t i = 0; i < cards.size(); i++) {
    const Card& card = cards[i];
    if (card.dueEpoch == 0 && card.intervalDays == 0) continue;  // never reviewed
    const int written =
        snprintf(line, sizeof(line), "%u %u %u %u\n", static_cast<unsigned>(i), static_cast<unsigned>(card.dueEpoch),
                 static_cast<unsigned>(card.intervalDays), static_cast<unsigned>(card.easeX100));
    if (written > 0) file.write(line, static_cast<size_t>(written));
  }
  file.flush();
  scheduleDirty = false;
}

void FlashcardsActivity::buildQueue() {
  queue.clear();
  queue.reserve(cards.size());
  for (size_t i = 0; i < cards.size(); i++) {
    // Without a clock every card is fair game; with one, only what is actually due.
    if (!clockValid || cards[i].dueEpoch == 0 || cards[i].dueEpoch <= nowEpoch) {
      queue.push_back(static_cast<uint16_t>(i));
    }
  }
  queuePos = 0;
}

bool FlashcardsActivity::loadCardText(int cardIndex) {
  front.clear();
  back.clear();
  if (cardIndex < 0 || cardIndex >= static_cast<int>(cards.size())) return false;

  HalFile file;
  if (!Storage.openFileForRead(MODULE, deckPath, file)) return false;
  if (!file.seekSet(cards[cardIndex].offset)) return false;

  // Read forward to the end of the line, splitting on the first tab.
  bool inBack = false;
  bool truncated = false;
  uint8_t chunk[READ_CHUNK];
  int readCount;
  while (!truncated && (readCount = file.read(chunk, sizeof(chunk))) > 0) {
    for (int i = 0; i < readCount; i++) {
      const char c = static_cast<char>(chunk[i]);
      if (c == '\n') {
        truncated = true;
        break;
      }
      if (c == '\r') continue;
      if (c == '\t' && !inBack) {
        inBack = true;
        continue;
      }
      std::string& target = inBack ? back : front;
      if (target.size() < MAX_FIELD_LEN) target += c;
    }
  }

  return !front.empty();
}

void FlashcardsActivity::showNextCard() {
  if (queuePos >= static_cast<int>(queue.size())) {
    view = View::Summary;
    requestUpdate();
    return;
  }
  if (!loadCardText(queue[queuePos])) {
    // Unreadable card: skip rather than stall the session.
    queuePos++;
    showNextCard();
    return;
  }
  view = View::Question;
  requestUpdate();
}

void FlashcardsActivity::gradeCurrent(int grade) {
  if (queuePos >= static_cast<int>(queue.size())) return;

  Card& card = cards[queue[queuePos]];
  reviewedCount++;

  if (grade == 0) {
    // Again: reset the interval and pull the ease down, floored at 1.30 as SM-2 does.
    againCount++;
    card.intervalDays = 0;
    card.easeX100 = static_cast<uint16_t>(std::max(130, static_cast<int>(card.easeX100) - 20));
    // Re-queue at the back so it comes round again this session.
    queue.push_back(queue[queuePos]);
  } else {
    if (card.intervalDays == 0) {
      card.intervalDays = 1;
    } else if (card.intervalDays == 1) {
      card.intervalDays = grade == 2 ? 4 : 3;
    } else {
      const int scaled = static_cast<int>(card.intervalDays) * static_cast<int>(card.easeX100) / 100;
      card.intervalDays = static_cast<uint16_t>(std::min(3650, grade == 2 ? scaled * 13 / 10 : scaled));
    }
    if (grade == 2) card.easeX100 = static_cast<uint16_t>(std::min(350, static_cast<int>(card.easeX100) + 15));
  }

  if (clockValid) card.dueEpoch = nowEpoch + static_cast<uint32_t>(card.intervalDays) * SECONDS_PER_DAY;
  scheduleDirty = true;

  queuePos++;
  showNextCard();
}

void FlashcardsActivity::loop() {
  using Button = MappedInputManager::Button;

  if (view == View::DeckList) {
    if (handleToolBack()) return;
    if (decks.empty()) return;

    if (mappedInput.wasPressed(Button::Confirm)) {
      if (openDeck(decks[selectedDeck])) {
        showNextCard();
      } else {
        requestUpdate();
      }
      return;
    }
    buttonNavigator.onNext([this] {
      selectedDeck = ButtonNavigator::nextIndex(selectedDeck, static_cast<int>(decks.size()));
      requestUpdate();
    });
    buttonNavigator.onPrevious([this] {
      selectedDeck = ButtonNavigator::previousIndex(selectedDeck, static_cast<int>(decks.size()));
      requestUpdate();
    });
    return;
  }

  if (view == View::Summary) {
    if (handleToolBack()) return;
    if (mappedInput.wasPressed(Button::Confirm)) {
      saveSchedule();
      view = View::DeckList;
      requestUpdate();
    }
    return;
  }

  // Question / Answer: Back saves progress and returns to the deck list rather
  // than dropping straight out of the tool mid-session.
  if (mappedInput.wasPressed(Button::Back)) {
    saveSchedule();
    view = View::DeckList;
    requestUpdate();
    return;
  }

  if (view == View::Question) {
    if (mappedInput.wasPressed(Button::Confirm)) {
      view = View::Answer;
      requestUpdate();
    }
    return;
  }

  // View::Answer -- grade the card.
  if (mappedInput.wasPressed(Button::Left)) {
    gradeCurrent(0);
    return;
  }
  if (mappedInput.wasPressed(Button::Confirm)) {
    gradeCurrent(1);
    return;
  }
  if (mappedInput.wasPressed(Button::Right)) {
    gradeCurrent(2);
  }
}

void FlashcardsActivity::renderDeckList() {
  const auto W = renderer.getScreenWidth();
  const auto H = renderer.getScreenHeight();
  const auto& metrics = UITheme::getInstance().getMetrics();

  beginToolRender(tr(STR_FLASHCARDS));

  if (decks.empty()) {
    const Rect full{0, 0, W, H};
    UITheme::drawCenteredText(renderer, full, UI_10_FONT_ID, static_cast<int>(H) / 2 - 12, tr(STR_FC_NO_DECKS));
    UITheme::drawCenteredText(renderer, full, UI_10_FONT_ID, static_cast<int>(H) / 2 + 12, tr(STR_FC_DECK_HINT));
    endToolRender(tr(STR_BTN_BACK), "", "", "");
    return;
  }

  const Rect content = toolContentRect();
  const int lineHeight = renderer.getLineHeight(UI_12_FONT_ID) + metrics.verticalSpacing / 2;
  const int visibleRows = std::max(1, content.height / lineHeight);
  const int firstRow =
      std::max(0, std::min(selectedDeck - visibleRows / 2, static_cast<int>(decks.size()) - visibleRows));

  int y = content.y + metrics.verticalSpacing;
  for (int i = firstRow; i < static_cast<int>(decks.size()) && i < firstRow + visibleRows; i++) {
    // Strip the .tsv so the list reads as deck names, not file names.
    std::string label = decks[i].substr(0, decks[i].size() - strlen(DECK_SUFFIX));
    if (i == selectedDeck) label = "> " + label;
    renderer.drawText(UI_12_FONT_ID, content.x, y, label.c_str(), true,
                      i == selectedDeck ? EpdFontFamily::BOLD : EpdFontFamily::REGULAR);
    y += lineHeight;
  }

  endToolRender(tr(STR_BTN_BACK), tr(STR_FC_STUDY), "", "");
}

void FlashcardsActivity::renderCard(bool showAnswer) {
  const auto& metrics = UITheme::getInstance().getMetrics();

  char subtitle[32];
  const int remaining = static_cast<int>(queue.size()) - queuePos;
  snprintf(subtitle, sizeof(subtitle), tr(STR_FC_REMAINING_FMT), remaining);
  beginToolRender(tr(STR_FLASHCARDS), subtitle);

  const Rect content = toolContentRect();
  const int centreX = content.x + content.width / 2;
  const int maxWidth = content.width;

  if (!showAnswer) {
    drawWrappedCentered(renderer, NOTOSANS_18_FONT_ID, centreX, content.y + content.height / 3, maxWidth, front,
                        EpdFontFamily::BOLD);
    endToolRender(tr(STR_BTN_BACK), tr(STR_FC_SHOW_ANSWER), "", "");
    return;
  }

  // Answer side: question on top, rule, answer beneath.
  drawWrappedCentered(renderer, UI_12_FONT_ID, centreX, content.y + metrics.verticalSpacing, maxWidth, front,
                      EpdFontFamily::REGULAR);

  const int ruleY = content.y + content.height / 3;
  renderer.drawLine(content.x + maxWidth / 4, ruleY, content.x + maxWidth * 3 / 4, ruleY, true);

  drawWrappedCentered(renderer, NOTOSANS_18_FONT_ID, centreX, ruleY + metrics.verticalSpacing * 2, maxWidth, back,
                      EpdFontFamily::BOLD);

  endToolRender(tr(STR_BTN_BACK), tr(STR_FC_GOOD), tr(STR_FC_AGAIN), tr(STR_FC_EASY));
}

void FlashcardsActivity::renderSummary() {
  const auto W = renderer.getScreenWidth();
  const auto H = renderer.getScreenHeight();

  beginToolRender(tr(STR_FLASHCARDS));

  const Rect full{0, 0, W, H};
  const int centreY = static_cast<int>(H) / 2;
  UITheme::drawCenteredText(renderer, full, NOTOSANS_18_FONT_ID, centreY - 30, tr(STR_FC_SESSION_DONE));

  char line[64];
  snprintf(line, sizeof(line), tr(STR_FC_REVIEWED_FMT), reviewedCount, againCount);
  UITheme::drawCenteredText(renderer, full, UI_12_FONT_ID, centreY + 10, line);

  if (!clockValid) {
    UITheme::drawCenteredText(renderer, full, UI_10_FONT_ID, centreY + 40, tr(STR_FC_NO_CLOCK));
  }

  endToolRender(tr(STR_BTN_BACK), tr(STR_FC_DECKS), "", "");
}

void FlashcardsActivity::render(RenderLock&&) {
  switch (view) {
    case View::DeckList:
      renderDeckList();
      break;
    case View::Question:
      renderCard(false);
      break;
    case View::Answer:
      renderCard(true);
      break;
    case View::Summary:
      renderSummary();
      break;
  }
}
