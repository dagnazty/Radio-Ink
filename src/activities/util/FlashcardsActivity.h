#pragma once

#include <GfxRenderer.h>

#include <cstdint>
#include <string>
#include <vector>

#include "activities/util/ToolActivityBase.h"
#include "util/ButtonNavigator.h"

// Spaced-repetition flashcards, reading tab-separated decks off the SD card.
//
// Decks live at /flashcards/<name>.tsv, one card per line as "front<TAB>back".
// Scheduling state is persisted alongside as /flashcards/<name>.sched (a plain
// text sidecar so it can be inspected or deleted by hand).
//
// Memory: card text is NOT held in RAM. The deck is indexed once into a vector of
// byte offsets plus 12 bytes of schedule state per card, and each card's text is
// read from SD on demand as it is shown. A 512-card deck therefore costs ~6 KB
// regardless of how long the cards are.
class FlashcardsActivity final : public ToolActivityBase {
 public:
  FlashcardsActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : ToolActivityBase("Flashcards", renderer, mappedInput, ToolItem::FLASHCARDS) {}

  void onEnter() override;
  void onExit() override;
  void loop() override;
  void render(RenderLock&&) override;

 private:
  enum class View { DeckList, Question, Answer, Summary };

  // Per-card scheduling state. Kept deliberately small -- one of these exists for
  // every card in the open deck.
  struct Card {
    uint32_t offset = 0;        // byte offset of this card's line in the .tsv
    uint32_t dueEpoch = 0;      // UTC epoch when this card is next due; 0 = new
    uint16_t intervalDays = 0;  // current SM-2 interval
    uint16_t easeX100 = 250;    // SM-2 ease factor scaled by 100 (2.50 default)
  };

  View view = View::DeckList;
  ButtonNavigator buttonNavigator;

  std::vector<std::string> decks;  // file names found under /flashcards
  int selectedDeck = 0;

  std::string deckPath;
  std::string schedPath;
  std::vector<Card> cards;
  std::vector<uint16_t> queue;  // indices into `cards` due this session
  int queuePos = 0;
  bool scheduleDirty = false;

  // Text of the card currently on screen, read from SD when the card is shown.
  std::string front;
  std::string back;

  // Session tally, shown on the summary screen.
  int reviewedCount = 0;
  int againCount = 0;

  // Without a valid RTC there is no "today", so scheduling is skipped and the
  // deck is simply walked end to end.
  bool clockValid = false;
  uint32_t nowEpoch = 0;

  static constexpr int MAX_CARDS = 512;
  static constexpr size_t MAX_FIELD_LEN = 512;

  void scanDecks();
  bool openDeck(const std::string& name);
  void buildQueue();
  bool loadCardText(int cardIndex);
  void showNextCard();
  // grade: 0 = Again, 1 = Good, 2 = Easy.
  void gradeCurrent(int grade);
  void loadSchedule();
  void saveSchedule();

  void renderDeckList();
  void renderCard(bool showAnswer);
  void renderSummary();
};
