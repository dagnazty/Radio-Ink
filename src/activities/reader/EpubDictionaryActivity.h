#pragma once

#include <I18n.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "activities/Activity.h"
#include "util/ButtonNavigator.h"

struct DictionaryWordList {
  static constexpr size_t MAX_WORDS = 80;
  static constexpr size_t MAX_WORD_BYTES = 32;

  char words[MAX_WORDS][MAX_WORD_BYTES] = {};
  size_t count = 0;

  bool addRawWord(const std::string& raw);
};

class EpubDictionaryActivity final : public Activity {
 public:
  EpubDictionaryActivity(GfxRenderer& renderer, MappedInputManager& mappedInput, const DictionaryWordList& words);

  void onEnter() override;
  void onExit() override;
  void loop() override;
  void render(RenderLock&&) override;

 private:
  enum class ViewMode : uint8_t {
    WordList,
    Definition,
  };

  enum class LookupStatus : uint8_t {
    Found,
    NotFound,
    MissingFile,
  };

  DictionaryWordList words;
  int selectedIndex = 0;
  ViewMode viewMode = ViewMode::WordList;
  LookupStatus lookupStatus = LookupStatus::NotFound;
  char selectedWord[DictionaryWordList::MAX_WORD_BYTES] = {};
  char definitionText[512] = {};
  ButtonNavigator buttonNavigator;

  void lookupSelectedWord();
  void renderWordList();
  void renderDefinition();
};
