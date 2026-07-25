#pragma once

#include <GfxRenderer.h>

#include <string>

#include "activities/util/ToolActivityBase.h"

// On-device password / passphrase generator: esp_random()-backed, length and
// character set adjustable. Nothing is persisted -- generate, read it off the
// screen, done.
class PasswordGenActivity final : public ToolActivityBase {
 public:
  PasswordGenActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : ToolActivityBase("PasswordGen", renderer, mappedInput, ToolItem::PASSWORD_GEN) {}

  void onEnter() override;
  void loop() override;
  void render(RenderLock&&) override;

 private:
  enum class Charset { LettersDigits, LettersDigitsSymbols, DigitsOnly, COUNT };

  int length = 16;
  Charset charset = Charset::LettersDigitsSymbols;
  std::string generated;

  static constexpr int MIN_LEN = 6;
  static constexpr int MAX_LEN = 48;

  void regenerate();
  const char* charsetLabel() const;
  double entropyBits() const;
};
