#pragma once

#include <GfxRenderer.h>

#include <string>

#include "activities/util/ToolActivityBase.h"

// Quick text transforms for CTF/forensics work: Base64, Hex, and URL encode or
// decode. Left/Right cycle the mode; the current input is re-run through
// whichever mode is selected.
class EncodeDecodeActivity final : public ToolActivityBase {
 public:
  EncodeDecodeActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : ToolActivityBase("EncodeDecode", renderer, mappedInput, ToolItem::ENCODE_DECODE) {}

  void onEnter() override;
  void loop() override;
  void render(RenderLock&&) override;

 private:
  enum class Mode { Base64Encode, Base64Decode, HexEncode, HexDecode, UrlEncode, UrlDecode, COUNT };

  Mode mode = Mode::Base64Encode;
  std::string input;
  std::string output;
  bool outputValid = true;  // false if decode failed (malformed input)

  void promptInput();
  void recompute();
  const char* modeLabel() const;
};
