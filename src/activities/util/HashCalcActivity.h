#pragma once

#include <GfxRenderer.h>

#include <string>

#include "activities/util/ToolActivityBase.h"

// Computes MD5 / SHA-1 / SHA-256 of typed text (mbedtls, already linked in for
// TOTP). Useful for CTF/forensics field work: verify a hash, fingerprint a
// string, check a known-plaintext guess.
class HashCalcActivity final : public ToolActivityBase {
 public:
  HashCalcActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : ToolActivityBase("HashCalc", renderer, mappedInput, ToolItem::HASH_CALC) {}

  void onEnter() override;
  void loop() override;
  void render(RenderLock&&) override;

 private:
  std::string input;
  std::string md5Hex, sha1Hex, sha256Hex;

  void promptInput();
  void recompute();
};
