#pragma once

#include <HalStorage.h>
#include <Memory.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "activities/Activity.h"

// Monochrome flipbook "movie" player. Streams 1-bit frame packs (.rivid, built
// off-device by scripts/gen_video.py) from /.radioink/movies/ on the SD card and
// blits them upscaled to the e-ink panel with fast partial refresh. No audio,
// a few fps -- a novelty, not full-motion video (the panel physically can't).
// Frames stay at their small source resolution on SD and are nearest-neighbour
// scaled on device, so the player only ever holds one frame in RAM.
class MoviePlayerActivity : public Activity {
 public:
  explicit MoviePlayerActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : Activity("Movies", renderer, mappedInput) {}

  void onEnter() override;
  void onExit() override;
  void loop() override;
  void render(RenderLock&&) override;
  // Run the loop back-to-back while playing so frames advance as fast as the
  // panel allows; idle (list/paused) can power-save normally.
  bool skipLoopDelay() override { return state == State::PLAYING; }
  bool preventAutoSleep() override { return state == State::PLAYING || state == State::PAUSED; }

 private:
  enum class State { LIST, PLAYING, PAUSED, ENDED, ERROR };

  void loadMovieList();
  bool startPlayback(const std::string& name);
  void stopPlayback();           // close file, return to the list
  void advanceFrame();           // step currentFrame on the fps timer
  void renderList();
  void drawCurrentFrame();       // blit currentFrame scaled + centered
  void renderMessage(const char* title, const char* line1, const char* line2);

  State state = State::LIST;
  std::vector<std::string> movies;  // .rivid filenames in MOVIES_DIR
  int selected = 0;
  int listScroll = 0;
  std::string status;

  // Open movie + decoded header.
  HalFile file;
  uint16_t vidW = 0;
  uint16_t vidH = 0;
  uint8_t fps = 3;
  uint32_t frameCount = 0;
  uint32_t rowBytes = 0;    // bytes per packed row = (vidW + 7) / 8
  uint32_t frameBytes = 0;  // rowBytes * vidH
  std::unique_ptr<uint8_t[]> frameBuf;  // exactly one frame
  uint32_t currentFrame = 0;
  uint32_t lastFrameMs = 0;

  // Destination rect (panel coords), precomputed to preserve aspect.
  int destX = 0;
  int destY = 0;
  int destW = 0;
  int destH = 0;

  // Scaling lookup tables built once per playback so the per-frame blit is a
  // table lookup instead of an integer divide per output pixel (~384k/frame).
  std::unique_ptr<uint16_t[]> colByte;  // [destW] source byte index for each output column
  std::unique_ptr<uint8_t[]> colMask;   // [destW] source bit mask for each output column
  std::unique_ptr<uint16_t[]> rowOff;   // [destH] source row byte offset for each output row
};
