#pragma once

#include <GfxRenderer.h>

#include <cstdint>

#include "activities/util/ToolActivityBase.h"

// A small clock utility with three modes, switched left/right like tabs:
//   - Clock     : current wall time + date from the DS3231 RTC (set it with NTP).
//   - Stopwatch : count-up timer (Confirm start/stop, Up reset). millis()-based.
//   - Timer     : count-down (Up/Down set minutes, Confirm start/pause); a visual
//                 alert blinks when it hits zero (the device has no buzzer).
//
// Stopwatch/Timer use millis() so they work without an RTC sync; only the Clock
// mode needs the RTC. The screen refreshes ~1 Hz while a timer is running.
class ClockActivity final : public ToolActivityBase {
 public:
  ClockActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : ToolActivityBase("Clock", renderer, mappedInput, ToolItem::CLOCK) {}

  void onEnter() override;
  void loop() override;
  void render(RenderLock&&) override;
  bool preventAutoSleep() override { return swRunning || tmRunning || tmExpired; }

 private:
  enum class Mode { Clock, Stopwatch, Timer, COUNT };
  Mode mode = Mode::Clock;

  // Stopwatch
  bool swRunning = false;
  uint32_t swStartMs = 0;
  uint32_t swAccumMs = 0;

  // Timer
  bool tmRunning = false;
  bool tmExpired = false;
  uint32_t tmStartMs = 0;
  uint32_t tmAccumMs = 0;
  uint32_t tmSetMs = 5 * 60 * 1000;  // default 5 min
  bool blinkOn = true;               // expired-alert blink state

  uint32_t lastTickMs = 0;
  int lastMinute = -1;  // for low-wear minute-change refresh in Clock mode

  uint32_t stopwatchElapsed() const;
  uint32_t timerRemaining() const;

  void renderClock();
  void renderStopwatch();
  void renderTimer();
};
