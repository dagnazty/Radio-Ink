#include "ClockActivity.h"

#include <Arduino.h>
#include <GfxRenderer.h>
#include <HalClock.h>
#include <I18n.h>

#include <cstdio>
#include <ctime>

#include "MappedInputManager.h"
#include "RadioInkSettings.h"
#include "components/UITheme.h"
#include "fontIds.h"

namespace {
constexpr int BIG_FONT_ID = NOTOSANS_18_FONT_ID;  // largest available
constexpr int SUB_FONT_ID = NOTOSANS_14_FONT_ID;
constexpr uint32_t TIMER_STEP_MS = 60 * 1000;       // 1-minute set steps
constexpr uint32_t TIMER_MAX_MS = 180 * 60 * 1000;  // 3 h

const char* modeName(int m) {
  switch (m) {
    case 0:
      return tr(STR_CLOCK);
    case 1:
      return tr(STR_STOPWATCH);
    default:
      return tr(STR_TIMER);
  }
}

// Format milliseconds as M:SS, or H:MM:SS past an hour.
void fmtDuration(uint32_t ms, char* buf, size_t n) {
  const uint32_t total = ms / 1000;
  const uint32_t h = total / 3600, m = (total / 60) % 60, s = total % 60;
  if (h > 0)
    snprintf(buf, n, "%u:%02u:%02u", static_cast<unsigned>(h), static_cast<unsigned>(m), static_cast<unsigned>(s));
  else
    snprintf(buf, n, "%u:%02u", static_cast<unsigned>(m), static_cast<unsigned>(s));
}
}  // namespace

void ClockActivity::onEnter() {
  Activity::onEnter();
  lastTickMs = millis();
  lastMinute = -1;
  requestUpdate();
}

uint32_t ClockActivity::stopwatchElapsed() const { return swAccumMs + (swRunning ? millis() - swStartMs : 0); }

uint32_t ClockActivity::timerRemaining() const {
  const uint32_t elapsed = tmAccumMs + (tmRunning ? millis() - tmStartMs : 0);
  return elapsed >= tmSetMs ? 0 : tmSetMs - elapsed;
}

void ClockActivity::loop() {
  using Button = MappedInputManager::Button;

  if (handleToolBack()) {
    return;
  }

  // Left/Right switch mode (tabs). Allowed any time; running timers keep counting.
  if (mappedInput.wasPressed(Button::Left)) {
    mode =
        static_cast<Mode>((static_cast<int>(mode) + static_cast<int>(Mode::COUNT) - 1) % static_cast<int>(Mode::COUNT));
    lastMinute = -1;
    requestUpdate();
    return;
  }
  if (mappedInput.wasPressed(Button::Right)) {
    mode = static_cast<Mode>((static_cast<int>(mode) + 1) % static_cast<int>(Mode::COUNT));
    lastMinute = -1;
    requestUpdate();
    return;
  }

  if (mode == Mode::Stopwatch) {
    if (mappedInput.wasPressed(Button::Confirm)) {
      if (swRunning) {
        swAccumMs += millis() - swStartMs;
        swRunning = false;
      } else {
        swStartMs = millis();
        swRunning = true;
      }
      requestUpdate();
    } else if (mappedInput.wasPressed(Button::Up)) {
      swRunning = false;
      swAccumMs = 0;
      requestUpdate();
    }
  } else if (mode == Mode::Timer) {
    if (tmExpired) {
      if (mappedInput.wasPressed(Button::Confirm) || mappedInput.wasPressed(Button::Up)) {
        tmExpired = false;
        tmAccumMs = 0;  // back to the set screen
        requestUpdate();
      }
    } else if (tmRunning) {
      if (mappedInput.wasPressed(Button::Confirm)) {  // pause
        tmAccumMs += millis() - tmStartMs;
        tmRunning = false;
        requestUpdate();
      } else if (mappedInput.wasPressed(Button::Up)) {  // reset to set screen
        tmRunning = false;
        tmAccumMs = 0;
        requestUpdate();
      }
    } else {  // idle or paused
      const bool idle = (tmAccumMs == 0);
      if (mappedInput.wasPressed(Button::Confirm)) {  // start / resume
        tmStartMs = millis();
        tmRunning = true;
        requestUpdate();
      } else if (mappedInput.wasPressed(Button::Up)) {
        if (idle)
          tmSetMs = (tmSetMs + TIMER_STEP_MS > TIMER_MAX_MS) ? TIMER_MAX_MS : tmSetMs + TIMER_STEP_MS;
        else
          tmAccumMs = 0;  // paused -> reset to set screen
        requestUpdate();
      } else if (mappedInput.wasPressed(Button::Down)) {
        if (idle && tmSetMs > TIMER_STEP_MS) tmSetMs -= TIMER_STEP_MS;
        requestUpdate();
      }
    }
  }

  // Periodic refresh while something is live.
  const uint32_t now = millis();
  if (mode == Mode::Stopwatch && swRunning && now - lastTickMs >= 1000) {
    lastTickMs = now;
    requestUpdate();
  } else if (mode == Mode::Timer && tmRunning) {
    if (timerRemaining() == 0) {
      tmRunning = false;
      tmExpired = true;
      blinkOn = true;
      lastTickMs = now;
      requestUpdate();
    } else if (now - lastTickMs >= 1000) {
      lastTickMs = now;
      requestUpdate();
    }
  } else if (mode == Mode::Timer && tmExpired && now - lastTickMs >= 500) {
    lastTickMs = now;
    blinkOn = !blinkOn;
    requestUpdate();
  } else if (mode == Mode::Clock && now - lastTickMs >= 1000) {
    lastTickMs = now;
    uint8_t h, m;
    if (halClock.getTime(h, m) && m != lastMinute) {
      lastMinute = m;
      requestUpdate();
    }
  }
}

void ClockActivity::render(RenderLock&&) {
  switch (mode) {
    case Mode::Clock:
      renderClock();
      return;
    case Mode::Stopwatch:
      renderStopwatch();
      return;
    default:
      renderTimer();
      return;
  }
}

void ClockActivity::renderClock() {
  const auto H = renderer.getScreenHeight();

  char headerSub[24];
  snprintf(headerSub, sizeof(headerSub), "< %s >", modeName(static_cast<int>(mode)));
  beginToolRender(tr(STR_CLOCK), headerSub);

  const int midY = static_cast<int>(H) / 2;
  uint32_t epoch;
  if (halClock.getUnixTime(epoch)) {
    // Clamp against a corrupted persisted offset so the displayed time can't drift
    // outside [-12:00, +14:00] — mirrors HalClock::formatTime's guard.
    uint8_t offsetQ = SETTINGS.clockUtcOffsetQ;
    if (offsetQ > 104) offsetQ = 104;
    const int offsetSec = (static_cast<int>(offsetQ) - 48) * 15 * 60;
    const time_t local = static_cast<time_t>(epoch) + offsetSec;
    struct tm tmv;
    gmtime_r(&local, &tmv);
    char timeStr[12], dateStr[32];
    strftime(timeStr, sizeof(timeStr), SETTINGS.clockFormat == 1 ? "%I:%M %p" : "%H:%M", &tmv);
    strftime(dateStr, sizeof(dateStr), "%a  %Y-%m-%d", &tmv);
    renderer.drawCenteredText(BIG_FONT_ID, midY - renderer.getLineHeight(BIG_FONT_ID), timeStr, true,
                              EpdFontFamily::BOLD);
    renderer.drawCenteredText(SUB_FONT_ID, midY + 12, dateStr, true);
  } else {
    renderer.drawCenteredText(SUB_FONT_ID, midY - 10, tr(STR_CLOCK_NOT_SET), true, EpdFontFamily::BOLD);
    renderer.drawCenteredText(UI_10_FONT_ID, midY + 18, tr(STR_CLOCK_SET_HINT), true);
  }

  endToolRender(tr(STR_BTN_BACK), "", tr(STR_MODE), tr(STR_MODE));
}

void ClockActivity::renderStopwatch() {
  const auto H = renderer.getScreenHeight();

  char headerSub[24];
  snprintf(headerSub, sizeof(headerSub), "< %s >", modeName(static_cast<int>(mode)));
  beginToolRender(tr(STR_CLOCK), headerSub);

  const int midY = static_cast<int>(H) / 2;
  char buf[16];
  fmtDuration(stopwatchElapsed(), buf, sizeof(buf));
  renderer.drawCenteredText(BIG_FONT_ID, midY - renderer.getLineHeight(BIG_FONT_ID), buf, true, EpdFontFamily::BOLD);
  renderer.drawCenteredText(UI_10_FONT_ID, midY + 16, swRunning ? tr(STR_RUNNING_RESET) : tr(STR_STOPPED_RESET), true);

  endToolRender(tr(STR_BTN_BACK), swRunning ? tr(STR_STOP) : tr(STR_START), tr(STR_MODE), tr(STR_MODE));
}

void ClockActivity::renderTimer() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto W = renderer.getScreenWidth();
  const auto H = renderer.getScreenHeight();
  renderer.clearScreen();

  // Expired: blinking full-screen alert.
  if (tmExpired) {
    if (blinkOn) renderer.fillRect(0, 0, W, H, true);  // invert background
    const int midY = static_cast<int>(H) / 2;
    renderer.drawCenteredText(BIG_FONT_ID, midY - renderer.getLineHeight(BIG_FONT_ID), tr(STR_TIME_UP), !blinkOn,
                              EpdFontFamily::BOLD);
    renderer.drawCenteredText(UI_10_FONT_ID, midY + 16, tr(STR_CONFIRM_DISMISS), !blinkOn);
    // Fast (custom-LUT) refresh: a FULL_REFRESH takes ~1-2s and can't sustain the
    // 500ms blink cadence, leaving the device unresponsive and ghosting the panel.
    renderer.displayBuffer(HalDisplay::FAST_REFRESH);
    return;
  }

  char headerSub[24];
  snprintf(headerSub, sizeof(headerSub), "< %s >", modeName(static_cast<int>(mode)));
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, W, metrics.headerHeight}, tr(STR_CLOCK), headerSub);

  const int midY = static_cast<int>(H) / 2;
  const bool idle = (!tmRunning && tmAccumMs == 0);
  char buf[16];
  // Show ceil-to-second so it starts at the set value and ends cleanly at 0:00.
  const uint32_t rem = tmRunning ? timerRemaining() : (tmAccumMs == 0 ? tmSetMs : timerRemaining());
  fmtDuration((rem + 999) / 1000 * 1000, buf, sizeof(buf));
  renderer.drawCenteredText(BIG_FONT_ID, midY - renderer.getLineHeight(BIG_FONT_ID), buf, true, EpdFontFamily::BOLD);

  const char* hint = idle ? tr(STR_TIMER_SET_HINT) : tmRunning ? tr(STR_RUNNING_RESET) : tr(STR_PAUSED_RESET);
  renderer.drawCenteredText(UI_10_FONT_ID, midY + 16, hint, true);

  const char* confirmLabel = tmRunning ? tr(STR_PAUSE) : (idle ? tr(STR_START) : tr(STR_RESUME));
  endToolRender(tr(STR_BTN_BACK), confirmLabel, tr(STR_MODE), tr(STR_MODE));
}
