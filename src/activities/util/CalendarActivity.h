#pragma once

#include <GfxRenderer.h>

#include <cstdint>
#include <string>
#include <vector>

#include "activities/util/ToolActivityBase.h"
#include "util/ButtonNavigator.h"

// Calendar tool: a month grid backed by the DS3231 RTC, plus per-day events
// persisted to /calendar.txt on the SD card.
//   Month view : grid with today boxed and event-days dotted. Left/Right move the
//                cursor one day (wrapping across months); Up/Down jump a week;
//                Confirm opens the selected day. Back exits to Tools.
//   Day view   : lists that day's events. Confirm on "Add event" (top row) opens
//                the keyboard; Confirm on an event edits it (clearing the text
//                deletes it). Back returns to the month grid.
//
// Events live only while the activity is open; the vector frees on exit. Writes to
// SD happen only on an explicit add/edit/delete (never per keystroke), matching the
// Notepad save-on-edit pattern.
class CalendarActivity final : public ToolActivityBase {
 public:
  CalendarActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : ToolActivityBase("Calendar", renderer, mappedInput, ToolItem::CALENDAR) {}

  void onEnter() override;
  void loop() override;
  void render(RenderLock&&) override;

 private:
  enum class Mode { Month, Day };

  struct Event {
    uint16_t year = 0;
    uint8_t month = 0;  // 1-12
    uint8_t day = 0;    // 1-31
    std::string text;
  };

  static constexpr size_t MAX_EVENTS = 128;
  static constexpr size_t MAX_EVENT_LEN = 60;
  static constexpr const char* EVENTS_PATH = "/calendar.txt";

  Mode mode = Mode::Month;

  // Cursor / displayed month. Year clamped to [2000, 2099] so cursor stepping can
  // never run away.
  int selYear = 2026;
  int selMonth = 1;  // 1-12
  int selDay = 1;    // 1-31

  // Today, from the RTC. haveToday is false when the clock has never been set.
  bool haveToday = false;
  int todayYear = 0, todayMonth = 0, todayDay = 0;

  // Day-view row selection: 0 = "Add event", 1..N = events for selDay (filtered).
  int dayRow = 0;
  std::string dayNotice;  // transient message (e.g. "Event list full"); cleared on nav

  std::vector<Event> events;
  ButtonNavigator buttonNavigator;

  // --- date helpers ---
  static bool isLeap(int y);
  static int daysInMonth(int y, int m);
  static int firstWeekday(int y, int m);  // 0=Sun..6=Sat for the 1st of the month

  // --- event helpers ---
  void loadEvents();
  void saveEvents();
  bool dayHasEvent(int y, int m, int d) const;
  // Global indices into `events` that fall on the selected day, in stored order.
  void collectSelDayEvents(std::vector<int>& out) const;

  void moveCursorDays(int delta);  // step selDay, rolling months/years, clamped to year bounds

  void openDay();
  void promptAddEvent();
  void promptEditEvent(int eventIndex);

  void renderMonth();
  void renderDay();
};
