#include "CalendarActivity.h"

#include <Arduino.h>
#include <GfxRenderer.h>
#include <HalClock.h>
#include <HalStorage.h>
#include <I18n.h>
#include <Logging.h>

#include <cstdio>
#include <cstdlib>
#include <ctime>

#include "MappedInputManager.h"
#include "RadioInkSettings.h"
#include "activities/ActivityResult.h"
#include "activities/util/KeyboardEntryActivity.h"
#include "components/UITheme.h"
#include "fontIds.h"

namespace {
constexpr int GRID_FONT_ID = NOTOSANS_14_FONT_ID;
constexpr int DOW_FONT_ID = UI_10_FONT_ID;
constexpr int YEAR_MIN = 2000;
constexpr int YEAR_MAX = 2099;

constexpr const char* DOW_LABELS[7] = {"Su", "Mo", "Tu", "We", "Th", "Fr", "Sa"};
constexpr const char* MONTH_NAMES[12] = {"January", "February", "March",     "April",   "May",      "June",
                                         "July",    "August",   "September", "October", "November", "December"};
}  // namespace

// ---------------------------------------------------------------------------
// Date helpers
// ---------------------------------------------------------------------------
bool CalendarActivity::isLeap(int y) { return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0); }

int CalendarActivity::daysInMonth(int y, int m) {
  static constexpr int kDays[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  if (m < 1 || m > 12) return 30;
  if (m == 2 && isLeap(y)) return 29;
  return kDays[m - 1];
}

// Sakamoto's algorithm: weekday of (y, m, 1). Returns 0=Sunday .. 6=Saturday.
int CalendarActivity::firstWeekday(int y, int m) {
  static constexpr int t[12] = {0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4};
  int yy = y;
  if (m < 3) yy -= 1;
  return (yy + yy / 4 - yy / 100 + yy / 400 + t[m - 1] + 1) % 7;
}

// ---------------------------------------------------------------------------
// Events storage
// ---------------------------------------------------------------------------
void CalendarActivity::loadEvents() {
  events.clear();
  events.reserve(MAX_EVENTS);
  const String content = Storage.readFile(EVENTS_PATH);  // empty String if absent
  const char* p = content.c_str();
  const size_t len = content.length();
  size_t i = 0;
  // Each line: "YYYY-MM-DD|text"
  while (i < len && events.size() < MAX_EVENTS) {
    size_t eol = i;
    while (eol < len && p[eol] != '\n') eol++;
    const size_t lineLen = eol - i;
    if (lineLen >= 11 && p[i + 4] == '-' && p[i + 7] == '-' && p[i + 10] == '|') {
      const int y = atoi(std::string(p + i, 4).c_str());
      const int m = atoi(std::string(p + i + 5, 2).c_str());
      const int d = atoi(std::string(p + i + 8, 2).c_str());
      if (y >= YEAR_MIN && y <= YEAR_MAX && m >= 1 && m <= 12 && d >= 1 && d <= 31) {
        Event ev;
        ev.year = static_cast<uint16_t>(y);
        ev.month = static_cast<uint8_t>(m);
        ev.day = static_cast<uint8_t>(d);
        ev.text.assign(p + i + 11, lineLen - 11);
        if (!ev.text.empty()) events.push_back(std::move(ev));
      }
    }
    i = (eol < len) ? eol + 1 : eol;
  }
}

void CalendarActivity::saveEvents() {
  String out;
  char head[12];
  for (const auto& ev : events) {
    snprintf(head, sizeof(head), "%04u-%02u-%02u|", static_cast<unsigned>(ev.year), static_cast<unsigned>(ev.month),
             static_cast<unsigned>(ev.day));
    out += head;
    out += ev.text.c_str();
    out += '\n';
  }
  if (!Storage.writeFile(EVENTS_PATH, out)) {
    LOG_ERR("CALENDAR", "Failed to save %s", EVENTS_PATH);
  }
}

bool CalendarActivity::dayHasEvent(int y, int m, int d) const {
  for (const auto& ev : events) {
    if (ev.year == y && ev.month == m && ev.day == d) return true;
  }
  return false;
}

void CalendarActivity::collectSelDayEvents(std::vector<int>& out) const {
  out.clear();
  for (int i = 0; i < static_cast<int>(events.size()); i++) {
    if (events[i].year == selYear && events[i].month == selMonth && events[i].day == selDay) out.push_back(i);
  }
}

// ---------------------------------------------------------------------------
// Cursor movement
// ---------------------------------------------------------------------------
void CalendarActivity::moveCursorDays(int delta) {
  selDay += delta;
  while (selDay < 1) {
    selMonth--;
    if (selMonth < 1) {
      selMonth = 12;
      if (selYear > YEAR_MIN) selYear--;
    }
    selDay += daysInMonth(selYear, selMonth);
  }
  while (selDay > daysInMonth(selYear, selMonth)) {
    selDay -= daysInMonth(selYear, selMonth);
    selMonth++;
    if (selMonth > 12) {
      selMonth = 1;
      if (selYear < YEAR_MAX) selYear++;
    }
  }
}

// ---------------------------------------------------------------------------
// Lifecycle / navigation
// ---------------------------------------------------------------------------
void CalendarActivity::onEnter() {
  Activity::onEnter();
  loadEvents();

  uint32_t epoch;
  if (halClock.getUnixTime(epoch)) {
    uint8_t offsetQ = SETTINGS.clockUtcOffsetQ;
    if (offsetQ > 104) offsetQ = 104;  // mirror HalClock::formatTime's guard
    const int offsetSec = (static_cast<int>(offsetQ) - 48) * 15 * 60;
    const time_t local = static_cast<time_t>(epoch) + offsetSec;
    struct tm tmv;
    gmtime_r(&local, &tmv);
    todayYear = tmv.tm_year + 1900;
    todayMonth = tmv.tm_mon + 1;
    todayDay = tmv.tm_mday;
    if (todayYear >= YEAR_MIN && todayYear <= YEAR_MAX) {
      haveToday = true;
      selYear = todayYear;
      selMonth = todayMonth;
      selDay = todayDay;
    }
  }
  requestUpdate();
}

void CalendarActivity::openDay() {
  mode = Mode::Day;
  dayRow = 0;
  dayNotice.clear();
}

void CalendarActivity::promptAddEvent() {
  if (events.size() >= MAX_EVENTS) {
    dayNotice = tr(STR_EVENTS_FULL);
    requestUpdate();
    return;
  }
  startActivityForResult(
      std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, tr(STR_ADD_EVENT), "", MAX_EVENT_LEN,
                                              InputType::Text, true),
      [this](const ActivityResult& result) {
        if (!result.isCancelled) {
          const auto& kb = std::get<KeyboardResult>(result.data);
          if (!kb.text.empty() && events.size() < MAX_EVENTS) {
            Event ev;
            ev.year = static_cast<uint16_t>(selYear);
            ev.month = static_cast<uint8_t>(selMonth);
            ev.day = static_cast<uint8_t>(selDay);
            ev.text = kb.text;
            events.push_back(std::move(ev));
            saveEvents();
          }
        }
        requestUpdate();
      });
}

void CalendarActivity::promptEditEvent(int eventIndex) {
  if (eventIndex < 0 || eventIndex >= static_cast<int>(events.size())) return;
  startActivityForResult(
      std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, tr(STR_EDIT_EVENT), events[eventIndex].text,
                                              MAX_EVENT_LEN, InputType::Text, true),
      [this, eventIndex](const ActivityResult& result) {
        // The list can't change while the modal keyboard is up, so eventIndex stays valid.
        if (!result.isCancelled && eventIndex >= 0 && eventIndex < static_cast<int>(events.size())) {
          const auto& kb = std::get<KeyboardResult>(result.data);
          if (kb.text.empty()) {
            events.erase(events.begin() + eventIndex);  // clearing the text deletes the event
          } else {
            events[eventIndex].text = kb.text;
          }
          saveEvents();
        }
        requestUpdate();
      });
}

void CalendarActivity::loop() {
  using Button = MappedInputManager::Button;

  if (mode == Mode::Month) {
    if (handleToolBack()) return;

    if (mappedInput.wasPressed(Button::Left)) {
      moveCursorDays(-1);
      requestUpdate();
      return;
    }
    if (mappedInput.wasPressed(Button::Right)) {
      moveCursorDays(1);
      requestUpdate();
      return;
    }
    if (mappedInput.wasPressed(Button::Confirm)) {
      openDay();
      requestUpdate();
      return;
    }
    // Up/Down (side buttons) jump a week.
    buttonNavigator.onPrevious([this] {
      moveCursorDays(-7);
      requestUpdate();
    });
    buttonNavigator.onNext([this] {
      moveCursorDays(7);
      requestUpdate();
    });
    return;
  }

  // --- Day view ---
  if (mappedInput.wasPressed(Button::Back)) {
    mode = Mode::Month;
    dayNotice.clear();
    requestUpdate();
    return;
  }

  std::vector<int> dayEvents;
  collectSelDayEvents(dayEvents);
  const int rowCount = 1 + static_cast<int>(dayEvents.size());  // row 0 = Add event
  if (dayRow >= rowCount) dayRow = rowCount - 1;

  if (mappedInput.wasPressed(Button::Confirm)) {
    dayNotice.clear();
    if (dayRow == 0) {
      promptAddEvent();
    } else {
      const int idx = dayRow - 1;
      if (idx >= 0 && idx < static_cast<int>(dayEvents.size())) promptEditEvent(dayEvents[idx]);
    }
    return;
  }

  buttonNavigator.onPrevious([this, rowCount] {
    dayRow = ButtonNavigator::previousIndex(dayRow, rowCount);
    dayNotice.clear();
    requestUpdate();
  });
  buttonNavigator.onNext([this, rowCount] {
    dayRow = ButtonNavigator::nextIndex(dayRow, rowCount);
    dayNotice.clear();
    requestUpdate();
  });
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------
void CalendarActivity::render(RenderLock&&) {
  if (mode == Mode::Month) {
    renderMonth();
  } else {
    renderDay();
  }
}

void CalendarActivity::renderMonth() {
  char sub[32];
  snprintf(sub, sizeof(sub), "%s %d", MONTH_NAMES[selMonth - 1], selYear);
  // When the RTC has never been set, haveToday is false: the grid still works for
  // browsing and adding events, today just isn't boxed. Flagged in the subtitle.
  beginToolRender(tr(STR_CALENDAR), haveToday ? sub : (std::string(sub) + " *").c_str());

  const Rect content = toolContentRect();
  const int cols = 7;
  const int rows = 6;  // max weeks spanned by any month
  const int cellW = content.width / cols;
  const int sidePad = (content.width - cellW * cols) / 2;
  const int headerH = renderer.getLineHeight(DOW_FONT_ID) + 4;
  const int gridTop = content.y + headerH;
  const int gridH = content.height - headerH;
  const int cellH = gridH / rows;

  // Weekday header row.
  for (int c = 0; c < cols; c++) {
    const int cx = content.x + sidePad + c * cellW;
    const int tw = renderer.getTextWidth(DOW_FONT_ID, DOW_LABELS[c]);
    renderer.drawText(DOW_FONT_ID, cx + (cellW - tw) / 2, content.y, DOW_LABELS[c], true);
  }

  const int first = firstWeekday(selYear, selMonth);
  const int dim = daysInMonth(selYear, selMonth);
  const int numY = (cellH - renderer.getLineHeight(GRID_FONT_ID)) / 2;

  for (int d = 1; d <= dim; d++) {
    const int cellIdx = first + d - 1;
    const int c = cellIdx % cols;
    const int r = cellIdx / cols;
    const int cx = content.x + sidePad + c * cellW;
    const int cy = gridTop + r * cellH;

    const bool selected = (d == selDay);
    const bool today = haveToday && selYear == todayYear && selMonth == todayMonth && d == todayDay;

    if (selected) renderer.fillRect(cx + 1, cy + 1, cellW - 2, cellH - 2, true);
    if (today && !selected) renderer.drawRect(cx + 1, cy + 1, cellW - 2, cellH - 2, true);

    char num[4];
    snprintf(num, sizeof(num), "%d", d);
    const int tw = renderer.getTextWidth(GRID_FONT_ID, num);
    renderer.drawText(GRID_FONT_ID, cx + (cellW - tw) / 2, cy + numY, num, !selected);

    if (dayHasEvent(selYear, selMonth, d)) {
      const int dotY = cy + cellH - 5;
      renderer.fillRect(cx + cellW / 2 - 1, dotY, 3, 3, !selected);
    }
  }

  endToolRender(tr(STR_BTN_BACK), tr(STR_SELECT), tr(STR_DIR_LEFT), tr(STR_DIR_RIGHT));
}

void CalendarActivity::renderDay() {
  char sub[24];
  snprintf(sub, sizeof(sub), "%s %d, %d", MONTH_NAMES[selMonth - 1], selDay, selYear);
  beginToolRender(dayNotice.empty() ? tr(STR_CALENDAR) : dayNotice.c_str(), sub);

  std::vector<int> dayEvents;
  collectSelDayEvents(dayEvents);
  const int rowCount = 1 + static_cast<int>(dayEvents.size());

  const Rect content = toolContentRect();
  GUI.drawList(
      renderer, content, rowCount, dayRow,
      [this, &dayEvents](int i) -> std::string {
        if (i == 0) return std::string("+ ") + tr(STR_ADD_EVENT);
        const int idx = dayEvents[i - 1];
        return events[idx].text;
      },
      /*rowSubtitle=*/nullptr, /*rowIcon=*/nullptr);

  const char* confirm = (dayRow == 0) ? tr(STR_ADD_EVENT) : tr(STR_EDIT_EVENT);
  endToolRender(tr(STR_BTN_BACK), confirm, tr(STR_DIR_UP), tr(STR_DIR_DOWN));
}
