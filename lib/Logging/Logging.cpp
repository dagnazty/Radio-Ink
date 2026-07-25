#include "Logging.h"

#include <Arduino.h>

#include <cstring>
#include <string>

#define MAX_ENTRY_LEN 256
#define MAX_LOG_LINES 16

// --- SD-log staging ----------------------------------------------------------
// A small fixed ring of formatted lines that logPrintf() stages and the main
// loop drains to SD (see Logging.h). Kept tiny: errors are infrequent and the
// drain runs often, so this only has to bridge one loop iteration's worth.
#define SD_STAGE_LINES 24
static char sdStage[SD_STAGE_LINES][MAX_ENTRY_LEN];
static uint16_t sdStageHead = 0;   // next slot to write
static uint16_t sdStageCount = 0;  // staged-but-undrained
static uint8_t sdLogLevel = 0;     // 0=off, 1=ERR, 2=+INF, 3=+DBG
static portMUX_TYPE sdStageMux = portMUX_INITIALIZER_UNLOCKED;

void setSdLogLevel(uint8_t level) { sdLogLevel = level; }

// Map the level tag to a severity: ERR=1, INF=2, DBG=3 (unknown treated as ERR).
static uint8_t levelSeverity(const char* level) {
  if (level[0] == 'I') return 2;
  if (level[0] == 'D') return 3;
  return 1;
}

static void stageForSd(const char* line, uint8_t severity) {
  if (sdLogLevel == 0 || severity > sdLogLevel) return;
  portENTER_CRITICAL(&sdStageMux);
  strncpy(sdStage[sdStageHead], line, MAX_ENTRY_LEN - 1);
  sdStage[sdStageHead][MAX_ENTRY_LEN - 1] = '\0';
  sdStageHead = (sdStageHead + 1) % SD_STAGE_LINES;
  if (sdStageCount < SD_STAGE_LINES)
    sdStageCount++;  // full ring: oldest staged line is overwritten (dropped)
  portEXIT_CRITICAL(&sdStageMux);
}

void drainSdLogs(void (*sink)(const char* line)) {
  if (sink == nullptr) return;
  while (true) {
    char local[MAX_ENTRY_LEN];
    portENTER_CRITICAL(&sdStageMux);
    if (sdStageCount == 0) {
      portEXIT_CRITICAL(&sdStageMux);
      return;
    }
    const uint16_t tail = (sdStageHead + SD_STAGE_LINES - sdStageCount) % SD_STAGE_LINES;
    memcpy(local, sdStage[tail], MAX_ENTRY_LEN);
    sdStageCount--;
    portEXIT_CRITICAL(&sdStageMux);
    sink(local);  // SD I/O happens outside the critical section
  }
}

// Simple ring buffer log, useful for error reporting when we encounter a crash
RTC_NOINIT_ATTR char logMessages[MAX_LOG_LINES][MAX_ENTRY_LEN];
RTC_NOINIT_ATTR size_t logHead = 0;
// Magic word written alongside logHead to detect uninitialized RTC memory.
// RTC_NOINIT_ATTR is not zeroed on cold boot, so logHead may appear in-range
// (0..MAX_LOG_LINES-1) by chance even though logMessages is garbage. The magic
// value is only set by clearLastLogs(), so its absence means the buffer was
// never properly initialized.
RTC_NOINIT_ATTR uint32_t rtcLogMagic;
static constexpr uint32_t LOG_RTC_MAGIC = 0xDEADBEEF;

void addToLogRingBuffer(const char* message) {
  // Add the message to the ring buffer, overwriting old messages if necessary.
  // If the magic is wrong or logHead is out of range (RTC_NOINIT_ATTR garbage
  // on cold boot), clear the entire buffer so subsequent reads are safe.
  if (rtcLogMagic != LOG_RTC_MAGIC || logHead >= MAX_LOG_LINES) {
    memset(logMessages, 0, sizeof(logMessages));
    logHead = 0;
    rtcLogMagic = LOG_RTC_MAGIC;
  }
  strncpy(logMessages[logHead], message, MAX_ENTRY_LEN - 1);
  logMessages[logHead][MAX_ENTRY_LEN - 1] = '\0';
  logHead = (logHead + 1) % MAX_LOG_LINES;
}

// Since logging can take a large amount of flash, we want to make the format string as short as possible.
// This logPrintf prepend the timestamp, level and origin to the user-provided message, so that the user only needs to
// provide the format string for the message itself.
void logPrintf(const char* level, const char* origin, const char* format, ...) {
  va_list args;
  va_start(args, format);
  char buf[MAX_ENTRY_LEN];
  char* c = buf;
  // add timestamp, level and origin
  {
    unsigned long ms = millis();
    int len = snprintf(c, sizeof(buf), "[%lu] [%s] [%s] ", ms, level, origin);
    // error while writing => return
    if (len < 0) {
      va_end(args);
      return;
    }
    // clamp c to be in buffer range
    c += std::min(len, MAX_ENTRY_LEN);
  }
  // add the user message
  {
    int len = vsnprintf(c, sizeof(buf) - (c - buf), format, args);
    if (len < 0) {
      va_end(args);
      return;
    }
  }
  va_end(args);
  if (logSerial) {
    logSerial.print(buf);
  }
  addToLogRingBuffer(buf);
  stageForSd(buf, levelSeverity(level));
}

std::string getLastLogs() {
  if (rtcLogMagic != LOG_RTC_MAGIC) {
    return {};
  }
  std::string output;
  for (size_t i = 0; i < MAX_LOG_LINES; i++) {
    size_t idx = (logHead + i) % MAX_LOG_LINES;
    if (logMessages[idx][0] != '\0') {
      const size_t len = strnlen(logMessages[idx], MAX_ENTRY_LEN);
      output.append(logMessages[idx], len);
    }
  }
  return output;
}

// Checks whether the RTC log state is consistent: rtcLogMagic must equal
// LOG_RTC_MAGIC and logHead must be in 0..MAX_LOG_LINES-1. Returns true if
// corruption is detected, in which case rtcLogMagic is still invalid and
// logMessages may contain garbage. Callers (e.g. HalSystem::begin on the
// panic-reboot path) must call clearLastLogs() after a true result to fully
// reinitialize the ring buffer and stamp the magic before getLastLogs() is used.
bool sanitizeLogHead() {
  if (rtcLogMagic != LOG_RTC_MAGIC || logHead >= MAX_LOG_LINES) {
    logHead = 0;
    return true;
  }
  return false;
}

void clearLastLogs() {
  for (size_t i = 0; i < MAX_LOG_LINES; i++) {
    logMessages[i][0] = '\0';
  }
  logHead = 0;
  rtcLogMagic = LOG_RTC_MAGIC;
}
