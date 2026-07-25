#pragma once

#include <Arduino.h>
#include <Wire.h>

#include "HalGPIO.h"

class HalClock;
extern HalClock halClock;  // Singleton

class HalClock {
  bool _available = false;
  bool _timeValid = false;  // false if the DS3231 reported a stopped oscillator (OSF)
  mutable uint8_t _cachedHour = 0;
  mutable uint8_t _cachedMinute = 0;
  mutable bool _hasCachedTime = false;
  mutable unsigned long _lastPollMs = 0;

  static constexpr unsigned long CLOCK_POLL_MS = 10000;  // 10 seconds

 public:
  // Call after gpio.begin() and powerManager.begin() (I2C already initialised for X3)
  void begin();

  // True if the DS3231 RTC is present on this device
  bool isAvailable() const { return _available; }

  // False if the RTC's oscillator had stopped (OSF) since it was last set, e.g.
  // after a dead/removed backup battery -- the held time is then meaningless and
  // the user should re-sync. Cleared once a fresh time is written.
  bool isTimeValid() const { return _timeValid; }

  // Get current hour (0-23) and minute (0-59).
  // Returns false if RTC is not available.
  bool getTime(uint8_t& hour, uint8_t& minute) const;

  // Read the full date+time from the DS3231 and return it as a UTC Unix epoch
  // (seconds since 1970-01-01). The RTC is kept in UTC by syncFromNTP. Returns
  // false if the RTC is unavailable or its time has never been validly set
  // (OSF) — callers should prompt for an NTP sync in that case. Used by TOTP.
  bool getUnixTime(uint32_t& epoch) const;

  // Format time into a caller-provided buffer.
  // 24h mode produces "HH:MM" (needs >=6 bytes); 12h mode produces "H:MM AM"/"HH:MM PM" (needs >=9 bytes).
  // utcOffsetQuarterHoursBiased: biased quarter-hour offset (48 = UTC+0, 0 = UTC-12, 104 = UTC+14).
  // use12Hour: when true, format as 12-hour clock with AM/PM suffix.
  // Returns false if RTC is not available.
  bool formatTime(char* buf, size_t bufSize, uint8_t utcOffsetQuarterHoursBiased = 48, bool use12Hour = false) const;

  // Sync the DS3231 RTC from an NTP server. Requires WiFi to be connected.
  // Blocks for up to ~5s while waiting for SNTP response.
  // Returns true if the RTC was successfully updated.
  //
  // Debouncing (skip if already synced once) is enforced by the caller, not here,
  // so the HAL stays free of any app-layer settings dependency.
  bool syncFromNTP();

 private:
  // Writes the full date+time (regs 0x00-0x06) in 24h UTC. Date is included so
  // the RTC holds a real calendar date (needed for Unix-epoch reads / TOTP), not
  // just H:M:S as earlier firmware did.
  bool writeTimeToRTC(uint16_t year, uint8_t month, uint8_t day, uint8_t hour, uint8_t minute, uint8_t second);

  // Single-register DS3231 access helpers.
  bool readRegister(uint8_t reg, uint8_t& value) const;
  bool writeRegister(uint8_t reg, uint8_t value) const;
  // Clear EOSC so the oscillator keeps running on the backup battery, and read
  // the OSF flag to detect a previously-stopped oscillator (sets _timeValid).
  void ensureOscillatorKeepsTime();
};
