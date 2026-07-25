#include "HalClock.h"

#include <Logging.h>
#include <WiFi.h>
#include <esp_sntp.h>
#include <time.h>

#include <cassert>

HalClock halClock;  // Singleton instance

// DS3231 register layout (BCD encoded):
//   0x00: Seconds  (bits 6-4 = tens, bits 3-0 = ones)
//   0x01: Minutes  (bits 6-4 = tens, bits 3-0 = ones)
//   0x02: Hours    (bit 6 = 12/24 mode, bits 5-4 = tens, bits 3-0 = ones)

static uint8_t bcdToDec(uint8_t bcd) { return ((bcd >> 4) * 10) + (bcd & 0x0F); }
static uint8_t decToBcd(uint8_t dec) { return ((dec / 10) << 4) | (dec % 10); }

void HalClock::begin() {
  if (!gpio.deviceIsX3()) {
    _available = false;
    return;
  }

  // I2C is already initialised by HalPowerManager::begin() for X3.
  // Probe the DS3231 by reading the seconds register.
  Wire.beginTransmission(I2C_ADDR_DS3231);
  Wire.write(DS3231_SEC_REG);
  if (Wire.endTransmission(false) != 0) {
    LOG_INF("CLK", "DS3231 RTC not found");
    _available = false;
    return;
  }
  Wire.requestFrom(I2C_ADDR_DS3231, (uint8_t)1);
  if (Wire.available() < 1) {
    _available = false;
    return;
  }
  Wire.read();  // discard — just testing connectivity

  _available = true;
  LOG_INF("CLK", "DS3231 RTC found");

  // Make sure the oscillator keeps ticking on the backup battery (clear EOSC)
  // and learn whether it had stopped (OSF) -- the usual cause of "lost time
  // after sleep / power-off" on a DS3231.
  ensureOscillatorKeepsTime();

  // Prime the cache with an initial read
  uint8_t h, m;
  getTime(h, m);
}

bool HalClock::readRegister(uint8_t reg, uint8_t& value) const {
  Wire.beginTransmission(I2C_ADDR_DS3231);
  Wire.write(reg);
  if (Wire.endTransmission(false) != 0) return false;
  Wire.requestFrom(I2C_ADDR_DS3231, (uint8_t)1);
  if (Wire.available() < 1) return false;
  value = Wire.read();
  return true;
}

bool HalClock::writeRegister(uint8_t reg, uint8_t value) const {
  Wire.beginTransmission(I2C_ADDR_DS3231);
  Wire.write(reg);
  Wire.write(value);
  return Wire.endTransmission() == 0;
}

void HalClock::ensureOscillatorKeepsTime() {
  // EOSC (control reg bit 7) is active-low: when set, the oscillator is disabled
  // while running from VBAT, so the clock freezes on every power loss / deep
  // sleep. Clear it so the DS3231 holds time like it should.
  uint8_t control;
  if (readRegister(DS3231_CONTROL_REG, control)) {
    if (control & DS3231_EOSC_BIT) {
      control &= ~DS3231_EOSC_BIT;
      if (writeRegister(DS3231_CONTROL_REG, control))
        LOG_INF("CLK", "DS3231 EOSC was set; enabled oscillator on backup battery");
      else
        LOG_ERR("CLK", "DS3231 failed to clear EOSC");
    }
  }

  // OSF (status reg bit 7) latches whenever the oscillator has stopped (dead or
  // missing coin cell, first power-up). If set, the held time is invalid -- flag
  // it so the UI can prompt a re-sync. OSF is cleared when a fresh time is set.
  uint8_t status;
  if (readRegister(DS3231_STATUS_REG, status)) {
    _timeValid = !(status & DS3231_OSF_BIT);
    if (!_timeValid)
      LOG_ERR("CLK", "DS3231 OSF set: oscillator had stopped (check backup battery); time invalid until re-synced");
  } else {
    _timeValid = true;  // can't read status; assume valid rather than nag
  }
}

bool HalClock::getTime(uint8_t& hour, uint8_t& minute) const {
  if (!_available) return false;

  const unsigned long now = millis();
  if (_lastPollMs != 0 && (now - _lastPollMs) < CLOCK_POLL_MS) {
    hour = _cachedHour;
    minute = _cachedMinute;
    return true;
  }

  // Read 3 bytes starting at register 0x00: seconds, minutes, hours
  Wire.beginTransmission(I2C_ADDR_DS3231);
  Wire.write(DS3231_SEC_REG);
  if (Wire.endTransmission(false) != 0) {
    if (!_hasCachedTime) return false;
    _lastPollMs = now;
    hour = _cachedHour;
    minute = _cachedMinute;
    return true;
  }
  Wire.requestFrom(I2C_ADDR_DS3231, (uint8_t)3);
  if (Wire.available() < 3) {
    if (!_hasCachedTime) return false;
    _lastPollMs = now;
    hour = _cachedHour;
    minute = _cachedMinute;
    return true;
  }

  Wire.read();  // seconds — not needed
  const uint8_t rawMin = Wire.read();
  const uint8_t rawHour = Wire.read();

  _cachedMinute = bcdToDec(rawMin & 0x7F);
  // Handle 12/24h mode: bit 6 high = 12h mode
  if (rawHour & 0x40) {
    // 12h mode: bit 5 = PM, bits 4-0 = hours (1-12)
    uint8_t h12 = bcdToDec(rawHour & 0x1F);
    bool pm = rawHour & 0x20;
    if (h12 == 12) h12 = 0;
    _cachedHour = pm ? (h12 + 12) : h12;
  } else {
    // 24h mode: bits 5-0 = hours (0-23)
    _cachedHour = bcdToDec(rawHour & 0x3F);
  }
  _lastPollMs = now;
  _hasCachedTime = true;

  hour = _cachedHour;
  minute = _cachedMinute;
  return true;
}

bool HalClock::formatTime(char* buf, size_t bufSize, uint8_t utcOffsetQuarterHoursBiased, bool use12Hour) const {
  if (bufSize < (use12Hour ? 9u : 6u)) return false;
  // If the oscillator had stopped (OSF), the held time is meaningless -- report
  // failure so the UI shows nothing instead of a wrong time until a re-sync.
  if (!_timeValid) return false;
  uint8_t h, m;
  if (!getTime(h, m)) return false;

  // Apply UTC offset: convert biased value to signed quarter-hours.
  // Clamp against corrupted persisted values so display time can't drift outside [-12:00, +14:00].
  if (utcOffsetQuarterHoursBiased > 104) utcOffsetQuarterHoursBiased = 104;
  int offsetQuarterHours = static_cast<int>(utcOffsetQuarterHoursBiased) - 48;
  int totalMinutes = static_cast<int>(h) * 60 + static_cast<int>(m) + offsetQuarterHours * 15;

  // Wrap around 24 hours
  totalMinutes = ((totalMinutes % 1440) + 1440) % 1440;

  const int hour24 = totalMinutes / 60;
  const int min = totalMinutes % 60;
  if (use12Hour) {
    const bool pm = hour24 >= 12;
    int hour12 = hour24 % 12;
    if (hour12 == 0) hour12 = 12;
    snprintf(buf, bufSize, "%d:%02d %s", hour12, min, pm ? "PM" : "AM");
  } else {
    snprintf(buf, bufSize, "%02d:%02d", hour24, min);
  }
  return true;
}

bool HalClock::getUnixTime(uint32_t& epoch) const {
  if (!_available || !_timeValid) return false;

  // Read regs 0x00-0x06: sec, min, hour, dow, date, month(+century), year.
  Wire.beginTransmission(I2C_ADDR_DS3231);
  Wire.write(DS3231_SEC_REG);
  if (Wire.endTransmission(false) != 0) return false;
  Wire.requestFrom(I2C_ADDR_DS3231, (uint8_t)7);
  if (Wire.available() < 7) return false;

  const uint8_t sec = bcdToDec(Wire.read() & 0x7F);
  const uint8_t minute = bcdToDec(Wire.read() & 0x7F);
  const uint8_t rawHour = Wire.read();
  uint8_t hour;
  if (rawHour & 0x40) {  // 12h mode
    uint8_t h12 = bcdToDec(rawHour & 0x1F);
    const bool pm = rawHour & 0x20;
    if (h12 == 12) h12 = 0;
    hour = pm ? h12 + 12 : h12;
  } else {
    hour = bcdToDec(rawHour & 0x3F);
  }
  Wire.read();  // day-of-week, unused
  const uint8_t day = bcdToDec(Wire.read() & 0x3F);
  const uint8_t monthRaw = Wire.read();
  const uint8_t month = bcdToDec(monthRaw & 0x1F);
  const uint16_t year = 2000 + bcdToDec(Wire.read()) + ((monthRaw & 0x80) ? 100 : 0);

  // OSF only tells us the oscillator never stopped; it does NOT prove the date
  // registers were ever set. Firmware before v1.3.0 wrote only H:M:S, leaving the
  // DS3231 date registers at their power-on default (~2000-01-01). Treat any date
  // that predates this firmware as "date not yet synced" so callers (TOTP, clock)
  // fall back instead of computing an epoch from bogus year-2000 registers.
  if (year < 2024 || month < 1 || month > 12 || day < 1 || day > 31) return false;

  // Days-from-civil (Howard Hinnant's algorithm) → UTC epoch. TZ-independent, so
  // it never depends on the ESP system clock or any configured offset.
  const int y = year - (month <= 2 ? 1 : 0);
  const int era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);
  const unsigned doy = (153u * (month > 2 ? month - 3u : month + 9u) + 2) / 5 + day - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  const long days = static_cast<long>(era) * 146097 + static_cast<long>(doe) - 719468;

  epoch = static_cast<uint32_t>(days * 86400L + hour * 3600L + minute * 60L + sec);
  return true;
}

bool HalClock::writeTimeToRTC(uint16_t year, uint8_t month, uint8_t day, uint8_t hour, uint8_t minute, uint8_t second) {
  assert(hour < 24);
  assert(minute < 60);
  assert(second < 60);
  const uint8_t centuryBit = (year >= 2100) ? 0x80 : 0x00;  // DS3231 century bit lives in the month reg
  Wire.beginTransmission(I2C_ADDR_DS3231);
  Wire.write(DS3231_SEC_REG);                              // Start at register 0x00
  Wire.write(decToBcd(second));                            // 0x00: Seconds
  Wire.write(decToBcd(minute));                            // 0x01: Minutes
  Wire.write(decToBcd(hour));                              // 0x02: Hours (24h mode, bit 6 = 0)
  Wire.write(decToBcd(1));                                 // 0x03: Day-of-week (unused, 1)
  Wire.write(decToBcd(day));                               // 0x04: Date (1-31)
  Wire.write(decToBcd(month) | centuryBit);                // 0x05: Month (+ century bit)
  Wire.write(decToBcd(static_cast<uint8_t>(year % 100)));  // 0x06: Year (00-99)
  if (Wire.endTransmission() != 0) {
    LOG_ERR("CLK", "Failed to write time to DS3231");
    return false;
  }

  // A fresh, valid time was set: clear the oscillator-stopped flag so OSF no
  // longer reports the time as invalid.
  uint8_t status;
  if (readRegister(DS3231_STATUS_REG, status) && (status & DS3231_OSF_BIT))
    writeRegister(DS3231_STATUS_REG, status & ~DS3231_OSF_BIT);
  _timeValid = true;

  // Invalidate cache so next read fetches fresh data
  _lastPollMs = 0;
  _cachedHour = hour;
  _cachedMinute = minute;
  _hasCachedTime = true;
  return true;
}

bool HalClock::syncFromNTP() {
  if (!_available) return false;

  if (WiFi.status() != WL_CONNECTED) {
    LOG_ERR("CLK", "WiFi not connected, cannot sync NTP");
    return false;
  }

  LOG_INF("CLK", "Starting NTP sync...");
  configTzTime("UTC0", "pool.ntp.org", "time.nist.gov");

  // Wait for SNTP sync to complete (up to 5 seconds)
  constexpr int maxAttempts = 50;
  for (int i = 0; i < maxAttempts; i++) {
    if (sntp_get_sync_status() == SNTP_SYNC_STATUS_COMPLETED) {
      time_t now = time(nullptr);
      struct tm timeinfo;
      gmtime_r(&now, &timeinfo);

      if (writeTimeToRTC(static_cast<uint16_t>(timeinfo.tm_year + 1900), static_cast<uint8_t>(timeinfo.tm_mon + 1),
                         static_cast<uint8_t>(timeinfo.tm_mday), timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec)) {
        LOG_INF("CLK", "RTC set to %04d-%02d-%02d %02d:%02d:%02d UTC", timeinfo.tm_year + 1900, timeinfo.tm_mon + 1,
                timeinfo.tm_mday, timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
        return true;
      }
      return false;
    }
    delay(100);
  }

  LOG_ERR("CLK", "NTP sync timed out");
  return false;
}
