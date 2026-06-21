#pragma once

#include <Arduino.h>

namespace RadioInkAuditApp {
  void begin(bool announce = false);
  void pollSerial();
  void command(const String &line);
  void autoScan(uint8_t bleSeconds = 5);
  bool deepScanWifi(uint8_t index);
  bool deepScanBle(uint8_t index);
  String reportText();
  String reportCsv();
  String reportJson();
}
