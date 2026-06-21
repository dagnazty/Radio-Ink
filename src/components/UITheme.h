#pragma once

#include <EpdFontFamily.h>

#include <functional>
#include <memory>

#include "RadioInkSettings.h"
#include "components/themes/BaseTheme.h"

class UITheme {
  // Static instance
  static UITheme instance;

 public:
  UITheme();
  static UITheme& getInstance() { return instance; }

  const ThemeMetrics& getMetrics() const { return *currentMetrics; }
  const BaseTheme& getTheme() const { return *currentTheme; }
  Rect getScreenSafeArea(const GfxRenderer& renderer, bool hasFrontButtonHints = false,
                         bool hasSideButtonHints = false);
  static void drawCenteredText(const GfxRenderer& renderer, Rect screen, int fontId, int y, const char* text,
                               bool black = true, EpdFontFamily::Style style = EpdFontFamily::REGULAR);
  void reload();
  void setTheme(RadioInkSettings::UI_THEME type);
  static int getNumberOfItemsPerPage(const GfxRenderer& renderer, bool hasHeader, bool hasTabBar, bool hasButtonHints,
                                     bool hasSubtitle, int extraReservedHeight = 0);
  static std::string getCoverThumbPath(std::string coverBmpPath, int coverHeight);
  static UIIcon getFileIcon(const std::string& filename);
  static int getStatusBarHeight();
  static int getProgressBarHeight();

  // Brand-logo opt-out for the Radio Ink theme: a page calls this before its
  // drawButtonHints to skip the logo for that one render (data/log views).
  void suppressBrandLogoOnce() { brandLogoSuppressed_ = true; }
  bool consumeBrandLogoSuppressed() {
    const bool suppressed = brandLogoSuppressed_;
    brandLogoSuppressed_ = false;
    return suppressed;
  }

 private:
  const ThemeMetrics* currentMetrics;
  std::unique_ptr<BaseTheme> currentTheme;
  bool brandLogoSuppressed_ = false;
};

// Helper macro to access current theme
#define GUI UITheme::getInstance().getTheme()
