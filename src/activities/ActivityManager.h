#pragma once

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>

#include <cassert>
#include <memory>
#include <string>
#include <vector>

#include "GfxRenderer.h"
#include "MappedInputManager.h"
#include "util/ScreenshotInfo.h"

class Activity;    // forward declaration
class RenderLock;  // forward declaration

// The utility apps (Notepad/Badge/Authenticator/Clock) live under the home "Tools"
// entry now, not directly on the home menu; NOTEPAD/BADGE/AUTHENTICATOR/CLOCK stay
// in the enum only for the goHome name-mapping fallback.
enum class HomeMenuItem {
  NONE,
  FILE_BROWSER,
  RECENTS,
  OPDS_BROWSER,
  FILE_TRANSFER,
  RADIO_AUDIT,
  MOVIES,
  TOOLS,
  NOTEPAD,
  BADGE,
  AUTHENTICATOR,
  CLOCK,
  SETTINGS_MENU,
  ABOUT
};

// Items inside the Tools submenu (used to preselect a row when returning to it).
enum class ToolItem {
  NONE,
  NOTEPAD,
  BADGE,
  AUTHENTICATOR,
  CLOCK,
  PASSWORD_GEN,
  HASH_CALC,
  ENCODE_DECODE,
  QR_GEN,
  CALENDAR,
  CALCULATOR,
  FLASHCARDS,
  READ_LATER,
  NEWS
};

// Which screen to restore when waking from sleep. Persisted in RadioInkState as a
// uint8_t, so append new values at the end and never renumber existing ones. Only
// "safe" screens are listed here; network/AP/reader activities resume via their own
// paths or fall back to home. Home == "no resume".
enum class ResumeTarget : uint8_t {
  Home = 0,
  Tools,
  Notepad,
  Badge,
  Authenticator,
  Clock,
  PasswordGen,
  HashCalc,
  EncodeDecode,
  QrGen,
  RadioAudit,
  FileBrowser,
  RecentBooks,
  Settings,
  About,
  Movies,
  Calendar,
  Calculator,
  Flashcards,
  ReadLater,
  News
};

/**
 * ActivityManager
 *
 * This mirrors the same concept of Activity in Android, where an activity represents a single screen of the UI. The
 * manager is responsible for launching activities, and ensuring that only one activity is active at a time.
 *
 * It also provides a stack mechanism to allow activities to launch sub-activities and get back the results when the
 * sub-activity is done. For example, the WebServer activity can launch a WifiSelect activity to let the user choose a
 * wifi network, and get back the selected network when the user is done.
 *
 * Main differences from Android's ActivityManager:
 * - No onPause/onResume, since we don't have a concept of background activities
 * - onActivityResult is implemented via a callback instead of a separate method, for simplicity
 */
class ActivityManager {
  friend class RenderLock;

 protected:
  GfxRenderer& renderer;
  MappedInputManager& mappedInput;
  std::vector<std::unique_ptr<Activity>> stackActivities;
  std::unique_ptr<Activity> currentActivity;

  void exitActivity(const RenderLock& lock);

  // Pending activity to be launched on next loop iteration
  std::unique_ptr<Activity> pendingActivity;
  enum class PendingAction { None, Push, Pop, Replace };
  PendingAction pendingAction = PendingAction::None;

  // Task to render and display the activity
  TaskHandle_t renderTaskHandle = nullptr;
  static void renderTaskTrampoline(void* param);
  [[noreturn]] virtual void renderTaskLoop();

  // Set by requestUpdateAndWait(); read and cleared by the render task after render completes.
  // Note: only one waiting task is supported at a time
  TaskHandle_t waitingTaskHandle = nullptr;

  // Mutex to protect rendering operations from race conditions
  // Must only be used via RenderLock
  SemaphoreHandle_t renderingMutex = nullptr;

  // Whether to trigger a render after the current loop()
  // This variable must only be set by the main loop, to avoid race conditions
  bool requestedUpdate = false;

 public:
  explicit ActivityManager(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : renderer(renderer), mappedInput(mappedInput), renderingMutex(xSemaphoreCreateMutex()) {
    assert(renderingMutex != nullptr && "Failed to create rendering mutex");
    stackActivities.reserve(10);
  }
  ~ActivityManager() { assert(false); /* should never be called */ };

  void begin();
  void loop();

  // Will replace currentActivity and drop all activities on stack
  void replaceActivity(std::unique_ptr<Activity>&& newActivity);

  // goTo... functions are convenient wrapper for replaceActivity()
  void goToFileTransfer();
  void goToSettings();
  void goToFileBrowser(std::string path = {}, bool allFiles = false);
  void goToRecentBooks();
  void goToBrowser();
  void goToRadioAudit();
  void goToMovies();
  void goToNotepad();
  void goToBadge();
  void goToAuthenticator();
  void goToClock();
  void goToCalendar();
  void goToCalculator();
  void goToFlashcards();
  void goToReadLater();
  void goToNews();
  void goToPasswordGen();
  void goToHashCalc();
  void goToEncodeDecode();
  void goToQrGen();
  void goToTools(ToolItem initial = ToolItem::NONE);
  void goToAbout();
  void goToReader(std::string path);

  // Map the current activity to a resume target for sleep persistence. Returns
  // ResumeTarget::Home when the current screen shouldn't be auto-restored on wake
  // (network/AP screens, the reader, or anything not in the whitelist).
  ResumeTarget currentResumeTarget() const;
  // Restore a resume target when waking from sleep. Returns false for Home/unknown
  // so the caller can fall back to goHome().
  bool resumeActivity(ResumeTarget target);

  void goToSleep(bool fromTimeout = false);
  void goToBoot();
  void goToFullScreenMessage(std::string message, EpdFontFamily::Style style = EpdFontFamily::REGULAR);
  void goToCrashReport();
  void goHome(HomeMenuItem initialMenuItem = HomeMenuItem::NONE);

  // This will move current activity to stack instead of deleting it
  void pushActivity(std::unique_ptr<Activity>&& activity);

  // Remove the currentActivity, returning the last one on stack
  // Note: if popActivity() on last activity on the stack, we will goHome()
  void popActivity();

  bool preventAutoSleep() const;
  bool isReaderActivity() const;
  bool skipLoopDelay() const;
  ScreenshotInfo getScreenshotInfo() const;

  // If immediate is true, the update will be triggered immediately.
  // Otherwise, it will be deferred until the end of the current loop iteration.
  void requestUpdate(bool immediate = false);

  // Trigger a render and block until it completes.
  // Must NOT be called from the render task or while holding a RenderLock.
  void requestUpdateAndWait();
};

extern ActivityManager activityManager;  // singleton, to be defined in main.cpp
