#pragma once

#include <vector>

class RadioInkSettings;
class RadioInkState;
class WifiCredentialStore;
class RecentBooksStore;
class OpdsServerStore;
struct BookmarkEntry;

namespace JsonSettingsIO {

// RadioInkSettings
bool saveSettings(const RadioInkSettings& s, const char* path);
bool loadSettings(RadioInkSettings& s, const char* json, bool* needsResave = nullptr);

// RadioInkState
bool saveState(const RadioInkState& s, const char* path);
bool loadState(RadioInkState& s, const char* json);

// WifiCredentialStore
bool saveWifi(const WifiCredentialStore& store, const char* path);
bool loadWifi(WifiCredentialStore& store, const char* json, bool* needsResave = nullptr);

// RecentBooksStore
bool saveRecentBooks(const RecentBooksStore& store, const char* path);
bool loadRecentBooks(RecentBooksStore& store, const char* json);

// OpdsServerStore
bool saveOpds(const OpdsServerStore& store, const char* path);
bool loadOpds(OpdsServerStore& store, const char* json, bool* needsResave = nullptr);

// Bookmarks
bool saveBookmarks(const std::vector<BookmarkEntry>& bookmarks, const char* path);
bool loadBookmarks(std::vector<BookmarkEntry>& bookmarks, const char* json);

}  // namespace JsonSettingsIO
