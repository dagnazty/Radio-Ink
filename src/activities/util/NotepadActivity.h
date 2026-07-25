#pragma once

#include <GfxRenderer.h>

#include <string>
#include <vector>

#include "activities/util/ToolActivityBase.h"
#include "util/ButtonNavigator.h"

// A two-level on-device notepad.
//
//   Level 1 (page list): titled pages. Each page is either a free-text NOTE or a
//                        checklist (LIST). Open / add / rename / change-kind /
//                        delete from here.
//   Level 2 (open page): a NOTE opens to a scrollable text body you can append to
//                        or rewrite; a LIST opens to its checkable items.
//
// Persisted as one text file on the SD card. Each page starts with a count-prefixed
// header "@note <n> <title>" or "@list <n> <title>", followed by exactly <n> content
// lines consumed verbatim (note body lines, or "[ ]/[x] item" rows). The count makes
// body/item text that itself begins with "@note"/"[x] " round-trip safely.
//
// Controls follow standard firmware nav: side Up/Down scroll; front Confirm,
// Left, Right and Back are per-view actions (see the hint bar on each screen).
class NotepadActivity final : public ToolActivityBase {
 public:
  explicit NotepadActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : ToolActivityBase("Notepad", renderer, mappedInput, ToolItem::NOTEPAD) {}

  void onEnter() override;
  void onExit() override;
  void loop() override;
  void render(RenderLock&&) override;

 private:
  enum class Kind { Note, List };
  enum class View { PageList, NoteBody, Checklist };

  struct ListItem {
    bool done = false;
    std::string text;
  };
  struct Page {
    Kind kind = Kind::Note;
    std::string title;
    std::string body;             // Note pages: free text (newline-separated)
    std::vector<ListItem> items;  // List pages: checklist rows
  };

  std::vector<Page> pages;
  View view = View::PageList;
  int pageSel = 0;                     // selected row in the page list
  int openPage = -1;                   // index of the page open in NoteBody / Checklist
  int itemSel = 0;                     // selected row in an open checklist
  int bodyScroll = 0;                  // first visible wrapped line in an open note
  std::vector<std::string> bodyLines;  // cached word-wrapped lines for the open note

  bool menuOpen = false;  // action-menu overlay (page menu in PageList, item menu in Checklist)
  int menuSel = 0;
  bool dirty = false;
  ButtonNavigator buttonNavigator;  // per-instance: no latched state across entries

  void load();
  void save();

  // Page-list level
  void addPage();
  void openSelectedPage();
  void renamePage(int idx);
  void changeKind(int idx);
  void deletePage(int idx);

  // Note body
  void rebuildBodyLines();
  void addToNote();
  void editNoteBody();

  // Checklist items
  void addItem();
  void editItem(int idx);
  void toggleItem(int idx);
  void deleteItem(int idx);

  // Shared action menu
  void openMenu();
  void runMenuItem(int sel);
  int menuCount() const;  // page menu has a Sync row; item menu does not
  void launchSync();      // stand up the Wi-Fi sync AP (reboots on exit)

  void renderPageList();
  void renderNoteBody();
  void renderChecklist();
  void renderMenu();
};
