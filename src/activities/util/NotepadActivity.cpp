#include "NotepadActivity.h"

#include <GfxRenderer.h>
#include <HalStorage.h>
#include <I18n.h>
#include <Logging.h>

#include <algorithm>
#include <cstdio>
#include <string>

#include "MappedInputManager.h"
#include "activities/ActivityResult.h"
#include "activities/util/KeyboardEntryActivity.h"
#include "activities/util/NotepadSyncActivity.h"
#include "components/UITheme.h"
#include "fontIds.h"
#include "util/ButtonNavigator.h"

namespace {
constexpr const char* NOTES_PATH = "/notes.txt";
constexpr size_t MAX_TITLE_LEN = 60;
constexpr size_t MAX_LINE_LEN = 200;   // a single note line / checklist item
constexpr size_t MAX_BODY_LEN = 4000;  // whole-note edit cap
constexpr size_t MAX_PAGES = 64;
constexpr size_t MAX_ITEMS = 256;
constexpr int BODY_FONT_ID = UI_12_FONT_ID;

// Word-wrap `text` (newline-separated paragraphs) into display lines no wider
// than `maxW` pixels, measured in `fontId`. Long single words are hard-broken.
void wrapInto(const std::string& text, int maxW, int fontId, std::vector<std::string>& out, const GfxRenderer& r) {
  size_t start = 0;
  while (true) {
    const size_t nl = text.find('\n', start);
    const std::string para = text.substr(start, nl == std::string::npos ? std::string::npos : nl - start);
    if (para.empty()) {
      out.push_back("");
    } else {
      std::string line;
      size_t i = 0;
      while (i < para.size()) {
        const size_t sp = para.find(' ', i);
        const std::string word = para.substr(i, sp == std::string::npos ? std::string::npos : sp - i);
        const std::string cand = line.empty() ? word : line + " " + word;
        if (line.empty() && r.getTextWidth(fontId, word.c_str()) > maxW) {
          // Single word wider than the line: hard-break it character by character.
          std::string chunk;
          for (char c : word) {
            const std::string t = chunk + c;
            if (!chunk.empty() && r.getTextWidth(fontId, t.c_str()) > maxW) {
              out.push_back(chunk);
              chunk = std::string(1, c);
            } else {
              chunk = t;
            }
          }
          line = chunk;
        } else if (r.getTextWidth(fontId, cand.c_str()) <= maxW || line.empty()) {
          line = cand;
        } else {
          out.push_back(line);
          line = word;
        }
        i = (sp == std::string::npos) ? para.size() : sp + 1;
      }
      out.push_back(line);
    }
    if (nl == std::string::npos) break;
    start = nl + 1;
  }
}
}  // namespace

// --- Lifecycle ---

void NotepadActivity::onEnter() {
  Activity::onEnter();
  load();
  view = View::PageList;
  pageSel = 0;
  openPage = -1;
  menuOpen = false;
  dirty = false;
  requestUpdate();
}

void NotepadActivity::onExit() {
  if (dirty) save();  // backstop; mutations already persist as they happen
  Activity::onExit();
}

// --- Persistence ---

void NotepadActivity::load() {
  pages.clear();
  const String content = Storage.readFile(NOTES_PATH);
  const int len = content.length();
  if (len == 0) return;

  // Format is count-prefixed: a header line "@note <n> <title>" / "@list <n> <title>"
  // is followed by exactly <n> content lines that are consumed verbatim. This keeps
  // body text or checklist items that themselves start with "@note"/"@list"/"[x] "
  // from being misread as structural markers on reload.
  pages.reserve(8);
  int start = 0;
  int cur = -1;       // index into pages of the page currently being filled
  int remaining = 0;  // content lines still to consume for pages[cur]
  bool firstBody = true;
  while (start < len) {
    const int nl = content.indexOf('\n', start);
    const int end = (nl < 0) ? len : nl;
    String line = content.substring(start, end);
    start = (nl < 0) ? len : nl + 1;
    while (line.length() && line[line.length() - 1] == '\r') line.remove(line.length() - 1);

    if (remaining > 0 && cur >= 0) {
      // Verbatim content line for the current page, regardless of its prefix.
      Page& p = pages[cur];
      if (p.kind == Kind::Note) {
        if (!firstBody) p.body += '\n';
        p.body += line.c_str();
        firstBody = false;
      } else if (p.items.size() < MAX_ITEMS) {
        ListItem it;
        if (line.startsWith("[x] ") || line.startsWith("[X] ")) {
          it.done = true;
          it.text = line.substring(4).c_str();
        } else if (line.startsWith("[ ] ")) {
          it.text = line.substring(4).c_str();
        } else {
          it.text = line.c_str();  // tolerate a malformed line
        }
        p.items.push_back(std::move(it));
      }
      remaining--;
      continue;
    }

    const bool isNote = line.startsWith("@note ");
    const bool isList = line.startsWith("@list ");
    if (isNote || isList) {
      if (pages.size() >= MAX_PAGES) break;
      // Parse "<prefix> <count> <title>": digits after the 6-char prefix, then title.
      int countEnd = 6;
      while (countEnd < static_cast<int>(line.length()) && line[countEnd] >= '0' && line[countEnd] <= '9') countEnd++;
      const int count = line.substring(6, countEnd).toInt();
      const bool spaceAfterCount = countEnd < static_cast<int>(line.length()) && line[countEnd] == ' ';
      const int titleStart = spaceAfterCount ? countEnd + 1 : countEnd;
      Page p;
      p.kind = isNote ? Kind::Note : Kind::List;
      p.title = line.substring(titleStart).c_str();
      pages.push_back(std::move(p));
      cur = static_cast<int>(pages.size()) - 1;
      remaining = count;
      firstBody = true;
    }
    // else: stray line outside any page header → ignore.
  }
}

void NotepadActivity::save() {
  String out;
  out.reserve(pages.size() * 64 + 1);
  for (const Page& p : pages) {
    if (p.kind == Kind::Note) {
      // Line count = number of '\n' in body + 1 (empty body → 0 lines).
      int lineCount = 0;
      if (!p.body.empty()) {
        lineCount = 1;
        for (const char c : p.body) {
          if (c == '\n') lineCount++;
        }
      }
      out += "@note ";
      out += lineCount;
      out += ' ';
      out += p.title.c_str();
      out += '\n';
      if (lineCount > 0) {
        out += p.body.c_str();
        out += '\n';
      }
    } else {
      out += "@list ";
      out += static_cast<int>(p.items.size());
      out += ' ';
      out += p.title.c_str();
      out += '\n';
      for (const ListItem& it : p.items) {
        out += it.done ? "[x] " : "[ ] ";
        out += it.text.c_str();
        out += '\n';
      }
    }
  }
  if (!Storage.writeFile(NOTES_PATH, out)) {
    LOG_ERR("NOTEPAD", "Failed to save %s", NOTES_PATH);
  }
  dirty = false;
}

// --- Page-list level ---

void NotepadActivity::addPage() {
  if (pages.size() >= MAX_PAGES) return;
  startActivityForResult(std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, tr(STR_NEW_PAGE_TITLE), "",
                                                                 MAX_TITLE_LEN, InputType::Text, true),
                         [this](const ActivityResult& result) {
                           if (!result.isCancelled) {
                             const auto& kb = std::get<KeyboardResult>(result.data);
                             Page p;
                             p.kind = Kind::Note;  // new pages start as plain notes
                             p.title = kb.text.empty() ? "Untitled" : kb.text;
                             pages.push_back(std::move(p));
                             pageSel = static_cast<int>(pages.size()) - 1;
                             save();
                           }
                           requestUpdate();
                         });
}

void NotepadActivity::openSelectedPage() {
  if (pageSel < 0 || pageSel >= static_cast<int>(pages.size())) return;
  openPage = pageSel;
  if (pages[openPage].kind == Kind::Note) {
    view = View::NoteBody;
    bodyScroll = 0;
    rebuildBodyLines();
  } else {
    view = View::Checklist;
    itemSel = 0;
  }
  requestUpdate();
}

void NotepadActivity::renamePage(int idx) {
  if (idx < 0 || idx >= static_cast<int>(pages.size())) return;
  startActivityForResult(
      std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, tr(STR_RENAME_PAGE), pages[idx].title,
                                              MAX_TITLE_LEN, InputType::Text, true),
      [this, idx](const ActivityResult& result) {
        if (!result.isCancelled && idx < static_cast<int>(pages.size())) {
          const auto& kb = std::get<KeyboardResult>(result.data);
          pages[idx].title = kb.text.empty() ? "Untitled" : kb.text;
          save();
        }
        requestUpdate();
      });
}

void NotepadActivity::changeKind(int idx) {
  if (idx < 0 || idx >= static_cast<int>(pages.size())) return;
  Page& p = pages[idx];
  if (p.kind == Kind::Note) {
    // Note -> checklist: each non-empty body line becomes an item.
    p.items.clear();
    size_t start = 0;
    while (start <= p.body.size() && p.items.size() < MAX_ITEMS) {
      const size_t nl = p.body.find('\n', start);
      const std::string seg = p.body.substr(start, nl == std::string::npos ? std::string::npos : nl - start);
      if (!seg.empty()) p.items.push_back(ListItem{false, seg});
      if (nl == std::string::npos) break;
      start = nl + 1;
    }
    p.body.clear();
    p.kind = Kind::List;
  } else {
    // Checklist -> note: items become body lines (done state dropped).
    p.body.clear();
    for (const ListItem& it : p.items) {
      if (!p.body.empty()) p.body += '\n';
      p.body += it.text;
    }
    p.items.clear();
    p.kind = Kind::Note;
  }
  dirty = true;
  save();
  requestUpdate();
}

void NotepadActivity::deletePage(int idx) {
  if (idx < 0 || idx >= static_cast<int>(pages.size())) return;
  pages.erase(pages.begin() + idx);
  if (pageSel >= static_cast<int>(pages.size())) pageSel = std::max(0, static_cast<int>(pages.size()) - 1);
  dirty = true;
  save();
}

// --- Note body ---

void NotepadActivity::rebuildBodyLines() {
  bodyLines.clear();
  if (openPage < 0 || openPage >= static_cast<int>(pages.size())) return;
  const auto& metrics = UITheme::getInstance().getMetrics();
  const int maxW = renderer.getScreenWidth() - 2 * metrics.contentSidePadding;
  wrapInto(pages[openPage].body, maxW, BODY_FONT_ID, bodyLines, renderer);
}

void NotepadActivity::addToNote() {
  if (openPage < 0 || openPage >= static_cast<int>(pages.size())) return;
  startActivityForResult(std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, tr(STR_ADD_LINE), "",
                                                                 MAX_LINE_LEN, InputType::Text, true),
                         [this](const ActivityResult& result) {
                           if (!result.isCancelled && openPage >= 0 && openPage < static_cast<int>(pages.size())) {
                             const auto& kb = std::get<KeyboardResult>(result.data);
                             if (!kb.text.empty()) {
                               std::string& b = pages[openPage].body;
                               if (!b.empty()) b += '\n';
                               b += kb.text;
                               rebuildBodyLines();
                               save();
                             }
                           }
                           requestUpdate();
                         });
}

void NotepadActivity::editNoteBody() {
  if (openPage < 0 || openPage >= static_cast<int>(pages.size())) return;
  startActivityForResult(
      std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, tr(STR_EDIT_NOTE), pages[openPage].body,
                                              MAX_BODY_LEN, InputType::Text, true),
      [this](const ActivityResult& result) {
        if (!result.isCancelled && openPage >= 0 && openPage < static_cast<int>(pages.size())) {
          const auto& kb = std::get<KeyboardResult>(result.data);
          pages[openPage].body = kb.text;
          bodyScroll = 0;
          rebuildBodyLines();
          save();
        }
        requestUpdate();
      });
}

// --- Checklist items ---

void NotepadActivity::addItem() {
  if (openPage < 0 || openPage >= static_cast<int>(pages.size())) return;
  if (pages[openPage].items.size() >= MAX_ITEMS) return;
  startActivityForResult(std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, tr(STR_NEW_ITEM), "",
                                                                 MAX_LINE_LEN, InputType::Text, true),
                         [this](const ActivityResult& result) {
                           if (!result.isCancelled && openPage >= 0 && openPage < static_cast<int>(pages.size())) {
                             const auto& kb = std::get<KeyboardResult>(result.data);
                             if (!kb.text.empty()) {
                               pages[openPage].items.push_back(ListItem{false, kb.text});
                               itemSel = static_cast<int>(pages[openPage].items.size()) - 1;
                               save();
                             }
                           }
                           requestUpdate();
                         });
}

void NotepadActivity::editItem(int idx) {
  if (openPage < 0 || openPage >= static_cast<int>(pages.size())) return;
  auto& items = pages[openPage].items;
  if (idx < 0 || idx >= static_cast<int>(items.size())) return;
  startActivityForResult(std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, tr(STR_EDIT_ITEM),
                                                                 items[idx].text, MAX_LINE_LEN, InputType::Text, true),
                         [this, idx](const ActivityResult& result) {
                           if (!result.isCancelled && openPage >= 0 && openPage < static_cast<int>(pages.size()) &&
                               idx < static_cast<int>(pages[openPage].items.size())) {
                             const auto& kb = std::get<KeyboardResult>(result.data);
                             if (!kb.text.empty()) {
                               pages[openPage].items[idx].text = kb.text;
                               save();
                             }
                           }
                           requestUpdate();
                         });
}

void NotepadActivity::toggleItem(int idx) {
  if (openPage < 0 || openPage >= static_cast<int>(pages.size())) return;
  auto& items = pages[openPage].items;
  if (idx < 0 || idx >= static_cast<int>(items.size())) return;
  items[idx].done = !items[idx].done;
  // Toggling a checkbox is a high-frequency interaction; just mark dirty and let the
  // onExit() backstop (if (dirty) save()) persist it, instead of rewriting the whole
  // notes file to SD on every press (SD erase-cycle wear + UI stall).
  dirty = true;
  requestUpdate();
}

void NotepadActivity::deleteItem(int idx) {
  if (openPage < 0 || openPage >= static_cast<int>(pages.size())) return;
  auto& items = pages[openPage].items;
  if (idx < 0 || idx >= static_cast<int>(items.size())) return;
  items.erase(items.begin() + idx);
  if (itemSel >= static_cast<int>(items.size())) itemSel = std::max(0, static_cast<int>(items.size()) - 1);
  dirty = true;
  save();
}

// --- Shared action menu (page menu in PageList, item menu in Checklist) ---

void NotepadActivity::openMenu() {
  if (view == View::PageList && pages.empty()) return;
  if (view == View::Checklist && (openPage < 0 || pages[openPage].items.empty())) return;
  menuOpen = true;
  menuSel = 0;
  requestUpdate();
}

int NotepadActivity::menuCount() const { return view == View::PageList ? 5 : 4; }

void NotepadActivity::launchSync() {
  // Hands off to the Wi-Fi sync AP; it reboots on exit (heap/BLE), so the result
  // callback never fires — notes reload from /notes.txt after the restart.
  startActivityForResult(std::make_unique<NotepadSyncActivity>(renderer, mappedInput), [](const ActivityResult&) {});
}

void NotepadActivity::runMenuItem(int sel) {
  menuOpen = false;
  if (view == View::PageList) {
    switch (sel) {
      case 0:
        renamePage(pageSel);
        return;  // keyboard return refreshes
      case 1:
        changeKind(pageSel);
        break;
      case 2:
        deletePage(pageSel);
        break;
      case 3:
        launchSync();
        return;
      default:
        break;  // Cancel
    }
  } else {  // Checklist item menu
    switch (sel) {
      case 0:
        editItem(itemSel);
        return;
      case 1:
        toggleItem(itemSel);
        break;
      case 2:
        deleteItem(itemSel);
        break;
      default:
        break;
    }
  }
  requestUpdate();
}

// --- Input ---

void NotepadActivity::loop() {
  using Button = MappedInputManager::Button;

  if (menuOpen) {
    if (mappedInput.wasPressed(Button::Back)) {
      menuOpen = false;
      requestUpdate();
      return;
    }
    if (mappedInput.wasPressed(Button::Confirm)) {
      runMenuItem(menuSel);
      return;
    }
    const int mc = menuCount();
    buttonNavigator.onNext([this, mc] {
      menuSel = ButtonNavigator::nextIndex(menuSel, mc);
      requestUpdate();
    });
    buttonNavigator.onPrevious([this, mc] {
      menuSel = ButtonNavigator::previousIndex(menuSel, mc);
      requestUpdate();
    });
    return;
  }

  switch (view) {
    case View::PageList: {
      if (handleToolBack()) {
        return;
      }
      if (mappedInput.wasPressed(Button::Right)) {
        addPage();
        return;
      }
      if (pages.empty()) {
        if (mappedInput.wasPressed(Button::Left)) launchSync();  // sync reachable with no pages yet
        return;
      }
      const int n = static_cast<int>(pages.size());
      if (mappedInput.wasPressed(Button::Up)) {
        pageSel = ButtonNavigator::previousIndex(pageSel, n);
        requestUpdate();
      } else if (mappedInput.wasPressed(Button::Down)) {
        pageSel = ButtonNavigator::nextIndex(pageSel, n);
        requestUpdate();
      } else if (mappedInput.wasPressed(Button::Confirm)) {
        openSelectedPage();
      } else if (mappedInput.wasPressed(Button::Left)) {
        openMenu();
      }
      return;
    }

    case View::NoteBody: {
      if (mappedInput.wasPressed(Button::Back)) {
        view = View::PageList;
        requestUpdate();
        return;
      }
      if (mappedInput.wasPressed(Button::Right)) {
        addToNote();
        return;
      }
      if (mappedInput.wasPressed(Button::Confirm)) {
        editNoteBody();
        return;
      }
      const int n = static_cast<int>(bodyLines.size());
      if (n > 0 && mappedInput.wasPressed(Button::Up)) {
        if (bodyScroll > 0) bodyScroll--;
        requestUpdate();
      } else if (n > 0 && mappedInput.wasPressed(Button::Down)) {
        if (bodyScroll < n - 1) bodyScroll++;
        requestUpdate();
      }
      return;
    }

    case View::Checklist: {
      if (mappedInput.wasPressed(Button::Back)) {
        view = View::PageList;
        requestUpdate();
        return;
      }
      if (mappedInput.wasPressed(Button::Right)) {
        addItem();
        return;
      }
      if (openPage < 0 || openPage >= static_cast<int>(pages.size())) return;
      const int n = static_cast<int>(pages[openPage].items.size());
      if (n == 0) return;
      if (mappedInput.wasPressed(Button::Up)) {
        itemSel = ButtonNavigator::previousIndex(itemSel, n);
        requestUpdate();
      } else if (mappedInput.wasPressed(Button::Down)) {
        itemSel = ButtonNavigator::nextIndex(itemSel, n);
        requestUpdate();
      } else if (mappedInput.wasPressed(Button::Left)) {
        toggleItem(itemSel);
      } else if (mappedInput.wasPressed(Button::Confirm)) {
        openMenu();
      }
      return;
    }
  }
}

// --- Rendering ---

void NotepadActivity::render(RenderLock&&) {
  if (menuOpen) {
    renderMenu();
    return;
  }
  switch (view) {
    case View::PageList:
      renderPageList();
      return;
    case View::NoteBody:
      renderNoteBody();
      return;
    case View::Checklist:
      renderChecklist();
      return;
  }
}

void NotepadActivity::renderPageList() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  const auto pageHeight = renderer.getScreenHeight();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;

  char sub[24];
  snprintf(sub, sizeof(sub), tr(STR_NOTEPAD_PAGES_FMT), static_cast<int>(pages.size()), pages.size() == 1 ? "" : "s");
  beginToolRender(tr(STR_NOTEPAD), sub);

  const int listHeight = pageHeight - contentTop - metrics.buttonHintsHeight - metrics.verticalSpacing;
  if (pages.empty()) {
    const auto h = renderer.getLineHeight(UI_10_FONT_ID);
    const auto top = contentTop + (pageHeight - contentTop - metrics.buttonHintsHeight - h) / 2;
    UITheme::drawCenteredText(renderer, Rect{0, contentTop, pageWidth, pageHeight - contentTop}, UI_10_FONT_ID, top,
                              tr(STR_NO_PAGES));
  } else {
    GUI.drawList(
        renderer, Rect{0, contentTop, pageWidth, listHeight}, static_cast<int>(pages.size()), pageSel,
        [this](int i) { return pages[i].title.empty() ? std::string("Untitled") : pages[i].title; },
        [this](int i) -> std::string {
          const Page& p = pages[i];
          if (p.kind == Kind::Note) {
            if (p.body.empty()) return std::string(tr(STR_NOTE_SUB_EMPTY));
            const size_t nl = p.body.find('\n');
            return std::string(tr(STR_NOTE_SUB_PREFIX)) +
                   p.body.substr(0, nl == std::string::npos ? std::string::npos : nl);
          }
          int done = 0;
          for (const auto& it : p.items) done += it.done ? 1 : 0;
          char b[32];
          snprintf(b, sizeof(b), tr(STR_LIST_SUB_FMT), done, static_cast<int>(p.items.size()));
          return std::string(b);
        },
        [this](int i) { return pages[i].kind == Kind::Note ? UIIcon::Text : UIIcon::Library; });
  }

  const bool any = !pages.empty();
  endToolRender(tr(STR_BTN_BACK), any ? tr(STR_OPEN) : "", any ? tr(STR_MENU) : tr(STR_SYNC), tr(STR_ADD));
}

void NotepadActivity::renderNoteBody() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  const auto pageHeight = renderer.getScreenHeight();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;

  const char* title = (openPage >= 0 && openPage < static_cast<int>(pages.size()) && !pages[openPage].title.empty())
                          ? pages[openPage].title.c_str()
                          : tr(STR_NOTE_TITLE);
  beginToolRender(title);

  const int x = metrics.contentSidePadding;
  const int lineH = renderer.getLineHeight(BODY_FONT_ID);
  const int areaBottom = pageHeight - metrics.buttonHintsHeight - metrics.verticalSpacing;
  if (bodyLines.empty()) {
    UITheme::drawCenteredText(renderer, Rect{0, contentTop, pageWidth, pageHeight - contentTop}, UI_10_FONT_ID,
                              contentTop + lineH, tr(STR_NOTE_EMPTY_HINT));
  } else {
    int y = contentTop;
    for (int i = bodyScroll; i < static_cast<int>(bodyLines.size()) && y + lineH <= areaBottom; i++) {
      renderer.drawText(BODY_FONT_ID, x, y, bodyLines[i].c_str(), true);
      y += lineH;
    }
  }

  endToolRender(tr(STR_BTN_BACK), tr(STR_EDIT), "", tr(STR_ADD));
}

void NotepadActivity::renderChecklist() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  const auto pageHeight = renderer.getScreenHeight();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;

  const bool valid = openPage >= 0 && openPage < static_cast<int>(pages.size());
  const char* title =
      (valid && !pages[openPage].title.empty()) ? pages[openPage].title.c_str() : tr(STR_CHECKLIST_TITLE);
  beginToolRender(title);

  if (!valid) {
    endToolRender(tr(STR_BTN_BACK), "", "", "");
    return;
  }

  const auto& items = pages[openPage].items;
  const int listHeight = pageHeight - contentTop - metrics.buttonHintsHeight - metrics.verticalSpacing;
  if (items.empty()) {
    const auto h = renderer.getLineHeight(UI_10_FONT_ID);
    const auto top = contentTop + (pageHeight - contentTop - metrics.buttonHintsHeight - h) / 2;
    UITheme::drawCenteredText(renderer, Rect{0, contentTop, pageWidth, pageHeight - contentTop}, UI_10_FONT_ID, top,
                              tr(STR_NO_ITEMS));
  } else {
    GUI.drawList(
        renderer, Rect{0, contentTop, pageWidth, listHeight}, static_cast<int>(items.size()), itemSel,
        [&items](int i) { return std::string(items[i].done ? "[x] " : "[ ] ") + items[i].text; }, nullptr, nullptr,
        nullptr, false, [&items](int i) { return items[i].done; });
  }

  const bool any = !items.empty();
  endToolRender(tr(STR_BTN_BACK), any ? tr(STR_MENU) : "", any ? tr(STR_DONE) : "", tr(STR_ADD));
}

void NotepadActivity::renderMenu() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  const auto pageHeight = renderer.getScreenHeight();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;

  const bool pageMenu = (view == View::PageList);
  const char* header = pageMenu ? tr(STR_PAGE_ACTIONS) : tr(STR_ITEM_ACTIONS);
  beginToolRender(header);

  const bool isNote =
      pageMenu && pageSel >= 0 && pageSel < static_cast<int>(pages.size()) && pages[pageSel].kind == Kind::Note;
  const bool itemDone = !pageMenu && openPage >= 0 && itemSel >= 0 &&
                        itemSel < static_cast<int>(pages[openPage].items.size()) && pages[openPage].items[itemSel].done;

  const int listHeight = pageHeight - contentTop - metrics.buttonHintsHeight - metrics.verticalSpacing;
  GUI.drawList(
      renderer, Rect{0, contentTop, pageWidth, listHeight}, menuCount(), menuSel,
      [pageMenu, isNote, itemDone](int i) -> std::string {
        if (pageMenu) {
          switch (i) {
            case 0:
              return tr(STR_RENAME);
            case 1:
              return isNote ? tr(STR_MAKE_CHECKLIST) : tr(STR_MAKE_NOTE);
            case 2:
              return tr(STR_DELETE_PAGE);
            case 3:
              return tr(STR_SYNC_WIFI);
            default:
              return tr(STR_CANCEL);
          }
        }
        switch (i) {
          case 0:
            return tr(STR_EDIT);
          case 1:
            return itemDone ? tr(STR_MARK_NOT_DONE) : tr(STR_MARK_DONE);
          case 2:
            return tr(STR_DELETE);
          default:
            return tr(STR_CANCEL);
        }
      },
      nullptr, nullptr);

  endToolRender(tr(STR_BTN_BACK), tr(STR_SELECT), tr(STR_DIR_UP), tr(STR_DIR_DOWN));
}
