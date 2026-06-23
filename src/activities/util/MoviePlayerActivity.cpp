#include "MoviePlayerActivity.h"

#include <Logging.h>

#include <cstring>

#include "MappedInputManager.h"
#include "activities/ActivityManager.h"
#include "components/UITheme.h"
#include "fontIds.h"

namespace {
constexpr const char* MOVIES_DIR = "/.radioink/movies";
constexpr const char* AUTOLOOP_PATH = "/.radioink/movies/.autoloop";  // presence = autoloop on
constexpr size_t RIVID_HEADER_SIZE = 16;
constexpr uint16_t MAX_W = 800;
constexpr uint16_t MAX_H = 480;
}  // namespace

void MoviePlayerActivity::onEnter() {
  Activity::onEnter();
  Storage.ensureDirectoryExists(MOVIES_DIR);
  autoLoop = Storage.exists(AUTOLOOP_PATH);
  loadMovieList();
  state = State::LIST;
  requestUpdate();
}

void MoviePlayerActivity::onExit() {
  if (file.isOpen()) file.close();
  frameBuf.reset();
  colByte.reset();
  colMask.reset();
  rowOff.reset();
  Activity::onExit();
}

void MoviePlayerActivity::loadMovieList() {
  movies.clear();
  selected = 0;
  listScroll = 0;

  auto dir = Storage.open(MOVIES_DIR);
  if (!dir || !dir.isDirectory()) {
    status = "No movies folder";
    return;
  }
  dir.rewindDirectory();
  char nameBuf[128];
  movies.reserve(16);
  for (auto entry = dir.openNextFile(); entry; entry = dir.openNextFile()) {
    entry.getName(nameBuf, sizeof(nameBuf));
    if (nameBuf[0] == '.' || entry.isDirectory()) continue;
    const size_t len = strlen(nameBuf);
    if (len > 6 && strcmp(nameBuf + len - 6, ".rivid") == 0) movies.emplace_back(nameBuf);
  }
  status = movies.empty() ? "Put .rivid files in /.radioink/movies" : std::to_string(movies.size()) + " movie(s)";
}

bool MoviePlayerActivity::startPlayback(const std::string& name) {
  const std::string path = std::string(MOVIES_DIR) + "/" + name;
  if (!Storage.openFileForRead("MOVIE", path, file)) {
    status = "Cannot open file";
    state = State::ERROR;
    return false;
  }

  uint8_t hdr[RIVID_HEADER_SIZE];
  if (file.read(hdr, RIVID_HEADER_SIZE) != static_cast<int>(RIVID_HEADER_SIZE) || memcmp(hdr, "RIVD", 4) != 0) {
    LOG_ERR("MOVIE", "bad header: %s", path.c_str());
    status = "Not a .rivid file";
    state = State::ERROR;
    file.close();
    return false;
  }
  // hdr[4]=version hdr[5]=flags, then width/height/fps/reserved/frameCount (LE).
  memcpy(&vidW, hdr + 6, 2);
  memcpy(&vidH, hdr + 8, 2);
  fps = hdr[10];
  memcpy(&frameCount, hdr + 12, 4);
  if (vidW == 0 || vidH == 0 || vidW > MAX_W || vidH > MAX_H || frameCount == 0) {
    status = "Bad movie dimensions";
    state = State::ERROR;
    file.close();
    return false;
  }
  if (fps < 1) fps = 1;
  if (fps > 30) fps = 30;

  rowBytes = (vidW + 7u) / 8u;
  frameBytes = rowBytes * vidH;
  frameBuf = makeUniqueNoThrow<uint8_t[]>(frameBytes);
  if (!frameBuf) {
    LOG_ERR("MOVIE", "OOM frame buffer: %u bytes", static_cast<unsigned>(frameBytes));
    status = "Out of memory";
    state = State::ERROR;
    file.close();
    return false;
  }

  // Fit-to-screen rect preserving aspect ratio (nearest-neighbour upscale).
  const int screenW = renderer.getScreenWidth();
  const int screenH = renderer.getScreenHeight();
  if (static_cast<int>(vidW) * screenH > static_cast<int>(vidH) * screenW) {
    destW = screenW;
    destH = static_cast<int>(vidH) * screenW / static_cast<int>(vidW);
  } else {
    destH = screenH;
    destW = static_cast<int>(vidW) * screenH / static_cast<int>(vidH);
  }
  destX = (screenW - destW) / 2;
  destY = (screenH - destH) / 2;

  // Precompute the source coordinate for every output pixel once, so the blit
  // loop is pure table lookups (no divide/shift per pixel).
  colByte = makeUniqueNoThrow<uint16_t[]>(destW);
  colMask = makeUniqueNoThrow<uint8_t[]>(destW);
  rowOff = makeUniqueNoThrow<uint16_t[]>(destH);
  if (!colByte || !colMask || !rowOff) {
    LOG_ERR("MOVIE", "OOM scaling tables");
    status = "Out of memory";
    state = State::ERROR;
    file.close();
    frameBuf.reset();
    colByte.reset();
    colMask.reset();
    rowOff.reset();
    return false;
  }
  for (int ox = 0; ox < destW; ox++) {
    const int sx = ox * static_cast<int>(vidW) / destW;
    colByte[ox] = static_cast<uint16_t>(sx >> 3);
    colMask[ox] = static_cast<uint8_t>(0x80 >> (sx & 7));
  }
  for (int oy = 0; oy < destH; oy++) {
    const int sy = oy * static_cast<int>(vidH) / destH;
    rowOff[oy] = static_cast<uint16_t>(sy * static_cast<int>(rowBytes));
  }

  currentFrame = 0;
  lastFrameMs = millis();
  state = State::PLAYING;
  status = name;
  requestUpdate();
  return true;
}

void MoviePlayerActivity::stopPlayback() {
  if (file.isOpen()) file.close();
  frameBuf.reset();
  colByte.reset();
  colMask.reset();
  rowOff.reset();
  state = State::LIST;
  loadMovieList();
  requestUpdate();
}

void MoviePlayerActivity::loop() {
  switch (state) {
    case State::LIST:
      if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
        onGoHome(HomeMenuItem::MOVIES);
        return;
      }
      if (movies.empty()) return;
      // Use the aggregate Nav buttons (side Up/Down + front Left/Right, orientation
      // aware) so the front buttons work here like every other menu.
      if (mappedInput.wasPressed(MappedInputManager::Button::NavPrevious)) {
        selected = (selected == 0) ? static_cast<int>(movies.size()) - 1 : selected - 1;
        requestUpdate();
      } else if (mappedInput.wasPressed(MappedInputManager::Button::NavNext)) {
        selected = (selected + 1) % static_cast<int>(movies.size());
        requestUpdate();
      } else if (mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
        startPlayback(movies[selected]);
      }
      return;

    case State::PLAYING:
      if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
        stopPlayback();
        return;
      }
      if (mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
        state = State::PAUSED;
        requestUpdate();
        return;
      }
      // Between frames there's nothing to do; yield instead of busy-spinning at
      // full clock (skipLoopDelay keeps power-save off during playback).
      if (!advanceFrame()) delay(15);
      return;

    case State::PAUSED:
      if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
        stopPlayback();
      } else if (mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
        lastFrameMs = millis();
        state = State::PLAYING;
        requestUpdate();
      } else if (mappedInput.wasPressed(MappedInputManager::Button::NavPrevious)) {
        toggleAutoLoop();
      }
      return;

    case State::ENDED:
      if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
        stopPlayback();
      } else if (mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
        currentFrame = 0;
        lastFrameMs = millis();
        state = State::PLAYING;
        requestUpdate();
      } else if (mappedInput.wasPressed(MappedInputManager::Button::NavPrevious)) {
        toggleAutoLoop();
      }
      return;

    case State::ERROR:
      if (mappedInput.wasPressed(MappedInputManager::Button::Back) ||
          mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
        stopPlayback();
      }
      return;
  }
}

bool MoviePlayerActivity::advanceFrame() {
  const uint32_t now = millis();
  const uint32_t interval = 1000u / fps;
  if (now - lastFrameMs < interval) return false;  // not time yet
  lastFrameMs = now;
  currentFrame++;
  if (currentFrame >= frameCount) {
    if (autoLoop)
      currentFrame = 0;  // restart, keep playing
    else
      state = State::ENDED;
  }
  requestUpdate();
  return true;
}

void MoviePlayerActivity::toggleAutoLoop() {
  autoLoop = !autoLoop;
  if (autoLoop)
    Storage.writeFile(AUTOLOOP_PATH, "1");  // presence persists the choice across reboots
  else
    Storage.remove(AUTOLOOP_PATH);
  requestUpdate();
}

void MoviePlayerActivity::drawCurrentFrame() {
  if (!frameBuf || !file.isOpen()) return;
  const size_t offset = RIVID_HEADER_SIZE + static_cast<size_t>(currentFrame) * frameBytes;
  if (!file.seek(offset) || file.read(frameBuf.get(), frameBytes) != static_cast<int>(frameBytes)) {
    status = "Read error";
    state = State::ERROR;
    requestUpdate();
    return;
  }

  renderer.clearScreen();  // white background
  const uint8_t* buf = frameBuf.get();
  for (int oy = 0; oy < destH; oy++) {
    const uint8_t* srcRow = buf + rowOff[oy];
    const int y = destY + oy;
    for (int ox = 0; ox < destW; ox++) {
      if (srcRow[colByte[ox]] & colMask[ox]) renderer.drawPixel(destX + ox, y, true);  // ink
    }
  }
  renderer.displayBuffer(HalDisplay::FAST_REFRESH);
}

void MoviePlayerActivity::renderList() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  const auto pageHeight = renderer.getScreenHeight();
  renderer.clearScreen();

  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, "Movies", status.c_str());

  if (movies.empty()) {
    const int y = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing * 3;
    renderer.drawText(UI_12_FONT_ID, metrics.contentSidePadding, y, "No movies found.", true, EpdFontFamily::BOLD);
    renderer.drawText(SMALL_FONT_ID, metrics.contentSidePadding, y + renderer.getLineHeight(UI_12_FONT_ID) + 6,
                      "Build with scripts/gen_video.py, copy to");
    renderer.drawText(SMALL_FONT_ID, metrics.contentSidePadding, y + renderer.getLineHeight(UI_12_FONT_ID) + 6 +
                                                                     renderer.getLineHeight(SMALL_FONT_ID) + 2,
                      "/.radioink/movies/ on the SD card.");
  } else {
    const int menuY = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;
    const int menuHeight = pageHeight - menuY - metrics.buttonHintsHeight - metrics.verticalSpacing;
    GUI.drawButtonMenu(
        renderer, Rect{0, menuY, pageWidth, menuHeight}, static_cast<int>(movies.size()), selected,
        [this](int index) { return movies[index]; }, [](int) { return UIIcon::Image; });
  }

  const auto labels = mappedInput.mapLabels("Back", movies.empty() ? "" : "Play", "Up", "Down");
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}

void MoviePlayerActivity::renderMessage(const char* title, const char* line1, const char* line2,
                                       const char* confirmLabel, bool showLoop) {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  renderer.clearScreen();
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, title, status.c_str());
  int y = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing * 3;
  if (line1 && line1[0]) {
    renderer.drawText(UI_12_FONT_ID, metrics.contentSidePadding, y, line1, true, EpdFontFamily::BOLD);
    y += renderer.getLineHeight(UI_12_FONT_ID) + 8;
  }
  if (line2 && line2[0]) {
    renderer.drawText(SMALL_FONT_ID, metrics.contentSidePadding, y, line2);
    y += renderer.getLineHeight(SMALL_FONT_ID) + 8;
  }
  if (showLoop) {
    renderer.drawText(UI_12_FONT_ID, metrics.contentSidePadding, y,
                      autoLoop ? "Autoloop: [x] ON" : "Autoloop: [ ] OFF", true, EpdFontFamily::BOLD);
  }

  const auto labels = mappedInput.mapLabels("Back", confirmLabel, showLoop ? "Loop" : "", "");
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}

void MoviePlayerActivity::render(RenderLock&&) {
  switch (state) {
    case State::LIST:
      renderList();
      return;
    case State::PLAYING:
      drawCurrentFrame();
      return;
    case State::PAUSED:
      renderMessage("Paused", status.c_str(), "", "Resume", true);
      return;
    case State::ENDED:
      renderMessage("End", status.c_str(), "", "Replay", true);
      return;
    case State::ERROR:
      renderMessage("Movie error", status.c_str(), "Press a button to continue.");
      return;
  }
}
