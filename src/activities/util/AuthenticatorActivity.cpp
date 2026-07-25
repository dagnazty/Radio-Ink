#include "AuthenticatorActivity.h"

#include <GfxRenderer.h>
#include <HalClock.h>
#include <HalStorage.h>
#include <I18n.h>
#include <Logging.h>
#include <mbedtls/md.h>

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "MappedInputManager.h"
#include "activities/ActivityResult.h"
#include "activities/util/KeyboardEntryActivity.h"
#include "components/UITheme.h"
#include "fontIds.h"
#include "util/ButtonNavigator.h"

namespace {
constexpr const char* TOTP_PATH = "/totp.txt";
constexpr size_t MAX_ENTRIES = 32;
constexpr size_t MAX_LABEL_LEN = 40;
constexpr size_t MAX_SECRET_LEN = 128;
constexpr int TOTP_PERIOD = 30;  // seconds per RFC 6238 default
constexpr int MENU_COUNT = 2;    // Delete, Cancel
}  // namespace

void AuthenticatorActivity::onEnter() {
  Activity::onEnter();
  load();
  selected = 0;
  menuOpen = false;
  dirty = false;
  refreshCodes(true);
  requestUpdate();
}

void AuthenticatorActivity::onExit() {
  if (dirty) save();
  Activity::onExit();
}

// --- Persistence ("label:BASE32" per line) ---

void AuthenticatorActivity::load() {
  entries.clear();
  const String content = Storage.readFile(TOTP_PATH);
  const int len = content.length();
  if (len == 0) return;

  entries.reserve(8);
  int start = 0;
  while (start < len && entries.size() < MAX_ENTRIES) {
    const int nl = content.indexOf('\n', start);
    const int end = (nl < 0) ? len : nl;
    String line = content.substring(start, end);
    start = (nl < 0) ? len : nl + 1;
    while (line.length() && line[line.length() - 1] == '\r') line.remove(line.length() - 1);
    if (line.length() == 0) continue;

    // Split on the LAST ':' — base32 secrets never contain a colon, so any colons
    // belong to the label (e.g. "AWS: prod:SECRET" → label "AWS: prod", secret "SECRET").
    const int colon = line.lastIndexOf(':');
    Entry e;
    if (colon < 0) {
      e.label = "Account";
      e.secret = line.c_str();
    } else {
      e.label = line.substring(0, colon).c_str();
      e.secret = line.substring(colon + 1).c_str();
    }
    e.code = "------";
    entries.push_back(std::move(e));
  }
}

void AuthenticatorActivity::save() {
  String out;
  out.reserve(entries.size() * 48 + 1);
  for (const Entry& e : entries) {
    out += e.label.c_str();
    out += ':';
    out += e.secret.c_str();
    out += '\n';
  }
  if (!Storage.writeFile(TOTP_PATH, out)) LOG_ERR("TOTP", "Failed to save %s", TOTP_PATH);
  dirty = false;
}

// --- TOTP math ---

int AuthenticatorActivity::base32Decode(const std::string& in, uint8_t* out, int outCap) {
  uint32_t buffer = 0;
  int bitsLeft = 0;
  int count = 0;
  for (char ch : in) {
    if (ch == '=' || ch == ' ' || ch == '-') continue;  // padding / formatting
    int val;
    if (ch >= 'A' && ch <= 'Z')
      val = ch - 'A';
    else if (ch >= 'a' && ch <= 'z')
      val = ch - 'a';
    else if (ch >= '2' && ch <= '7')
      val = ch - '2' + 26;
    else
      return -1;  // invalid base32 character
    buffer = (buffer << 5) | static_cast<uint32_t>(val);
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      bitsLeft -= 8;
      if (count >= outCap) return -1;
      out[count++] = static_cast<uint8_t>((buffer >> bitsLeft) & 0xFF);
    }
  }
  return count;
}

bool AuthenticatorActivity::computeTotp(const std::string& base32Secret, uint32_t epoch, char out[7]) {
  uint8_t key[MAX_SECRET_LEN];
  const int keyLen = base32Decode(base32Secret, key, sizeof(key));
  if (keyLen <= 0) return false;

  uint64_t counter = epoch / TOTP_PERIOD;
  uint8_t msg[8];
  for (int i = 7; i >= 0; i--) {
    msg[i] = static_cast<uint8_t>(counter & 0xFF);
    counter >>= 8;
  }

  uint8_t hmac[20];
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
  if (!info || mbedtls_md_hmac(info, key, keyLen, msg, sizeof(msg), hmac) != 0) return false;

  const int off = hmac[19] & 0x0F;  // dynamic truncation
  const uint32_t bin = (static_cast<uint32_t>(hmac[off] & 0x7F) << 24) | (static_cast<uint32_t>(hmac[off + 1]) << 16) |
                       (static_cast<uint32_t>(hmac[off + 2]) << 8) | static_cast<uint32_t>(hmac[off + 3]);
  snprintf(out, 7, "%06u", static_cast<unsigned>(bin % 1000000u));
  return true;
}

void AuthenticatorActivity::refreshCodes(bool force) {
  uint32_t epoch = 0;
  haveTime = halClock.getUnixTime(epoch);
  if (!haveTime) {
    for (auto& e : entries) e.code = "------";
    return;
  }
  secondsLeft = TOTP_PERIOD - static_cast<int>(epoch % TOTP_PERIOD);
  const uint32_t period = epoch / TOTP_PERIOD;
  if (!force && period == lastPeriod) return;  // same 30s window, codes unchanged
  lastPeriod = period;
  for (auto& e : entries) {
    char buf[7];
    e.code = computeTotp(e.secret, epoch, buf) ? buf : "ERR";
  }
}

// --- Mutations ---

void AuthenticatorActivity::addEntry() {
  if (entries.size() >= MAX_ENTRIES) return;
  startActivityForResult(std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, tr(STR_ACCOUNT_LABEL), "",
                                                                 MAX_LABEL_LEN, InputType::Text, true),
                         [this](const ActivityResult& result) {
                           if (result.isCancelled) {
                             requestUpdate();
                             return;
                           }
                           pendingLabel = std::get<KeyboardResult>(result.data).text;
                           if (pendingLabel.empty()) pendingLabel = "Account";
                           // Second step: the base32 secret.
                           startActivityForResult(
                               std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, tr(STR_SECRET_BASE32), "",
                                                                       MAX_SECRET_LEN, InputType::Text, true),
                               [this](const ActivityResult& secretResult) {
                                 if (!secretResult.isCancelled) {
                                   const std::string secret = std::get<KeyboardResult>(secretResult.data).text;
                                   uint8_t probe[MAX_SECRET_LEN];
                                   if (!secret.empty() && base32Decode(secret, probe, sizeof(probe)) > 0) {
                                     entries.push_back(Entry{pendingLabel, secret, "------"});
                                     selected = static_cast<int>(entries.size()) - 1;
                                     save();
                                     refreshCodes(true);
                                   } else {
                                     LOG_ERR("TOTP", "Rejected invalid base32 secret");
                                   }
                                 }
                                 requestUpdate();
                               });
                         });
}

void AuthenticatorActivity::deleteEntry(int idx) {
  if (idx < 0 || idx >= static_cast<int>(entries.size())) return;
  entries.erase(entries.begin() + idx);
  if (selected >= static_cast<int>(entries.size())) selected = std::max(0, static_cast<int>(entries.size()) - 1);
  dirty = true;
  save();
}

// --- Input ---

void AuthenticatorActivity::loop() {
  using Button = MappedInputManager::Button;

  if (menuOpen) {
    if (mappedInput.wasPressed(Button::Back)) {
      menuOpen = false;
      requestUpdate();
      return;
    }
    if (mappedInput.wasPressed(Button::Confirm)) {
      menuOpen = false;
      if (menuSel == 0) deleteEntry(selected);
      requestUpdate();
      return;
    }
    buttonNavigator.onNext([this] {
      menuSel = ButtonNavigator::nextIndex(menuSel, MENU_COUNT);
      requestUpdate();
    });
    buttonNavigator.onPrevious([this] {
      menuSel = ButtonNavigator::previousIndex(menuSel, MENU_COUNT);
      requestUpdate();
    });
    return;
  }

  if (handleToolBack()) {
    return;
  }
  if (mappedInput.wasPressed(Button::Right)) {
    addEntry();
    return;
  }
  if (!entries.empty()) {
    const int n = static_cast<int>(entries.size());
    if (mappedInput.wasPressed(Button::Up)) {
      selected = ButtonNavigator::previousIndex(selected, n);
      requestUpdate();
      return;
    }
    if (mappedInput.wasPressed(Button::Down)) {
      selected = ButtonNavigator::nextIndex(selected, n);
      requestUpdate();
      return;
    }
    if (mappedInput.wasPressed(Button::Confirm)) {
      menuOpen = true;
      menuSel = 0;
      requestUpdate();
      return;
    }
  }

  // Roll the codes over when the 30s window advances (one e-ink refresh / period).
  // Poll the RTC at most once a second: getUnixTime() is a blocking DS3231 I2C read,
  // and calling it every loop tick pointlessly hammers the shared I2C bus.
  const uint32_t now = millis();
  if (now - lastCheckMs < 1000) return;
  lastCheckMs = now;
  const uint32_t prevPeriod = lastPeriod;
  refreshCodes(false);
  if (haveTime && lastPeriod != prevPeriod) requestUpdate();
}

// --- Rendering ---

void AuthenticatorActivity::render(RenderLock&&) {
  if (menuOpen) {
    renderMenu();
    return;
  }
  renderList();
}

void AuthenticatorActivity::renderList() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  const auto pageHeight = renderer.getScreenHeight();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;

  char sub[24];
  if (haveTime)
    snprintf(sub, sizeof(sub), tr(STR_TOTP_NEW_IN_FMT), secondsLeft);
  else
    snprintf(sub, sizeof(sub), "%s", tr(STR_NO_CLOCK));
  beginToolRender(tr(STR_AUTHENTICATOR), sub);

  const int listHeight = pageHeight - contentTop - metrics.buttonHintsHeight - metrics.verticalSpacing;
  if (!haveTime) {
    const auto h = renderer.getLineHeight(UI_10_FONT_ID);
    const auto top = contentTop + (pageHeight - contentTop - metrics.buttonHintsHeight - h) / 2;
    UITheme::drawCenteredText(renderer, Rect{0, contentTop, pageWidth, pageHeight - contentTop}, UI_10_FONT_ID, top,
                              tr(STR_SET_CLOCK_FIRST));
  } else if (entries.empty()) {
    const auto h = renderer.getLineHeight(UI_10_FONT_ID);
    const auto top = contentTop + (pageHeight - contentTop - metrics.buttonHintsHeight - h) / 2;
    UITheme::drawCenteredText(renderer, Rect{0, contentTop, pageWidth, pageHeight - contentTop}, UI_10_FONT_ID, top,
                              tr(STR_NO_ACCOUNTS));
  } else {
    GUI.drawList(
        renderer, Rect{0, contentTop, pageWidth, listHeight}, static_cast<int>(entries.size()), selected,
        [this](int i) { return entries[i].label; }, nullptr, nullptr, [this](int i) { return entries[i].code; },
        true);  // code as the highlighted right-aligned value
  }

  const bool any = !entries.empty();
  endToolRender(tr(STR_BTN_BACK), any ? tr(STR_MENU) : "", "", tr(STR_ADD));
}

void AuthenticatorActivity::renderMenu() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  const auto pageHeight = renderer.getScreenHeight();
  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;
  beginToolRender(tr(STR_ACCOUNT_ACTIONS));

  const int listHeight = pageHeight - contentTop - metrics.buttonHintsHeight - metrics.verticalSpacing;
  GUI.drawList(
      renderer, Rect{0, contentTop, pageWidth, listHeight}, MENU_COUNT, menuSel,
      [](int i) -> std::string { return i == 0 ? tr(STR_DELETE) : tr(STR_CANCEL); }, nullptr, nullptr);

  endToolRender(tr(STR_BTN_BACK), tr(STR_SELECT), tr(STR_DIR_UP), tr(STR_DIR_DOWN));
}
