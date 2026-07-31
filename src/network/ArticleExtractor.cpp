#include "ArticleExtractor.h"

#include <HalStorage.h>
#include <Logging.h>

#include <cctype>
#include <cstring>

#include "HttpDownloader.h"

namespace {
constexpr const char* MODULE = "Article";
// Text is accumulated here and flushed to SD in one write per bufferful rather
// than a write per character.
constexpr size_t OUT_BUFFER_FLUSH = 512;

bool equalsIgnoreCase(const std::string& value, const char* other) { return strcasecmp(value.c_str(), other) == 0; }

// Expands the handful of entities that actually show up in article text. Anything
// unrecognised is dropped rather than passed through as literal "&#8230;".
void appendEntity(const std::string& entity, std::string& out) {
  if (entity.empty()) return;

  if (entity[0] == '#') {
    // Numeric entity: &#8217; or &#x2019;
    long code = 0;
    if (entity.size() > 2 && (entity[1] == 'x' || entity[1] == 'X')) {
      code = strtol(entity.c_str() + 2, nullptr, 16);
    } else {
      code = strtol(entity.c_str() + 1, nullptr, 10);
    }
    if (code <= 0) return;
    // Map the common typographic codepoints to ASCII the built-in fonts render
    // reliably; emit anything else in the Latin-1 range as UTF-8.
    switch (code) {
      case 0x2018:
      case 0x2019:
        out += '\'';
        return;
      case 0x201C:
      case 0x201D:
        out += '"';
        return;
      case 0x2013:
      case 0x2014:
        out += '-';
        return;
      case 0x2026:
        out += "...";
        return;
      case 0xA0:
        out += ' ';
        return;
      default:
        break;
    }
    if (code < 0x80) {
      out += static_cast<char>(code);
    } else if (code < 0x800) {
      out += static_cast<char>(0xC0 | (code >> 6));
      out += static_cast<char>(0x80 | (code & 0x3F));
    } else if (code < 0x10000) {
      out += static_cast<char>(0xE0 | (code >> 12));
      out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
      out += static_cast<char>(0x80 | (code & 0x3F));
    }
    return;
  }

  if (equalsIgnoreCase(entity, "amp")) {
    out += '&';
  } else if (equalsIgnoreCase(entity, "lt")) {
    out += '<';
  } else if (equalsIgnoreCase(entity, "gt")) {
    out += '>';
  } else if (equalsIgnoreCase(entity, "quot")) {
    out += '"';
  } else if (equalsIgnoreCase(entity, "apos") || equalsIgnoreCase(entity, "#39")) {
    out += '\'';
  } else if (equalsIgnoreCase(entity, "nbsp")) {
    out += ' ';
  } else if (equalsIgnoreCase(entity, "mdash") || equalsIgnoreCase(entity, "ndash")) {
    out += '-';
  } else if (equalsIgnoreCase(entity, "hellip")) {
    out += "...";
  }
}

// True for tags whose close should end the current line of output.
bool isBlockTag(const std::string& tag) {
  static const char* const BLOCK_TAGS[] = {"p",  "div", "br", "h1", "h2", "h3",    "h4",      "h5",
                                           "h6", "li",  "tr", "ul", "ol", "table", "section", "article"};
  for (const char* candidate : BLOCK_TAGS) {
    if (equalsIgnoreCase(tag, candidate)) return true;
  }
  return false;
}

// Streaming HTML -> text reduction. One instance walks the whole response.
class HtmlToText {
 public:
  HtmlToText(HalFile& file, std::string& title) : out(file), documentTitle(title) { pending.reserve(OUT_BUFFER_FLUSH); }

  void feed(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) consume(static_cast<char>(data[i]));
  }

  void finish() {
    flushWord();
    flushPending(true);
  }

 private:
  enum class State { Text, TagName, TagRest, Entity };

  HalFile& out;
  std::string& documentTitle;

  State state = State::Text;
  std::string tagName;
  std::string entity;
  std::string pending;  // text waiting to be written to SD
  bool closingTag = false;
  bool inSkippedElement = false;  // inside <script>/<style>: drop everything
  std::string skippedTag;
  bool capturingTitle = false;
  bool lineHasContent = false;
  bool pendingSpace = false;

  void consume(char c) {
    switch (state) {
      case State::Text:
        if (c == '<') {
          tagName.clear();
          closingTag = false;
          state = State::TagName;
        } else if (c == '&') {
          entity.clear();
          state = State::Entity;
        } else {
          emitTextChar(c);
        }
        return;

      case State::TagName:
        if (tagName.empty() && c == '/') {
          closingTag = true;
          return;
        }
        if (isalnum(static_cast<unsigned char>(c))) {
          if (tagName.size() < 16) tagName += c;
          return;
        }
        // Tag name finished; the rest of the tag is attributes we don't need.
        handleTag();
        state = c == '>' ? State::Text : State::TagRest;
        return;

      case State::TagRest:
        if (c == '>') state = State::Text;
        return;

      case State::Entity:
        if (c == ';') {
          std::string decoded;
          appendEntity(entity, decoded);
          for (char decodedChar : decoded) emitTextChar(decodedChar);
          state = State::Text;
        } else if (entity.size() >= 10 || isspace(static_cast<unsigned char>(c))) {
          // Not actually an entity ("Tom & Jerry"): treat it as literal text.
          emitTextChar('&');
          for (char entityChar : entity) emitTextChar(entityChar);
          emitTextChar(c);
          state = State::Text;
        } else {
          entity += c;
        }
        return;
    }
  }

  void handleTag() {
    if (inSkippedElement) {
      // Only the matching close tag gets us out again.
      if (closingTag && equalsIgnoreCase(tagName, skippedTag.c_str())) inSkippedElement = false;
      return;
    }

    if (!closingTag && (equalsIgnoreCase(tagName, "script") || equalsIgnoreCase(tagName, "style") ||
                        equalsIgnoreCase(tagName, "head") || equalsIgnoreCase(tagName, "nav") ||
                        equalsIgnoreCase(tagName, "footer"))) {
      // <head> is skipped wholesale, but the title inside it is still wanted, so
      // it is handled by its own flag below rather than by skipping.
      if (equalsIgnoreCase(tagName, "head")) return;
      inSkippedElement = true;
      skippedTag = tagName;
      return;
    }

    if (equalsIgnoreCase(tagName, "title")) {
      capturingTitle = !closingTag;
      return;
    }

    if (isBlockTag(tagName)) newline();
  }

  void emitTextChar(char c) {
    if (inSkippedElement) return;

    if (capturingTitle) {
      if (documentTitle.size() < ArticleExtractor::MAX_TITLE_LEN &&
          !(documentTitle.empty() && isspace(static_cast<unsigned char>(c)))) {
        documentTitle += isspace(static_cast<unsigned char>(c)) ? ' ' : c;
      }
      return;
    }

    if (isspace(static_cast<unsigned char>(c))) {
      // Collapse every run of whitespace to a single space, and never open a line
      // with one -- HTML source is mostly indentation.
      if (lineHasContent) pendingSpace = true;
      return;
    }

    if (pendingSpace) {
      pending += ' ';
      pendingSpace = false;
    }
    pending += c;
    lineHasContent = true;
    flushPending(false);
  }

  void newline() {
    if (!lineHasContent) return;  // no run of blank lines between nested tags
    pending += '\n';
    lineHasContent = false;
    pendingSpace = false;
    flushPending(false);
  }

  void flushWord() {
    if (lineHasContent) pending += '\n';
    lineHasContent = false;
  }

  void flushPending(bool force) {
    if (!force && pending.size() < OUT_BUFFER_FLUSH) return;
    if (pending.empty()) return;
    out.write(pending.data(), pending.size());
    pending.clear();
  }
};

// Streaming RSS/Atom scan. Deliberately not a real XML parser: it tracks the two
// element names that matter and pulls their text, which is enough for titles and
// links and costs a few hundred bytes.
class FeedParser {
 public:
  FeedParser(std::vector<ArticleExtractor::FeedItem>& out, size_t maxItems) : items(out), limit(maxItems) {}

  void feed(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len && items.size() < limit; i++) consume(static_cast<char>(data[i]));
  }

  void finish() { commitIfComplete(); }

 private:
  enum class State { Text, TagName, TagRest };

  std::vector<ArticleExtractor::FeedItem>& items;
  size_t limit;

  State state = State::Text;
  std::string tagName;
  std::string tagRest;
  bool closingTag = false;

  bool inItem = false;
  bool inTitle = false;
  bool inLink = false;
  std::string currentTitle;
  std::string currentLink;

  void consume(char c) {
    switch (state) {
      case State::Text:
        if (c == '<') {
          tagName.clear();
          tagRest.clear();
          closingTag = false;
          state = State::TagName;
        } else {
          collectText(c);
        }
        return;

      case State::TagName:
        if (tagName.empty() && c == '/') {
          closingTag = true;
          return;
        }
        if (isalnum(static_cast<unsigned char>(c)) || c == ':') {
          if (tagName.size() < 24) tagName += c;
          return;
        }
        if (c == '>') {
          handleTag();
          state = State::Text;
          return;
        }
        state = State::TagRest;
        return;

      case State::TagRest:
        if (c == '>') {
          handleTag();
          state = State::Text;
          return;
        }
        if (tagRest.size() < 400) tagRest += c;
        return;
    }
  }

  void collectText(char c) {
    if (inTitle && currentTitle.size() < ArticleExtractor::MAX_TITLE_LEN) {
      if (c == '\n' || c == '\r' || c == '\t') c = ' ';
      // Skip leading whitespace and CDATA scaffolding.
      if (!(currentTitle.empty() && c == ' ')) currentTitle += c;
    } else if (inLink && currentLink.size() < ArticleExtractor::MAX_LINK_LEN) {
      if (!isspace(static_cast<unsigned char>(c))) currentLink += c;
    }
  }

  // Atom links carry the URL in href="" rather than as element text.
  void extractHref() {
    const char* rest = tagRest.c_str();
    const char* href = strcasestr(rest, "href");
    if (!href) return;
    const char* quote = strpbrk(href, "\"'");
    if (!quote) return;
    const char delimiter = *quote++;
    const char* end = strchr(quote, delimiter);
    if (!end) return;
    const size_t length = static_cast<size_t>(end - quote);
    if (length == 0 || length > ArticleExtractor::MAX_LINK_LEN) return;
    // Prefer the alternate/permalink over self/replies rel values.
    if (strcasestr(rest, "rel=") && !strcasestr(rest, "alternate")) return;
    currentLink.assign(quote, length);
  }

  void handleTag() {
    if (equalsIgnoreCase(tagName, "item") || equalsIgnoreCase(tagName, "entry")) {
      if (closingTag) {
        commitIfComplete();
        inItem = false;
      } else {
        currentTitle.clear();
        currentLink.clear();
        inItem = true;
      }
      return;
    }

    if (!inItem) return;

    if (equalsIgnoreCase(tagName, "title")) {
      inTitle = !closingTag;
      return;
    }
    if (equalsIgnoreCase(tagName, "link")) {
      if (closingTag) {
        inLink = false;
      } else {
        extractHref();                 // Atom form; harmless for RSS
        inLink = currentLink.empty();  // RSS form: take the element text instead
      }
    }
  }

  void commitIfComplete() {
    if (currentTitle.empty() || currentLink.empty()) return;
    if (items.size() >= limit) return;

    // Strip CDATA wrappers that survived the text collection.
    std::string title = currentTitle;
    const size_t cdataStart = title.find("[CDATA[");
    if (cdataStart != std::string::npos) {
      title.erase(0, cdataStart + 7);
      const size_t cdataEnd = title.find("]]");
      if (cdataEnd != std::string::npos) title.erase(cdataEnd);
    }
    while (!title.empty() && isspace(static_cast<unsigned char>(title.back()))) title.pop_back();

    if (!title.empty()) items.push_back({title, currentLink});
    currentTitle.clear();
    currentLink.clear();
  }
};
}  // namespace

std::string ArticleExtractor::slugify(const std::string& title) {
  std::string slug;
  slug.reserve(32);
  for (char c : title) {
    if (slug.size() >= 32) break;
    if (isalnum(static_cast<unsigned char>(c))) {
      slug += static_cast<char>(tolower(static_cast<unsigned char>(c)));
    } else if (!slug.empty() && slug.back() != '-') {
      slug += '-';
    }
  }
  while (!slug.empty() && slug.back() == '-') slug.pop_back();
  return slug.empty() ? "article" : slug;
}

bool ArticleExtractor::fetchToText(const std::string& url, const std::string& destPath, std::string& titleOut) {
  HalFile file;
  if (!Storage.openFileForWrite(MODULE, destPath, file)) {
    LOG_ERR(MODULE, "Cannot open %s for write", destPath.c_str());
    return false;
  }

  HtmlToText converter(file, titleOut);
  const bool ok = HttpDownloader::fetchUrl(url, [&converter](const uint8_t* data, size_t len) {
    converter.feed(data, len);
    return true;
  });
  converter.finish();
  file.flush();

  if (!ok) {
    LOG_ERR(MODULE, "Fetch failed: %s", url.c_str());
    // Close before removing: the SdFat handle must be released first.
    file.close();
    Storage.remove(destPath.c_str());
    return false;
  }

  if (file.fileSize() == 0) {
    LOG_ERR(MODULE, "Nothing extracted from %s", url.c_str());
    file.close();
    Storage.remove(destPath.c_str());
    return false;
  }

  return true;
}

bool ArticleExtractor::fetchFeed(const std::string& url, std::vector<FeedItem>& items, size_t maxItems) {
  items.clear();
  items.reserve(maxItems);

  FeedParser parser(items, maxItems);
  const bool ok = HttpDownloader::fetchUrl(url, [&parser](const uint8_t* data, size_t len) {
    parser.feed(data, len);
    return true;
  });
  parser.finish();

  if (!ok) {
    LOG_ERR(MODULE, "Feed fetch failed: %s", url.c_str());
    return false;
  }
  return !items.empty();
}
