#pragma once

#include <cstddef>
#include <string>
#include <vector>

/**
 * Turns web content into plain text on the SD card.
 *
 * Both entry points are streaming: the response body is consumed in chunks by a
 * byte-at-a-time state machine and written straight out, so a 500 KB article
 * costs the same RAM as a 5 KB one. Nothing here renders HTML -- tags are
 * discarded, a few block-level ones become newlines, and the result is a text
 * file the reader can open like any other book.
 */
class ArticleExtractor {
 public:
  struct FeedItem {
    std::string title;
    std::string link;
  };

  /**
   * Fetch `url`, reduce it to text, and write it to `destPath`.
   * `titleOut` receives the document's <title> when it has one.
   */
  static bool fetchToText(const std::string& url, const std::string& destPath, std::string& titleOut);

  /**
   * Fetch and parse an RSS 2.0 or Atom feed into at most `maxItems` entries.
   */
  static bool fetchFeed(const std::string& url, std::vector<FeedItem>& items, size_t maxItems);

  /**
   * Build a safe 8.3-ish SD file name from an article title, without extension.
   * Falls back to "article" when the title has no usable characters.
   */
  static std::string slugify(const std::string& title);

  static constexpr size_t MAX_TITLE_LEN = 120;
  static constexpr size_t MAX_LINK_LEN = 250;
};
