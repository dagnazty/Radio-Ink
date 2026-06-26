#include "LanguageRegistry.h"

#include <algorithm>
#include <array>

#include "HyphenationCommon.h"

// Per-language hyphenation toggles. English is ALWAYS compiled in; every other
// language's pattern trie is OFF by default to minimize flash. Approx trie sizes:
// de ~206 KB, ru ~33 KB, sv ~24 KB, uk ~21 KB, pl ~16 KB, es ~14 KB, fr ~7 KB,
// it ~1.5 KB. Re-enable one language with -DHYPH_ENABLE_<CODE> (e.g. HYPH_ENABLE_DE),
// or compile them all back in with -DHYPH_ENABLE_ALL. Disabling a language only
// drops mid-word hyphenation for it -- text still renders and wraps at word
// boundaries.
#if defined(HYPH_ENABLE_ALL)
#define HYPH_ENABLE_DE
#define HYPH_ENABLE_FR
#define HYPH_ENABLE_RU
#define HYPH_ENABLE_ES
#define HYPH_ENABLE_IT
#define HYPH_ENABLE_PL
#define HYPH_ENABLE_SV
#define HYPH_ENABLE_UK
#endif

#include "generated/hyph-en.trie.h"
#if defined(HYPH_ENABLE_DE)
#include "generated/hyph-de.trie.h"
#endif
#if defined(HYPH_ENABLE_FR)
#include "generated/hyph-fr.trie.h"
#endif
#if defined(HYPH_ENABLE_RU)
#include "generated/hyph-ru.trie.h"
#endif
#if defined(HYPH_ENABLE_ES)
#include "generated/hyph-es.trie.h"
#endif
#if defined(HYPH_ENABLE_IT)
#include "generated/hyph-it.trie.h"
#endif
#if defined(HYPH_ENABLE_PL)
#include "generated/hyph-pl.trie.h"
#endif
#if defined(HYPH_ENABLE_SV)
#include "generated/hyph-sv.trie.h"
#endif
#if defined(HYPH_ENABLE_UK)
#include "generated/hyph-uk.trie.h"
#endif

namespace {

// English is always available (3/3 minimum prefix/suffix length).
LanguageHyphenator englishHyphenator(en_patterns, isLatinLetter, toLowerLatin, 3, 3);

// Each optional language compiles its hyphenator and a registry entry only when
// its flag is set; otherwise both the entry and its count collapse to nothing, so
// the registry array shrinks to exactly the languages that are enabled.
#if defined(HYPH_ENABLE_FR)
LanguageHyphenator frenchHyphenator(fr_patterns, isLatinLetter, toLowerLatin);
#define HYPH_FR_ENTRY {"french", "fr", &frenchHyphenator},
#define HYPH_FR_COUNT 1
#else
#define HYPH_FR_ENTRY
#define HYPH_FR_COUNT 0
#endif

#if defined(HYPH_ENABLE_DE)
LanguageHyphenator germanHyphenator(de_patterns, isLatinLetter, toLowerLatin);
#define HYPH_DE_ENTRY {"german", "de", &germanHyphenator},
#define HYPH_DE_COUNT 1
#else
#define HYPH_DE_ENTRY
#define HYPH_DE_COUNT 0
#endif

#if defined(HYPH_ENABLE_RU)
LanguageHyphenator russianHyphenator(ru_patterns, isCyrillicLetter, toLowerCyrillic);
#define HYPH_RU_ENTRY {"russian", "ru", &russianHyphenator},
#define HYPH_RU_COUNT 1
#else
#define HYPH_RU_ENTRY
#define HYPH_RU_COUNT 0
#endif

#if defined(HYPH_ENABLE_ES)
LanguageHyphenator spanishHyphenator(es_patterns, isLatinLetter, toLowerLatin);
#define HYPH_ES_ENTRY {"spanish", "es", &spanishHyphenator},
#define HYPH_ES_COUNT 1
#else
#define HYPH_ES_ENTRY
#define HYPH_ES_COUNT 0
#endif

#if defined(HYPH_ENABLE_IT)
LanguageHyphenator italianHyphenator(it_patterns, isLatinLetter, toLowerLatin);
#define HYPH_IT_ENTRY {"italian", "it", &italianHyphenator},
#define HYPH_IT_COUNT 1
#else
#define HYPH_IT_ENTRY
#define HYPH_IT_COUNT 0
#endif

#if defined(HYPH_ENABLE_PL)
LanguageHyphenator polishHyphenator(pl_patterns, isLatinLetter, toLowerLatin);
#define HYPH_PL_ENTRY {"polish", "pl", &polishHyphenator},
#define HYPH_PL_COUNT 1
#else
#define HYPH_PL_ENTRY
#define HYPH_PL_COUNT 0
#endif

#if defined(HYPH_ENABLE_SV)
LanguageHyphenator swedishHyphenator(sv_patterns, isLatinLetter, toLowerLatin);
#define HYPH_SV_ENTRY {"swedish", "sv", &swedishHyphenator},
#define HYPH_SV_COUNT 1
#else
#define HYPH_SV_ENTRY
#define HYPH_SV_COUNT 0
#endif

#if defined(HYPH_ENABLE_UK)
LanguageHyphenator ukrainianHyphenator(uk_patterns, isCyrillicLetter, toLowerCyrillic);
#define HYPH_UK_ENTRY {"ukrainian", "uk", &ukrainianHyphenator},
#define HYPH_UK_COUNT 1
#else
#define HYPH_UK_ENTRY
#define HYPH_UK_COUNT 0
#endif

using EntryArray = std::array<LanguageEntry, 1 + HYPH_FR_COUNT + HYPH_DE_COUNT + HYPH_RU_COUNT + HYPH_ES_COUNT +
                                                 HYPH_IT_COUNT + HYPH_PL_COUNT + HYPH_SV_COUNT + HYPH_UK_COUNT>;

const EntryArray& entries() {
  static const EntryArray kEntries = {{{"english", "en", &englishHyphenator},
                                       HYPH_FR_ENTRY HYPH_DE_ENTRY HYPH_RU_ENTRY HYPH_ES_ENTRY HYPH_IT_ENTRY
                                           HYPH_PL_ENTRY HYPH_SV_ENTRY HYPH_UK_ENTRY}};
  return kEntries;
}

}  // namespace

const LanguageHyphenator* getLanguageHyphenatorForPrimaryTag(const std::string& primaryTag) {
  const auto& allEntries = entries();
  const auto it = std::find_if(allEntries.begin(), allEntries.end(),
                               [&primaryTag](const LanguageEntry& entry) { return primaryTag == entry.primaryTag; });
  return (it != allEntries.end()) ? it->hyphenator : nullptr;
}

LanguageEntryView getLanguageEntries() {
  const auto& allEntries = entries();
  return LanguageEntryView{allEntries.data(), allEntries.size()};
}
