#!/usr/bin/env python3
"""Convert GNU GCIDE CIDE.* files to Radio Ink dictionary.tsv.

Output format:
  word<TAB>definition

The firmware displays definitions from a 512-byte buffer, so this converter
keeps entries compact by default.
"""

from __future__ import annotations

import argparse
import html
import re
from collections import OrderedDict
from pathlib import Path


ENTRY_RE = re.compile(r"<p><ent>(.*?)</ent>(.*?)(?=\n<p><ent>|\Z)", re.DOTALL)
DEF_RE = re.compile(r"<def>(.*?)</def>", re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")
GCIDE_SELF_TAG_RE = re.compile(r"<([A-Za-z][A-Za-z0-9]*)/")

GCIDE_SELF_TAG_TEXT = {
    "ae": "ae",
    "aemac": "ae",
    "aum": "a",
    "eum": "e",
    "imac": "i",
    "ium": "i",
    "ldquo": '"',
    "lsquo": "'",
    "ntil": "n",
    "oe": "oe",
    "oemac": "oe",
    "omac": "o",
    "oum": "o",
    "rdquo": '"',
    "rsquo": "'",
    "sect": "section",
    "umac": "u",
    "uum": "u",
    "yuml": "y",
}


def normalize_lookup_word(raw: str) -> str:
    out: list[str] = []
    for ch in raw:
        if ch.isascii() and ch.isalnum():
            out.append(ch.lower())
        elif ch in ("'", "-") and out:
            out.append(ch)

    while out and out[-1] in ("'", "-"):
        out.pop()
    return "".join(out)


def clean_text(raw: str) -> str:
    text = html.unescape(raw)
    text = GCIDE_SELF_TAG_RE.sub(lambda match: GCIDE_SELF_TAG_TEXT.get(match.group(1).lower(), ""), text)
    text = TAG_RE.sub("", text)
    text = text.replace("\t", " ")
    return " ".join(text.split())


def compact_definition(parts: list[str], max_chars: int) -> str:
    definition = "; ".join(part for part in parts if part)
    if len(definition) <= max_chars:
        return definition

    clipped = definition[: max(0, max_chars - 1)].rstrip()
    last_space = clipped.rfind(" ")
    if last_space > max_chars * 2 // 3:
        clipped = clipped[:last_space]
    return clipped.rstrip(" ;,.") + "..."


def iter_cide_files(source_dir: Path) -> list[Path]:
    return sorted(path for path in source_dir.glob("CIDE.*") if path.is_file() and path.name != "CIDE.*")


def convert_gcide(source_dir: Path, output_path: Path, max_chars: int, max_defs: int) -> tuple[int, int]:
    entries: OrderedDict[str, list[str]] = OrderedDict()
    skipped = 0

    for path in iter_cide_files(source_dir):
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in ENTRY_RE.finditer(text):
            word = clean_text(match.group(1))
            normalized = normalize_lookup_word(word)
            if len(normalized) < 2:
                skipped += 1
                continue

            defs = [clean_text(def_match.group(1)) for def_match in DEF_RE.finditer(match.group(2))]
            defs = [definition for definition in defs if definition]
            if not defs:
                skipped += 1
                continue

            bucket = entries.setdefault(normalized, [])
            for definition in defs:
                if definition not in bucket:
                    bucket.append(definition)
                if len(bucket) >= max_defs:
                    break

    with output_path.open("w", encoding="utf-8", newline="\n") as out:
        for word, defs in entries.items():
            out.write(word)
            out.write("\t")
            out.write(compact_definition(defs[:max_defs], max_chars))
            out.write("\n")

    return len(entries), skipped


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert GNU GCIDE CIDE.* files to dictionary.tsv.")
    parser.add_argument("source_dir", type=Path, help="Directory containing GCIDE CIDE.* files")
    parser.add_argument("output", type=Path, help="Output dictionary.tsv path")
    parser.add_argument("--max-chars", type=int, default=420, help="Maximum definition characters per word")
    parser.add_argument("--max-defs", type=int, default=3, help="Maximum definitions to keep per word")
    args = parser.parse_args()

    count, skipped = convert_gcide(args.source_dir, args.output, args.max_chars, args.max_defs)
    print(f"Wrote {count} entries to {args.output}")
    if skipped:
        print(f"Skipped {skipped} entries without a lookup key or definition")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
