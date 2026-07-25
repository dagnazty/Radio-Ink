#!/usr/bin/env python3
"""Split a TSV dictionary into Radio Ink SD-card dictionary shards.

Input format:
  word<TAB>definition

Output format:
  <output-dir>/a.tsv
  <output-dir>/b.tsv
  ...
  <output-dir>/0.tsv

The firmware also supports a flat /dictionary.tsv fallback, but sharded files
avoid scanning the whole dictionary for every lookup.
"""

from __future__ import annotations

import argparse
from pathlib import Path


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


def shard_name(word: str) -> str | None:
    normalized = normalize_lookup_word(word)
    if not normalized:
        return None
    first = normalized[0]
    if first.isascii() and first.isalnum():
        return f"{first}.tsv"
    return None


def split_dictionary(input_path: Path, output_dir: Path) -> tuple[int, int]:
    output_dir.mkdir(parents=True, exist_ok=True)
    handles: dict[str, object] = {}
    written = 0
    skipped = 0

    try:
        with input_path.open("r", encoding="utf-8", errors="replace") as src:
            for line in src:
                line = line.rstrip("\r\n")
                if not line or "\t" not in line:
                    skipped += 1
                    continue

                key = line.split("\t", 1)[0]
                name = shard_name(key)
                if name is None:
                    skipped += 1
                    continue

                handle = handles.get(name)
                if handle is None:
                    handle = (output_dir / name).open("w", encoding="utf-8")
                    handles[name] = handle

                handle.write(line)
                handle.write("\n")
                written += 1
    finally:
        for handle in handles.values():
            handle.close()

    return written, skipped


def main() -> int:
    parser = argparse.ArgumentParser(description="Split dictionary.tsv into Radio Ink dictionary shards.")
    parser.add_argument("input", type=Path, help="Source TSV file: word<TAB>definition")
    parser.add_argument("output_dir", type=Path, help="Destination directory, usually SD:/dictionary")
    args = parser.parse_args()

    written, skipped = split_dictionary(args.input, args.output_dir)
    print(f"Wrote {written} entries to {args.output_dir}")
    if skipped:
        print(f"Skipped {skipped} malformed or unlookupable lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
