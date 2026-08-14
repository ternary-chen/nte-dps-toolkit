#!/usr/bin/env python3
"""Build a deterministic GE/GA/Buff/Debuff identifier catalog from NTE_Assets."""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_FILES = 20_000
IDENTIFIER = re.compile(r'(?<![A-Za-z0-9_])((?:GE|GA|Buff|Debuff)_[A-Za-z0-9_]+)')


def normalized(value: str) -> str:
    if value.startswith("Default__"):
        value = value[9:]
    if value.lower().endswith("_c"):
        value = value[:-2]
    return value.lower()


def fnv1a64(value: str) -> int:
    result = 0xCBF29CE484222325
    for byte in normalized(value).encode("ascii"):
        result ^= byte
        result = (result * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assets", type=Path, default=Path("NTE_Assets"))
    parser.add_argument("--output", type=Path, default=Path("res/data/effects/effect_catalog.json"))
    args = parser.parse_args()
    files = sorted(args.assets.rglob("*.json"))
    if len(files) > MAX_FILES:
        raise SystemExit(f"asset file budget exceeded: {len(files)} > {MAX_FILES}")
    names: Counter[str] = Counter()
    for path in files:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise SystemExit(f"asset file too large: {path} ({size})")
        text = path.read_text(encoding="utf-8", errors="strict")
        names.update(IDENTIFIER.findall(text))
    rows = []
    for name in sorted(names, key=lambda value: (fnv1a64(value), value)):
        prefix = name.split("_", 1)[0].lower()
        rows.append({"hash": f"{fnv1a64(name):016x}", "name": name, "kind": prefix, "references": names[name]})
    document = {"version": 1, "source": "NTE_Assets", "fileCount": len(files), "entryCount": len(rows), "entries": rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"files={len(files)} entries={len(rows)} output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
