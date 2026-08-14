#!/usr/bin/env python3
"""Build a high-precision catalog of Buff effects confirmed to affect players."""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from build_enriched_effect_catalog import (
    MAX_TABLE_ROWS,
    build_localization_index,
    load_rows,
    read_json,
    resolve_text_reference,
    validate_text,
)

DEFAULT_ASSETS = Path("NTE_Assets")
DEFAULT_ENRICHED_CATALOG = Path("res/data/effects/effect_catalog_enriched.json")
DEFAULT_OUTPUT = Path("res/data/effects/player_buff_catalog.json")
MAX_AWAKEN_FILES = 100
MAX_EVIDENCE_PER_BUFF = 20


@dataclass(frozen=True)
class PlayerBuffEvidence:
    kind: str
    source: str
    display_name: str | None = None
    description: str | None = None
    buff_type: str | None = None


def buff_name_from_reference(reference: Any) -> str | None:
    if not isinstance(reference, dict):
        return None
    path = validate_text(reference.get("AssetPathName"), field="Buff.AssetPathName")
    if not path:
        return None
    leaf = path.rsplit("/", 1)[-1].split(".", 1)[0]
    if leaf.lower().endswith("_c"):
        leaf = leaf[:-2]
    return leaf if leaf.startswith("Buff_") else None


def first_ability_description(
    row: dict[str, Any], localization: dict[str, list[Any]]
) -> str | None:
    items = row.get("AbilityDescription", [])
    if not isinstance(items, list) or len(items) > MAX_TABLE_ROWS:
        raise ValueError("AbilityDescription must be a bounded array")
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("AbilityDescription item must be an object")
        if item.get("AbilityDesType") != "EAbilityDesType::ADT_DES":
            continue
        text, _, ambiguous = resolve_text_reference(item.get("Description"), localization)
        if ambiguous:
            raise ValueError("ambiguous ability description")
        if text:
            return text
    return None


def add_evidence(
    evidence: dict[str, list[PlayerBuffEvidence]], name: str, item: PlayerBuffEvidence
) -> None:
    values = evidence[name]
    if item not in values:
        values.append(item)
    if len(values) > MAX_EVIDENCE_PER_BUFF:
        raise ValueError(f"evidence budget exceeded for {name}")


def collect_visible_buff_evidence(
    effect_rows: dict[str, dict[str, Any]],
    localization: dict[str, list[Any]],
) -> dict[str, list[PlayerBuffEvidence]]:
    evidence: dict[str, list[PlayerBuffEvidence]] = defaultdict(list)
    for name, row in effect_rows.items():
        if not name.startswith("Buff_") or row.get("IsShowInBuffMaganger") is not True:
            continue
        display_name, _, name_ambiguous = resolve_text_reference(row.get("Name"), localization)
        description, _, description_ambiguous = resolve_text_reference(row.get("Desc"), localization)
        if name_ambiguous or description_ambiguous:
            raise ValueError(f"ambiguous visible Buff text: {name}")
        buff_type = validate_text(row.get("BuffType"), field=f"{name}.BuffType")
        add_evidence(
            evidence,
            name,
            PlayerBuffEvidence(
                kind="buff_manager_visible",
                source="GameplayEffectTipsDataTable",
                display_name=display_name,
                description=description,
                buff_type=buff_type,
            ),
        )
    return dict(evidence)


def collect_passive_buff_evidence(
    config_rows: dict[str, dict[str, Any]],
    ability_rows: dict[str, dict[str, Any]],
    localization: dict[str, list[Any]],
) -> dict[str, list[PlayerBuffEvidence]]:
    evidence: dict[str, list[PlayerBuffEvidence]] = defaultdict(list)
    for ability_name, row in config_rows.items():
        name = buff_name_from_reference(row.get("GameplayEffectToActivate"))
        if not name:
            continue
        ability_row = ability_rows.get(ability_name, {})
        display_name, _, name_ambiguous = resolve_text_reference(
            ability_row.get("Name"), localization
        )
        if name_ambiguous:
            raise ValueError(f"ambiguous passive Buff name: {name}")
        description = first_ability_description(ability_row, localization)
        add_evidence(
            evidence,
            name,
            PlayerBuffEvidence(
                kind="character_passive_effect",
                source="DT_CharacterAbilityEffectConfig",
                display_name=display_name,
                description=description,
            ),
        )
    return dict(evidence)


def collect_awaken_buff_evidence(
    awaken_directory: Path,
    localization: dict[str, list[Any]],
) -> dict[str, list[PlayerBuffEvidence]]:
    files = sorted(awaken_directory.glob("*.json"))
    if len(files) > MAX_AWAKEN_FILES:
        raise ValueError("awaken file budget exceeded")
    evidence: dict[str, list[PlayerBuffEvidence]] = defaultdict(list)
    for path in files:
        for row in load_rows(path).values():
            items = row.get("AwakenEffectStructList", [])
            if not isinstance(items, list) or len(items) > MAX_TABLE_ROWS:
                raise ValueError(f"AwakenEffectStructList must be bounded: {path}")
            for item in items:
                if not isinstance(item, dict):
                    raise ValueError(f"invalid awaken effect item: {path}")
                display_name, _, name_ambiguous = resolve_text_reference(
                    item.get("Title"), localization
                )
                description, _, description_ambiguous = resolve_text_reference(
                    item.get("Desc"), localization
                )
                if name_ambiguous or description_ambiguous:
                    raise ValueError(f"ambiguous awaken text: {path}")
                modifiers = item.get("ModifyDataList", [])
                if not isinstance(modifiers, list) or len(modifiers) > MAX_TABLE_ROWS:
                    raise ValueError(f"ModifyDataList must be bounded: {path}")
                for modifier in modifiers:
                    if not isinstance(modifier, dict):
                        raise ValueError(f"invalid awaken modifier: {path}")
                    name = buff_name_from_reference(modifier.get("Buff"))
                    if not name:
                        continue
                    add_evidence(
                        evidence,
                        name,
                        PlayerBuffEvidence(
                            kind="character_awaken_modifier",
                            source=path.name,
                            display_name=display_name,
                            description=description,
                        ),
                    )
    return dict(evidence)


def merge_evidence(
    *sources: dict[str, list[PlayerBuffEvidence]],
) -> dict[str, list[PlayerBuffEvidence]]:
    merged: dict[str, list[PlayerBuffEvidence]] = defaultdict(list)
    for source in sources:
        for name, items in source.items():
            for item in items:
                add_evidence(merged, name, item)
    return dict(merged)


def select_text(
    current: str,
    current_quality: str,
    evidence: list[PlayerBuffEvidence],
    field: str,
) -> tuple[str, str]:
    candidates = [getattr(item, field) for item in evidence if getattr(item, field)]
    distinct = list(dict.fromkeys(candidates))
    if current_quality == "localized" and current:
        return current, current_quality
    if not distinct:
        return current, current_quality
    return distinct[0], "localized"


def build_document(enriched: Any, evidence: dict[str, list[PlayerBuffEvidence]], locale: str) -> dict[str, Any]:
    if not isinstance(enriched, dict) or not isinstance(enriched.get("entries"), list):
        raise ValueError("enriched catalog must contain entries")
    canonical_buffs: dict[str, dict[str, Any]] = {}
    for entry in enriched["entries"]:
        if not isinstance(entry, dict):
            raise ValueError("enriched entry must be an object")
        name = entry.get("name")
        if entry.get("kind") != "buff" or not isinstance(name, str) or name.lower().endswith("_c"):
            continue
        canonical_buffs[name] = entry

    missing = sorted(set(evidence) - set(canonical_buffs))
    if missing:
        raise ValueError(f"confirmed player Buffs missing from catalog: {missing[:10]}")

    entries: list[dict[str, Any]] = []
    reason_counts: Counter[str] = Counter()
    for name in sorted(evidence, key=lambda value: (canonical_buffs[value]["hash"], value)):
        source = canonical_buffs[name]
        items = evidence[name]
        display_name, display_quality = select_text(
            source["displayName"], source["displayNameQuality"], items, "display_name"
        )
        description, description_quality = select_text(
            source["description"], source["descriptionQuality"], items, "description"
        )
        reasons = []
        buff_types = []
        for item in items:
            reason_counts[item.kind] += 1
            reasons.append({"kind": item.kind, "source": item.source})
            if item.buff_type and item.buff_type not in buff_types:
                buff_types.append(item.buff_type)

        output = {
            "hash": source["hash"],
            "name": name,
            "references": source["references"],
            "displayName": display_name,
            "displayNameQuality": display_quality,
            "description": description,
            "descriptionQuality": description_quality,
            "playerRelevance": "confirmed",
            "relevanceEvidence": reasons,
        }
        for field in ("gameplayEffectIndex", "assetPath"):
            if field in source:
                output[field] = source[field]
        if buff_types:
            output["buffTypes"] = buff_types
        entries.append(output)

    return {
        "version": 1,
        "source": "effect_catalog_enriched.json",
        "locale": locale,
        "selectionPolicy": "confirmed_player_buff_only",
        "entryCount": len(entries),
        "evidenceCounts": dict(sorted(reason_counts.items())),
        "entries": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assets", type=Path, default=DEFAULT_ASSETS)
    parser.add_argument("--enriched-catalog", type=Path, default=DEFAULT_ENRICHED_CATALOG)
    parser.add_argument("--locale", default="zh-CN")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    localization = build_localization_index(
        read_json(args.assets / "Localization" / args.locale / "game.json")
    )
    effect_rows = load_rows(
        args.assets / "DataTable" / "Skill" / "Buffer" / "GameplayEffectTipsDataTable.json"
    )
    config_rows = load_rows(
        args.assets / "DataTable" / "Character" / "DT_CharacterAbilityEffectConfig.json"
    )
    ability_rows = load_rows(
        args.assets / "DataTable" / "Skill" / "DT_GameplayAbilityTipsData.json"
    )
    evidence = merge_evidence(
        collect_visible_buff_evidence(effect_rows, localization),
        collect_passive_buff_evidence(config_rows, ability_rows, localization),
        collect_awaken_buff_evidence(
            args.assets / "DataTable" / "Character" / "Awaken", localization
        ),
    )
    document = build_document(read_json(args.enriched_catalog), evidence, args.locale)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(
        f"entries={document['entryCount']} policy={document['selectionPolicy']} "
        f"output={args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
