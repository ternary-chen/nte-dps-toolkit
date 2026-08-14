#!/usr/bin/env python3
from __future__ import annotations

import unittest

from build_player_buff_catalog import (
    PlayerBuffEvidence,
    buff_name_from_reference,
    merge_evidence,
    select_text,
)


class PlayerBuffCatalogTests(unittest.TestCase):
    def test_buff_name_from_reference_normalizes_class_suffix(self) -> None:
        self.assertEqual(
            buff_name_from_reference(
                {"AssetPathName": "/Game/Test/Buff_Player_Test.Buff_Player_Test_C"}
            ),
            "Buff_Player_Test",
        )

    def test_non_buff_reference_is_rejected(self) -> None:
        self.assertIsNone(
            buff_name_from_reference({"AssetPathName": "/Game/Test/GE_Test.GE_Test_C"})
        )

    def test_merge_evidence_deduplicates_identical_items(self) -> None:
        item = PlayerBuffEvidence("buff_manager_visible", "tips", "名称", "描述")
        merged = merge_evidence({"Buff_Test": [item]}, {"Buff_Test": [item]})
        self.assertEqual(merged, {"Buff_Test": [item]})

    def test_localized_current_text_wins(self) -> None:
        value, quality = select_text(
            "当前名称",
            "localized",
            [PlayerBuffEvidence("character_awaken_modifier", "test", "觉醒名称")],
            "display_name",
        )
        self.assertEqual((value, quality), ("当前名称", "localized"))

    def test_confirmed_evidence_replaces_technical_fallback(self) -> None:
        value, quality = select_text(
            "Buff_Test",
            "technical",
            [PlayerBuffEvidence("character_awaken_modifier", "test", "觉醒名称")],
            "display_name",
        )
        self.assertEqual((value, quality), ("觉醒名称", "localized"))


if __name__ == "__main__":
    unittest.main()
