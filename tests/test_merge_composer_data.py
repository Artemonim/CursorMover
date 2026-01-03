"""Unit tests for composer.composerData merge logic."""

from __future__ import annotations

import json
import unittest

from cursor_mover.merge import _merge_composer_data  # pylint: disable=protected-access


class MergeComposerDataTest(unittest.TestCase):
    def test_merge_unions_by_composer_id(self) -> None:
        dst = {
            "allComposers": [
                {"composerId": "a", "lastUpdatedAt": 10, "name": "A"},
                {"composerId": "b", "lastUpdatedAt": 5, "name": "B"},
            ],
            "selectedComposerIds": ["a"],
        }
        src = {
            "allComposers": [
                {"composerId": "b", "lastUpdatedAt": 7, "name": "B2"},
                {"composerId": "c", "lastUpdatedAt": 3, "name": "C"},
            ]
        }

        merged_raw = _merge_composer_data(
            json.dumps(dst).encode("utf-8"),
            [json.dumps(src).encode("utf-8")],
        )
        self.assertIsNotNone(merged_raw)
        merged = json.loads(merged_raw.decode("utf-8"))

        ids = [c["composerId"] for c in merged["allComposers"]]
        self.assertEqual(set(ids), {"a", "b", "c"})

        # * b should come from src (newer lastUpdatedAt).
        b_item = next(c for c in merged["allComposers"] if c["composerId"] == "b")
        self.assertEqual(b_item["name"], "B2")

