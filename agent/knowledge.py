"""
Knowledge base search and retrieval for LINA.
Provides keyword and category search over structured lessons.jsonl.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
from config import KNOWLEDGE_DIR


class KnowledgeBase:
    def __init__(self, lessons_path: Optional[Path] = None):
        self.lessons_file = lessons_path or (KNOWLEDGE_DIR / "lessons.jsonl")

    def load_lessons(self) -> List[Dict[str, Any]]:
        lessons = []
        if not self.lessons_file.exists():
            return lessons

        with open(self.lessons_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        lessons.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return lessons

    def search(self, query: str) -> List[Dict[str, Any]]:
        """Searches lessons for query matches across category, observations, and lessons."""
        query_lower = query.lower()
        results = []
        for item in self.load_lessons():
            searchable = (
                item.get("category", "") + " " +
                item.get("observations", "") + " " +
                item.get("reusable_lesson", "") + " " +
                item.get("explanation", "")
            ).lower()
            if query_lower in searchable:
                results.append(item)
        return results
