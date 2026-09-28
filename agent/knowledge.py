"""
Knowledge base search and retrieval for LINA.
Provides keyword and semantic vector search using local Ollama embeddings (nomic-embed-text)
over structured lessons.jsonl.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional
import httpx

from config import DEFAULT_EMBEDDING_MODEL, KNOWLEDGE_DIR, OLLAMA_HOST


def cosine_similarity(v1: List[float], v2: List[float]) -> float:
    """Calculates cosine similarity between two numeric vectors."""
    if not v1 or not v2 or len(v1) != len(v2):
        return 0.0
    dot = sum(a * b for a, b in zip(v1, v2))
    norm1 = math.sqrt(sum(a * a for a in v1))
    norm2 = math.sqrt(sum(b * b for b in v2))
    if norm1 == 0.0 or norm2 == 0.0:
        return 0.0
    return dot / (norm1 * norm2)


class KnowledgeBase:
    def __init__(
        self,
        lessons_path: Optional[Path] = None,
        ollama_host: str = OLLAMA_HOST,
        embedding_model: str = DEFAULT_EMBEDDING_MODEL
    ):
        self.lessons_file = lessons_path or (KNOWLEDGE_DIR / "lessons.jsonl")
        self.ollama_host = ollama_host.rstrip("/")
        self.embedding_model = embedding_model

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

    def get_embedding(self, text: str) -> Optional[List[float]]:
        """Queries local Ollama for text embedding vector."""
        url = f"{self.ollama_host}/api/embeddings"
        payload = {
            "model": self.embedding_model,
            "prompt": text
        }
        try:
            with httpx.Client(trust_env=False, timeout=5.0) as client:
                res = client.post(url, json=payload)
                if res.status_code == 200:
                    return res.json().get("embedding")
        except Exception:
            pass
        return None

    def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Searches knowledge lessons. Attempts semantic embedding retrieval first;
        if embeddings fail or Ollama is offline, falls back to keyword matching.
        """
        lessons = self.load_lessons()
        if not lessons:
            return []

        # Try semantic search via Ollama embeddings (e.g. nomic-embed-text)
        query_vector = self.get_embedding(query)
        if query_vector:
            scored_lessons = []
            for item in lessons:
                text_to_embed = (
                    f"{item.get('category', '')}: {item.get('observations', '')} "
                    f"{item.get('reusable_lesson', '')} {item.get('explanation', '')}"
                )
                item_vector = self.get_embedding(text_to_embed)
                if item_vector:
                    score = cosine_similarity(query_vector, item_vector)
                    scored_lessons.append((score, item))

            if scored_lessons:
                scored_lessons.sort(key=lambda x: x[0], reverse=True)
                return [
                    {**item, "similarity_score": round(score, 3)}
                    for score, item in scored_lessons[:top_k]
                    if score > 0.3
                ]

        # Keyword search fallback
        query_lower = query.lower()
        results = []
        for item in lessons:
            searchable = (
                item.get("category", "") + " " +
                item.get("observations", "") + " " +
                item.get("reusable_lesson", "") + " " +
                item.get("explanation", "")
            ).lower()
            if query_lower in searchable:
                results.append(item)
        return results
