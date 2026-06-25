"""
RAG knowledge layer for the VectorGuard Web Agent.

Retrieves relevant OWASP / PortSwigger guidance from a local corpus to ground the
agent's reasoning and remediation text. It reuses the core RAG pipeline
(``vectorguard.rag``: load -> chunk -> keyword retrieve), so it adds no new
dependencies.

This is retrieval only. Retrieved guidance is treated as untrusted reference
text: it informs explanations and remediation, and is never executed or turned
into an action.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from ...rag import chunk_documents, load_documents, retrieve_chunks

KNOWLEDGE_DIR = Path(__file__).resolve().parent / "knowledge"


@lru_cache(maxsize=8)
def _load_chunks(knowledge_dir: str) -> tuple[Any, ...]:
    """Load and chunk the corpus once per directory (cached)."""
    documents = load_documents(knowledge_dir)
    chunks = chunk_documents(documents, chunk_size_words=120, overlap_words=20)
    return tuple(chunks)


def retrieve_guidance(
    query: str,
    *,
    top_k: int = 3,
    knowledge_dir: str | Path = KNOWLEDGE_DIR,
) -> list[dict[str, Any]]:
    """
    Retrieve the most relevant guidance chunks for a query.

    Returns a list of ``{source, chunk_id, score, text}`` dicts, dropping
    zero-overlap matches. Empty when nothing relevant is found.
    """
    chunks = list(_load_chunks(str(knowledge_dir)))
    hits = retrieve_chunks(query=query, chunks=chunks, top_k=top_k)

    return [
        {
            "source": Path(hit.source_path).name,
            "chunk_id": hit.chunk_id,
            "score": hit.score,
            "text": hit.text,
        }
        for hit in hits
        if hit.score > 0
    ]


def build_guidance_block(guidance: list[dict[str, Any]]) -> str:
    """Format retrieved guidance into a prompt-ready, cited text block."""
    if not guidance:
        return "No relevant guidance retrieved."

    return "\n\n".join(f"[{item['source']}] {item['text']}" for item in guidance)
