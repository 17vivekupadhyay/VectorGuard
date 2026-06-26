"""Local RAG utilities: chunking and keyword retrieval."""

from __future__ import annotations

from vectorguard.rag import RagChunk, chunk_text, retrieve_chunks


def test_short_text_is_single_chunk():
    chunks = chunk_text("just a few words", chunk_size_words=160, overlap_words=30)
    assert len(chunks) == 1


def test_long_text_is_split_with_overlap():
    text = " ".join(f"word{i}" for i in range(400))
    chunks = chunk_text(text, chunk_size_words=160, overlap_words=30)
    assert len(chunks) > 1


def test_retrieve_ranks_relevant_chunk_first():
    chunks = [
        RagChunk(chunk_id="c1", source_path="clean.txt", text="the vacation policy allows ten days", label="clean"),
        RagChunk(chunk_id="c2", source_path="other.txt", text="completely unrelated cooking recipe", label="clean"),
    ]
    hits = retrieve_chunks(query="what is the vacation policy", chunks=chunks, top_k=1)
    assert len(hits) == 1
    assert hits[0].chunk_id == "c1"


def test_retrieve_respects_top_k():
    chunks = [
        RagChunk(chunk_id=f"c{i}", source_path="d.txt", text=f"vacation policy text {i}", label="clean")
        for i in range(5)
    ]
    hits = retrieve_chunks(query="vacation policy", chunks=chunks, top_k=2)
    assert len(hits) == 2
