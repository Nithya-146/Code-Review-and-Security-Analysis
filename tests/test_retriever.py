"""
Unit tests for Knowledge Base Ingestion and Retriever Module.

Verifies:
1. Ingestion creates a populated ChromaDB collection.
2. Retriever search for SQL injection yields Injection (A05) chunks.
3. Filtering by OWASP category works properly.
4. Result structure adheres to expected schema (text, source, category, similarity_score).
"""

from pathlib import Path
import pytest
from kb.ingest import ingest, CHROMA_DB_DIR, COLLECTION_NAME, DOCS_DIR
from kb.retriever import Retriever


@pytest.fixture(scope="module")
def retriever_instance() -> Retriever:
    """Fixture providing a cached Retriever instance for tests."""
    # Ensure database is indexed before running retriever tests
    ingest(docs_dir=DOCS_DIR, chroma_dir=CHROMA_DB_DIR)
    return Retriever(chroma_dir=CHROMA_DB_DIR, collection_name=COLLECTION_NAME)


def test_collection_has_indexed_chunks(retriever_instance: Retriever):
    """Checks that the ChromaDB collection contains indexed chunks."""
    chunk_count = retriever_instance.collection.count()
    assert chunk_count > 0, f"Expected ChromaDB collection to contain chunks, got {chunk_count}"


def test_sql_injection_query_returns_injection_chunks(retriever_instance: Retriever):
    """
    Checks that a query for SQL injection retrieves Injection (A05) chunks with high relevance.
    """
    query = "how to prevent SQL injection in database queries"
    hits = retriever_instance.search(query=query, k=4)

    assert len(hits) > 0, "Expected at least 1 search hit for SQL injection query."

    # Top results should match OWASP Category A05 or contain SQL injection keywords
    top_hit = hits[0]
    top_categories = [h["category"] for h in hits]
    top_sources = [h["source"].lower() for h in hits]

    assert "A05" in top_categories or any("sql" in s or "injection" in s for s in top_sources), (
        f"Expected A05 category in top hits, got categories: {top_categories} and sources: {top_sources}"
    )

    # Verify score is reasonable (> 0.4 similarity)
    assert top_hit["similarity_score"] > 0.4, (
        f"Expected similarity score > 0.4 for SQL injection, got {top_hit['similarity_score']}"
    )


def test_hardcoded_secrets_query(retriever_instance: Retriever):
    """
    Checks that searching for hardcoded secrets retrieves A07 / secrets chunks.
    """
    query = "hardcoded secrets in Python and environment variables"
    hits = retriever_instance.search(query=query, k=3)

    assert len(hits) > 0
    top_categories = [h["category"] for h in hits]
    top_sources = [h["source"].lower() for h in hits]

    assert "A07" in top_categories or any("secret" in s or "auth" in s for s in top_sources)


def test_category_filtering(retriever_instance: Retriever):
    """
    Checks that specifying a category strictly filters returned results.
    """
    target_category = "A01"
    hits = retriever_instance.search(query="access control permission", k=3, category=target_category)

    assert len(hits) > 0
    for hit in hits:
        assert hit["category"] == target_category, (
            f"Expected only category '{target_category}', but found '{hit['category']}'"
        )


def test_result_structure_and_types(retriever_instance: Retriever):
    """
    Validates that returned result items have the required dictionary keys and value types.
    """
    hits = retriever_instance.search(query="input validation", k=2)
    assert len(hits) > 0

    for hit in hits:
        assert isinstance(hit, dict)
        assert "text" in hit and isinstance(hit["text"], str) and len(hit["text"]) > 0
        assert "source" in hit and isinstance(hit["source"], str) and len(hit["source"]) > 0
        assert "category" in hit and isinstance(hit["category"], str)
        assert "similarity_score" in hit and isinstance(hit["similarity_score"], (int, float))
        assert 0.0 <= hit["similarity_score"] <= 1.0
