"""
Knowledge Base Retriever for AI Code Review & Security Analysis Agent.

Provides the Retriever class with vector similarity search over the persistent
ChromaDB knowledge base with optional category filtering and reusable single-instance
model/client caching.

Performance notes
-----------------
* HF_HUB_OFFLINE=1 is set here so that SentenceTransformer skips the network
  HEAD requests it normally makes on every load to check for model updates.
  The model weights are already cached locally after the first run; no download
  is needed and the round-trips add 10-17 seconds each time.
* The module-level _SINGLETON Retriever is created lazily on first use and then
  reused for the lifetime of the process (or Streamlit server).  Tests that need
  a fresh retriever should call retriever_singleton(reset=True).
* Evidence results are cached per rule-id in _EVIDENCE_CACHE inside SecurityAgent
  so the same KB query is never repeated within or across calls.
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

# Tell sentence-transformers / HuggingFace Hub to work fully offline.
# The model is already cached locally; these env vars suppress the ~10 network
# HEAD requests that add 10-17 seconds on every SentenceTransformer() call.
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

import chromadb
from sentence_transformers import SentenceTransformer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CHROMA_DB_DIR = PROJECT_ROOT / "kb" / "chroma_db"
COLLECTION_NAME = "owasp_security_rules"
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"

_MODEL_CACHE: Dict[str, SentenceTransformer] = {}
_CLIENT_CACHE: Dict[str, chromadb.PersistentClient] = {}

# ---------------------------------------------------------------------------
# Process-level lazy singleton — shared by SecurityAgent and the Streamlit UI
# ---------------------------------------------------------------------------
_SINGLETON: Optional["Retriever"] = None


def retriever_singleton(reset: bool = False) -> "Retriever":
    """
    Returns the process-level shared Retriever instance, creating it on first
    call.  Pass reset=True to force a fresh instance (useful in tests).
    """
    global _SINGLETON
    if reset or _SINGLETON is None:
        _SINGLETON = Retriever()
    return _SINGLETON


class Retriever:
    """
    Retriever class that loads the SentenceTransformer model and ChromaDB collection
    once for fast, reusable vector similarity search.
    """

    def __init__(
        self,
        chroma_dir: Optional[Path] = None,
        collection_name: str = COLLECTION_NAME,
        model_name: str = EMBEDDING_MODEL_NAME
    ) -> None:
        """
        Initializes the retriever, embedding model, and persistent ChromaDB collection.
        Reuses cached model and client instances to avoid redundant load overhead.
        """
        self.chroma_dir = chroma_dir or CHROMA_DB_DIR
        self.collection_name = collection_name
        self.model_name = model_name

        if self.model_name not in _MODEL_CACHE:
            logger.info("Loading SentenceTransformer model '%s'...", self.model_name)
            _MODEL_CACHE[self.model_name] = SentenceTransformer(self.model_name)
        self.model = _MODEL_CACHE[self.model_name]

        if not self.chroma_dir.exists():
            logger.warning("ChromaDB directory does not exist at %s. Please run kb.ingest first.",
                           self.chroma_dir)

        chroma_path_str = str(self.chroma_dir)
        if chroma_path_str not in _CLIENT_CACHE:
            _CLIENT_CACHE[chroma_path_str] = chromadb.PersistentClient(path=chroma_path_str)
        self.client = _CLIENT_CACHE[chroma_path_str]

        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"}
        )
        logger.info("Retriever initialized. Chunks available in collection: %d", self.collection.count())

    def search(
        self,
        query: str,
        k: int = 4,
        category: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Searches the knowledge base for chunks most relevant to the query.

        Args:
            query: The search query string.
            k: Number of top results to return.
            category: Optional OWASP category filter (e.g. 'A05', 'A01').

        Returns:
            List of result dicts containing:
                - text: chunk content
                - source: source file name
                - category: category identifier
                - similarity_score: float score between 0.0 and 1.0 (higher is more similar)
        """
        if not query.strip():
            logger.warning("Empty search query provided to Retriever.")
            return []

        query_embedding = self.model.encode([query]).tolist()

        where_clause: Optional[Dict[str, Any]] = None
        if category:
            where_clause = {"category": category}

        query_params: Dict[str, Any] = {
            "query_embeddings": query_embedding,
            "n_results": min(k, max(1, self.collection.count())),
            "include": ["documents", "metadatas", "distances"]
        }
        if where_clause:
            query_params["where"] = where_clause

        raw_results = self.collection.query(**query_params)

        results: List[Dict[str, Any]] = []
        if not raw_results or not raw_results.get("documents"):
            return results

        docs = raw_results["documents"][0]
        metas = raw_results["metadatas"][0] if raw_results.get("metadatas") else [{}] * len(docs)
        distances = raw_results["distances"][0] if raw_results.get("distances") else [0.0] * len(docs)

        for doc, meta, dist in zip(docs, metas, distances):
            # For cosine distance (range 0.0 to 2.0), similarity = max(0.0, 1.0 - dist)
            similarity = max(0.0, min(1.0, 1.0 - float(dist)))
            results.append({
                "text": doc,
                "source": meta.get("source", "unknown"),
                "category": meta.get("category", "GENERAL"),
                "similarity_score": round(similarity, 4)
            })

        logger.info("Query '%s' returned %d results (category filter=%s)", query, len(results), category)
        return results


def run_demo() -> None:
    """Runs a demo showcasing search across sample security queries."""
    sample_queries = [
        "how to prevent SQL injection",
        "hardcoded secrets in Python",
        "handling unhandled exceptions and leaking errors"
    ]

    retriever = Retriever()
    logger.info("Starting Retriever Demo with %d sample queries...", len(sample_queries))

    for query in sample_queries:
        logger.info("-" * 60)
        logger.info("Demo Query: '%s'", query)
        hits = retriever.search(query, k=2)
        for rank, hit in enumerate(hits, start=1):
            logger.info("Result #%d [Source: %s | Category: %s | Score: %.4f]:\n%s...\n",
                        rank, hit["source"], hit["category"], hit["similarity_score"],
                        hit["text"][:180].strip())


if __name__ == "__main__":
    run_demo()
