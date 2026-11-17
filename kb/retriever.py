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
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

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


_STOP_WORDS: Set[str] = {
    "the", "and", "for", "with", "that", "this", "from", "are", "how", "what",
    "why", "can", "should", "using", "into", "when", "does", "not", "all",
    "use", "your", "you", "our", "have", "has", "been", "prevent", "avoid",
}


def _tokenize_terms(text: str) -> Set[str]:
    """Extracts lowercase alphanumeric domain tokens (ignoring short stop words)."""
    tokens = re.findall(r"[a-z0-9_]+", (text or "").lower())
    return {t for t in tokens if len(t) >= 3 and t not in _STOP_WORDS}


def _hybrid_rerank(query: str, candidates: List[Dict[str, Any]], k: int) -> List[Dict[str, Any]]:
    """
    Lightweight hybrid reranker combining dense cosine similarity (80%) with
    lexical token & source-title overlap (20%) to suppress cross-document noise
    and boost exact OWASP/CWE/topic matches.
    """
    if not candidates:
        return []
    q_terms = _tokenize_terms(query)
    if not q_terms:
        return candidates[:k]

    scored: List[tuple[float, Dict[str, Any]]] = []
    for item in candidates:
        dense = float(item.get("similarity_score", 0.0))
        src_terms = _tokenize_terms(item.get("source", "").replace("_", " ").replace(".", " "))
        doc_terms = _tokenize_terms(item.get("text", ""))
        text_overlap = len(q_terms & doc_terms) / len(q_terms)
        src_overlap = len(q_terms & src_terms) / len(q_terms)
        lexical_score = min(1.0, 0.50 * text_overlap + 1.15 * src_overlap)
        blended = min(1.0, round(0.72 * dense + 0.28 * lexical_score, 4))
        updated = dict(item)
        updated["similarity_score"] = max(dense, blended) if lexical_score > 0.25 else blended
        scored.append((blended, updated))

    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [item for _, item in scored[:k]]


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

        total_chunks = max(1, self.collection.count())
        fetch_k = min(max(k * 3, 10), total_chunks)
        query_params: Dict[str, Any] = {
            "query_embeddings": query_embedding,
            "n_results": fetch_k,
            "include": ["documents", "metadatas", "distances"]
        }
        if where_clause:
            query_params["where"] = where_clause

        raw_results = self.collection.query(**query_params)

        candidates: List[Dict[str, Any]] = []
        if not raw_results or not raw_results.get("documents"):
            return candidates

        docs = raw_results["documents"][0]
        metas = raw_results["metadatas"][0] if raw_results.get("metadatas") else [{}] * len(docs)
        distances = raw_results["distances"][0] if raw_results.get("distances") else [0.0] * len(docs)

        for doc, meta, dist in zip(docs, metas, distances):
            # For cosine distance (range 0.0 to 2.0), similarity = max(0.0, 1.0 - dist)
            similarity = max(0.0, min(1.0, 1.0 - float(dist)))
            candidates.append({
                "text": doc,
                "source": meta.get("source", "unknown"),
                "category": meta.get("category", "GENERAL"),
                "similarity_score": round(similarity, 4)
            })

        results = _hybrid_rerank(query, candidates, k=k)
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
