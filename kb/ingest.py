"""
Knowledge Base Ingestion Pipeline for AI Code Review & Security Analysis Agent.

Loads documentation from kb/docs/ (.md, .txt, .pdf), chunks the documents,
embeds them with sentence-transformers (all-MiniLM-L6-v2), and idempotently
stores vectors and metadata in a persistent ChromaDB collection.
"""

import hashlib
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import chromadb
from langchain_text_splitters import RecursiveCharacterTextSplitter
from pypdf import PdfReader
from sentence_transformers import SentenceTransformer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Relative paths using pathlib
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = PROJECT_ROOT / "kb" / "docs"
CHROMA_DB_DIR = PROJECT_ROOT / "kb" / "chroma_db"
COLLECTION_NAME = "owasp_security_rules"
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"

# Map file prefixes / keywords to standard OWASP Category IDs
OWASP_CATEGORY_MAP: Dict[str, str] = {
    "A01": "A01: Broken Access Control",
    "A02": "A02: Security Misconfiguration",
    "A03": "A03: Software Supply Chain Failures",
    "A04": "A04: Cryptographic Failures",
    "A05": "A05: Injection",
    "A06": "A06: Insecure Design",
    "A07": "A07: Authentication Failures",
    "A08": "A08: Software or Data Integrity Failures",
    "A09": "A09: Security Logging and Alerting Failures",
    "A10": "A10: Mishandling of Exceptional Conditions",
}


def infer_category(filename: str) -> str:
    """
    Infers the OWASP or topic category from the filename.
    """
    match = re.match(r"^(A\d{2})", filename, re.IGNORECASE)
    if match:
        cat_key = match.group(1).upper()
        if cat_key in OWASP_CATEGORY_MAP:
            return cat_key

    lower = filename.lower()
    if "sqli" in lower or "injection" in lower:
        return "A05"
    if "secret" in lower or "auth" in lower:
        return "A07"
    if "crypto" in lower:
        return "A04"
    if "smell" in lower or "clean" in lower:
        return "CODE_QUALITY"
    return "GENERAL"


def load_file_content(file_path: Path) -> str:
    """
    Extracts text content from .md, .txt, or .pdf files.
    """
    suffix = file_path.suffix.lower()
    if suffix in [".md", ".txt"]:
        try:
            return file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            logger.warning("UTF-8 decoding failed for %s, trying latin-1", file_path.name)
            return file_path.read_text(encoding="latin-1")
    elif suffix == ".pdf":
        try:
            reader = PdfReader(str(file_path))
            pages_text = [page.extract_text() or "" for page in reader.pages]
            return "\n".join(pages_text)
        except Exception as err:
            logger.error("Error reading PDF %s: %s", file_path.name, err)
            return ""
    else:
        logger.debug("Skipping unsupported file extension: %s", file_path.name)
        return ""


def load_documents(docs_dir: Path) -> List[Dict[str, Any]]:
    """
    Loads all supported files from docs_dir.
    """
    if not docs_dir.exists():
        logger.error("Documents directory does not exist: %s", docs_dir)
        return []

    documents: List[Dict[str, Any]] = []
    supported_patterns = ["*.md", "*.txt", "*.pdf"]

    for pattern in supported_patterns:
        for file_path in docs_dir.glob(pattern):
            if file_path.is_file():
                content = load_file_content(file_path)
                if content.strip():
                    documents.append({
                        "filename": file_path.name,
                        "file_path": str(file_path),
                        "content": content,
                        "category": infer_category(file_path.name)
                    })
                    logger.info("Loaded '%s' (%d characters, Category: %s)",
                                file_path.name, len(content), infer_category(file_path.name))
                else:
                    logger.warning("Empty content in file: %s", file_path.name)

    return documents


def build_chunks(
    documents: List[Dict[str, Any]],
    chunk_size: int = 800,
    chunk_overlap: int = 100
) -> Tuple[List[str], List[Dict[str, Any]], List[str]]:
    """
    Splits document texts into chunks and assigns deterministic IDs and metadata.
    """
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        separators=["\n## ", "\n### ", "\n\n", "\n", " ", ""]
    )

    chunk_texts: List[str] = []
    chunk_metadatas: List[Dict[str, Any]] = []
    chunk_ids: List[str] = []

    for doc in documents:
        filename = doc["filename"]
        category = doc["category"]
        text_chunks = splitter.split_text(doc["content"])

        for idx, chunk in enumerate(text_chunks):
            # Deterministic ID using file stem, chunk index, and sha256 prefix
            hash_suffix = hashlib.sha256(chunk.encode("utf-8")).hexdigest()[:8]
            clean_stem = re.sub(r"[^a-zA-Z0-9_-]", "_", Path(filename).stem)
            deterministic_id = f"{clean_stem}_{idx}_{hash_suffix}"

            chunk_texts.append(chunk)
            chunk_metadatas.append({
                "source": filename,
                "category": category,
                "chunk_index": idx,
                "char_length": len(chunk)
            })
            chunk_ids.append(deterministic_id)

    return chunk_texts, chunk_metadatas, chunk_ids


def ingest(
    docs_dir: Optional[Path] = None,
    chroma_dir: Optional[Path] = None,
    collection_name: str = COLLECTION_NAME
) -> int:
    """
    Executes the ingestion pipeline. Returns total chunks indexed.
    """
    target_docs_dir = docs_dir or DOCS_DIR
    target_chroma_dir = chroma_dir or CHROMA_DB_DIR

    logger.info("Starting knowledge base ingestion from %s", target_docs_dir)
    documents = load_documents(target_docs_dir)
    if not documents:
        logger.warning("No documents loaded. Aborting ingestion.")
        return 0

    chunk_texts, chunk_metadatas, chunk_ids = build_chunks(documents)
    logger.info("Generated %d total chunks across %d documents", len(chunk_texts), len(documents))

    logger.info("Loading embedding model: %s", EMBEDDING_MODEL_NAME)
    model = SentenceTransformer(EMBEDDING_MODEL_NAME)

    logger.info("Encoding %d chunks into embeddings...", len(chunk_texts))
    embeddings = model.encode(chunk_texts, batch_size=32, show_progress_bar=False).tolist()

    target_chroma_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Connecting to ChromaDB at %s", target_chroma_dir)
    client = chromadb.PersistentClient(path=str(target_chroma_dir))

    collection = client.get_or_create_collection(
        name=collection_name,
        metadata={"hnsw:space": "cosine"}
    )

    # Upsert ensures idempotency: re-running does not produce duplicate chunks
    batch_size = 100
    for i in range(0, len(chunk_ids), batch_size):
        end_idx = min(i + batch_size, len(chunk_ids))
        collection.upsert(
            ids=chunk_ids[i:end_idx],
            documents=chunk_texts[i:end_idx],
            metadatas=chunk_metadatas[i:end_idx],
            embeddings=embeddings[i:end_idx]
        )
        logger.info("Upserted chunks %d - %d into collection '%s'", i + 1, end_idx, collection_name)

    total_chunks = collection.count()
    logger.info("Ingestion completed successfully! Total chunks currently in collection: %d", total_chunks)
    return total_chunks


if __name__ == "__main__":
    ingest()
