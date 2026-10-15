"""
AI Code Review & Security Analysis Agent - Milestone 1
Streamlit Application: Code Submission & AST Pre-Validation Module
"""

import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

import streamlit as st

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.python_parser import validate_python
from app.java_parser import validate_java
from app.schemas import ReviewReport

# Maximum allowed file size: 1 MB
MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024

# Page configuration
st.set_page_config(
    page_title="AI Code Review & Security Analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E293B;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #64748B;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        padding: 1rem;
        text-align: center;
    }
    .metric-val {
        font-size: 1.6rem;
        font-weight: 700;
        color: #0F172A;
    }
    .metric-label {
        font-size: 0.85rem;
        color: #64748B;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .status-badge-pass {
        background-color: #DCFCE7;
        color: #166534;
        font-weight: 600;
        padding: 4px 12px;
        border-radius: 9999px;
        display: inline-block;
    }
    .status-badge-fail {
        background-color: #FEE2E2;
        color: #991B1B;
        font-weight: 600;
        padding: 4px 12px;
        border-radius: 9999px;
        display: inline-block;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def get_kb_collection():
    """Caches direct ChromaDB collection connection for instant chunk counts."""
    import chromadb
    chroma_path = PROJECT_ROOT / "kb" / "chroma_db"
    client = chromadb.PersistentClient(path=str(chroma_path))
    return client.get_or_create_collection(name="owasp_security_rules")


def get_kb_chunk_count() -> int:
    """Reads count of indexed chunks in ChromaDB without loading embedding model."""
    try:
        col = get_kb_collection()
        return col.count()
    except Exception:
        return 0


@st.cache_resource
def get_retriever_instance():
    """Caches the Retriever instance across Streamlit reruns."""
    from kb.retriever import Retriever
    return Retriever()



# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.title("AI Code Review Agent")
    st.caption("Milestone 1 • AST Pre-Validation & RAG Store")

    st.markdown("---")
    st.markdown("### 📊 System Status")
    kb_count = get_kb_chunk_count()
    st.metric("Indexed KB Chunks", kb_count)
    st.write("**Supported Languages:** Python (`.py`), Java (`.java`)")
    st.write("**Max File Size:** 1 MB")
    st.write("**OWASP Standard:** Top 10:2025")

    st.markdown("---")
    if st.button("🔄 Reset Current Submission", use_container_width=True):
        for key in ["review_report", "current_code", "detected_lang", "submission_id"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    st.markdown("---")
    st.markdown(
        "<small style='color: #94A3B8;'>Antigravity AI Agent System • Milestone 1</small>",
        unsafe_allow_html=True
    )

# Main Navigation Tabs
tab_submission, tab_findings, tab_assistant = st.tabs([
    "📥 Code Submission",
    "🔍 Analysis Findings (Milestone 2)",
    "🤖 Security Assistant (Milestone 3)"
])

# ----------------- TAB 1: CODE SUBMISSION -----------------
with tab_submission:
    st.markdown("<div class='main-header'>Code Submission & AST Pre-Validation</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='sub-header'>Upload or paste source code for syntactic verification and AST structural extraction prior to security scanning.</div>",
        unsafe_allow_html=True
    )

    col_input, col_meta = st.columns([2, 1])

    # Choose Input Method
    input_mode = st.radio(
        "Submission Mode",
        ["Upload File", "Paste Code"],
        horizontal=True,
        label_visibility="collapsed"
    )

    uploaded_code: Optional[str] = None
    default_lang_index = 0  # 0 for Python, 1 for Java

    if input_mode == "Upload File":
        uploaded_file = st.file_uploader(
            "Upload a single source code file (.py or .java)",
            type=["py", "java"],
            help="Files larger than 1 MB will be rejected."
        )

        if uploaded_file is not None:
            # 1. Size Validation (1 MB limit)
            if uploaded_file.size > MAX_FILE_SIZE_BYTES:
                size_mb = uploaded_file.size / (1024 * 1024)
                st.error(f"❌ File size exceeds the 1 MB limit ({size_mb:.2f} MB). Please submit a smaller file.")
            else:
                # 2. Extension validation
                file_ext = Path(uploaded_file.name).suffix.lower()
                if file_ext == ".py":
                    default_lang_index = 0
                elif file_ext == ".java":
                    default_lang_index = 1
                else:
                    st.error(f"❌ Unsupported extension '{file_ext}'. Only .py and .java files are accepted.")

                # 3. Graceful UTF-8 decoding with fallback
                raw_bytes = uploaded_file.read()
                try:
                    uploaded_code = raw_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    try:
                        uploaded_code = raw_bytes.decode("latin-1")
                        st.warning("⚠️ File is not standard UTF-8 encoded; decoded using Latin-1 fallback.")
                    except Exception as decode_err:
                        st.error(f"❌ Failed to decode file content: {decode_err}")
                        uploaded_code = None

                if uploaded_code is not None:
                    st.info(f"📄 Loaded `{uploaded_file.name}` ({len(uploaded_code.splitlines())} lines, {uploaded_file.size} bytes)")
    else:
        pasted_text = st.text_area(
            "Paste Source Code:",
            height=280,
            placeholder="Paste your Python or Java code here...",
            key="pasted_code_area"
        )
        if pasted_text.strip():
            uploaded_code = pasted_text
            # Basic auto-detection heuristic for pasted snippet
            if "public class" in pasted_text or "System.out" in pasted_text or "import java." in pasted_text:
                default_lang_index = 1
            else:
                default_lang_index = 0

    # Language Selector
    language_choice = st.selectbox(
        "Target Language",
        ["Python", "Java"],
        index=default_lang_index,
        help="Defaults automatically from uploaded file extension."
    )
    lang_key = "python" if language_choice == "Python" else "java"

    # Preview Code
    if uploaded_code:
        with st.expander("👀 View Code Preview", expanded=False):
            st.code(uploaded_code, language=lang_key, line_numbers=True)

    # Validation Trigger Button
    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("🚀 Validate & Register Submission", type="primary", use_container_width=True):
        if not uploaded_code or not uploaded_code.strip():
            st.warning("⚠️ Submission is empty. Please upload a file or paste valid source code.")
        else:
            with st.spinner("Parsing AST and validating syntax..."):
                if lang_key == "python":
                    validation_result = validate_python(uploaded_code)
                else:
                    validation_result = validate_java(uploaded_code)

            if validation_result["is_valid"]:
                metadata = validation_result.get("metadata", {})
                submission_id = f"SUB-{uuid.uuid4().hex[:8].upper()}"

                # Instantiate and store Pydantic ReviewReport in session state
                report = ReviewReport(
                    submission_id=submission_id,
                    language=lang_key,
                    is_valid_syntax=True,
                    ast_metadata=metadata,
                    security_findings=[],
                    quality_findings=[],
                    remediations=[],
                    pr_summary_markdown=None
                )
                st.session_state["review_report"] = report.model_dump()
                st.session_state["current_code"] = uploaded_code
                st.session_state["submission_id"] = submission_id

                st.success("✅ Syntax Validation Passed! The submission has been verified and registered.")

                # Summary Metrics
                st.markdown("### 📋 Submission Summary")
                loc = metadata.get("lines_of_code", len(uploaded_code.splitlines()))
                functions = metadata.get("functions") or metadata.get("methods") or []
                classes = metadata.get("classes", [])
                imports = metadata.get("imports", [])

                m_col1, m_col2, m_col3, m_col4 = st.columns(4)
                with m_col1:
                    st.metric("Language", language_choice)
                with m_col2:
                    st.metric("Lines of Code", loc)
                with m_col3:
                    st.metric("Classes", len(classes))
                with m_col4:
                    st.metric("Functions / Methods", len(functions))

                # Structural Elements
                detail_col1, detail_col2 = st.columns(2)
                with detail_col1:
                    st.write("**Declared Functions / Methods:**")
                    if functions:
                        st.write(", ".join([f"`{f}`" for f in functions]))
                    else:
                        st.caption("No top-level functions or methods declared.")

                    st.write("**Declared Classes:**")
                    if classes:
                        st.write(", ".join([f"`{c}`" for c in classes]))
                    else:
                        st.caption("No classes declared.")

                with detail_col2:
                    st.write("**Detected Imports:**")
                    if imports:
                        st.write(", ".join([f"`{i}`" for i in imports]))
                    else:
                        st.caption("No external imports detected.")

                st.info(f"💾 Submission registered under ID `{submission_id}` in `st.session_state` and ready for the Milestone 2 agent pipeline.")

            else:
                st.error("❌ AST Validation Failed: Syntax Error Detected")
                error_msg = validation_result.get("error", "Unknown syntax error")
                st.error(error_msg)
                st.warning("Please correct the syntax errors before submitting to downstream security analyzers.")


# ----------------- TAB 2: FINDINGS PLACEHOLDER -----------------
with tab_findings:
    st.markdown("<div class='main-header'>Analysis Findings (Milestone 2)</div>", unsafe_allow_html=True)
    st.info("ℹ️ **Milestone 2 Pipeline Placeholder**: Security Analyzer, Code Smell Analyzer, and Fix Remediation Agents will populate this tab.")

    if "review_report" in st.session_state:
        rep = st.session_state["review_report"]
        st.markdown(f"**Current Registered Submission:** `{rep['submission_id']}` ({rep['language'].upper()})")
        st.json(rep)
    else:
        st.caption("No active submission currently in session. Validate code in the 'Code Submission' tab first.")


# ----------------- TAB 3: ASSISTANT PLACEHOLDER -----------------
with tab_assistant:
    st.markdown("<div class='main-header'>Interactive Security Assistant (Milestone 3)</div>", unsafe_allow_html=True)
    st.info("ℹ️ **Milestone 3 RAG Assistant Placeholder**: Interactive conversational Q&A grounded in the OWASP Top 10:2025 Knowledge Base will be implemented here.")

    st.markdown("#### 🧪 Test Knowledge Base Retrieval:")
    test_q = st.text_input("Enter a query to test the ChromaDB knowledge base:", "how to prevent SQL injection")
    if st.button("Search Knowledge Base"):
        try:
            r = get_retriever_instance()
            results = r.search(test_q, k=3)
            for idx, res in enumerate(results, start=1):
                st.markdown(f"**Hit #{idx}** — Source: `{res['source']}` | Category: `{res['category']}` | Score: `{res['similarity_score']:.4f}`")
                st.text(res["text"][:300] + "...")
                st.markdown("---")
        except Exception as e:
            st.error(f"Retriever error: {e}")
