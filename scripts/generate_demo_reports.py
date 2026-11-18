"""
Regenerate Demo PDF Code Review Reports (Milestone 4, Step 3).

Runs the existing multi-agent orchestrator and ReportLab PDF report generator
on the three canonical demo samples:
  1. tests/samples/py_small.py      (Simple — Python)
  2. tests/samples/py_medium.py     (Moderate — Python)
  3. tests/samples/JavaComplex.java (Complex — Java)

Writes PDF outputs to docs/demo_outputs/ using app.report_generator.generate_report.

Usage:
    python scripts/generate_demo_reports.py
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import List, Tuple

# Ensure offline SentenceTransformer cache usage before importing agents/retriever
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pypdf import PdfReader  # noqa: E402

from agents.orchestrator import analyze  # noqa: E402
from app.report_generator import generate_report  # noqa: E402

DEMO_SAMPLES: List[Tuple[str, str, str]] = [
    ("tests/samples/py_small.py", "python", "review_py_small.pdf"),
    ("tests/samples/py_medium.py", "python", "review_py_medium.pdf"),
    ("tests/samples/JavaComplex.java", "java", "review_JavaComplex.pdf"),
]


def generate_demo_reports(output_dir: Path) -> None:
    """Runs the full pipeline and writes PDF reports for the three demo samples."""
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating {len(DEMO_SAMPLES)} demo PDF reports into: {output_dir}\n")
    for rel_path, language, out_name in DEMO_SAMPLES:
        sample_path = PROJECT_ROOT / rel_path
        if not sample_path.exists():
            raise FileNotFoundError(f"Demo sample not found: {sample_path}")

        source_code = sample_path.read_text(encoding="utf-8")
        result = analyze(
            code=source_code,
            language=language,
            filename=sample_path.name,
        )

        pdf_bytes = generate_report(
            result=result,
            source_code=source_code,
            filename=sample_path.name,
            language=language,
        )
        if not pdf_bytes.startswith(b"%PDF"):
            raise ValueError(f"Generated output for {sample_path.name} is not a valid PDF.")

        out_path = output_dir / out_name
        out_path.write_bytes(pdf_bytes)

        reader = PdfReader(str(out_path))
        hs = result.health_score
        score_str = f"{hs.score}/100 (Grade {hs.grade})" if hs else "N/A"
        verified_cnt = sum(1 for r in result.remediations if r.verified)
        sev = result.counts_by_severity

        print(f"Sample: {sample_path.name} ({language}, {len(source_code.splitlines())} lines)")
        print(f"  Output:       {out_path.relative_to(PROJECT_ROOT)} ({len(pdf_bytes):,} bytes, {len(reader.pages)} pages)")
        print(f"  Health Score: {score_str}")
        print(
            f"  Findings:     {len(result.findings)} total "
            f"(CRITICAL={sev.get('CRITICAL', 0)}, HIGH={sev.get('HIGH', 0)}, "
            f"MEDIUM={sev.get('MEDIUM', 0)}, LOW={sev.get('LOW', 0)}, INFO={sev.get('INFO', 0)})"
        )
        print(f"  Remediations: {verified_cnt}/{len(result.remediations)} two-tier verified")
        for f in result.findings:
            print(f"    - [{f.id}] {f.severity.value:8s} ({f.severity_score:.1f}) L{f.line_start}-L{f.line_end} {f.title}")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate demo PDF code review reports.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT_ROOT / "docs" / "demo_outputs",
        help="Directory where generated demo PDF reports are written.",
    )
    args = parser.parse_args()
    generate_demo_reports(args.output_dir)


if __name__ == "__main__":
    main()
