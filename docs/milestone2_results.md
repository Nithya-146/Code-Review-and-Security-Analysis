# Milestone 2: Multi-Agent Benchmark Evaluation Results

Evaluation results comparing detected findings from `CodeAnalysisAgent` and `SecurityAgent`
against ground-truth planted defects in `tests/answer_key.json`.

| Evaluation Segment | True Positives (TP) | False Positives (FP) | False Negatives (FN) | Precision | Recall | F1 Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| Python Quality | 6 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Python Security | 7 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Java Quality | 6 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Java Security | 7 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Python Total | 13 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Java Total | 13 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Overall Code Analysis | 12 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Overall Security Analysis | 14 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| **OVERALL SYSTEM** | 26 | 0 | 0 | 1.000 | 1.000 | **1.000** |

### Benchmark Observations
- **Clean and Safe Samples**: Zero false positives detected across `tricky_safe.py`, `clean_module.py`, `TrickySafe.java`, and `CleanService.java`.
- **Fault Tolerance**: Agent isolation guarantees uninterrupted pipeline flow even if one agent errors.
- **Target Threshold**: All evaluation segments exceed the required minimum F1 score threshold of 0.70.

---
*Generated automatically by tests/evaluate.py.*
