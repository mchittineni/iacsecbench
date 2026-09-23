# IaCSecBench — Workspace Coding & Quality Rules

## 1. Code Formatting & Style Standards

- **Python (`evaluation/`, `benchmark/`, `security_framework/`, `scripts/`, `experiments/`)**:
  - Python 3.11+ compliance following PEP 8.
  - Line length: 100 characters max (`ruff` and `pyproject.toml`).
  - 4-space indentation.
  - Functions and classes must include clear docstrings.
  - Scripts intended for execution must include `if __name__ == "__main__":` entry points.
  - Linting: code must pass `ruff check .` and adhere to `.pre-commit-config.yaml`.
- **Terraform & HCL (`infrastructure/`, `benchmark/internal/cases/`)**:
  - Canonical formatting enforced with `terraform fmt -check`.
  - All test configurations must pass `terraform validate` (or structural admissibility gate `python -m evaluation.corpus --mode structural`).
  - Native tests defined using `.tftest.hcl` format.
- **LaTeX & Publication Artifacts (`paper/`)**:
  - Strict compliance with the EMSE (Springer) submission guidelines; `make -C paper dist` must produce a flat bundle.
  - Abstract must stay strictly within 150–250 words (`make -C paper check`).
  - All numbers, confusion matrices, and tables must be generated artifacts in `results/tables/`.
  - Zero unresolved author `TODO` markers.

## 2. Security, Privacy & Secret Sanitization

- **Zero-Secret Rule**: NEVER commit real cloud API keys, secrets, private keys, or credentials.
- Test cases requiring secret patterns must use synthetic, non-functional dummy tokens (e.g. `AKIAIOSFODNN7EXAMPLE`).
- Layer 1 secret and pattern detectors must validate cleanly without flagging false positives in codebase tooling.

## 3. Empirical & Benchmark Integrity

- **No Synthetic Result Fabrication**: Results must derive strictly from real scanner executions recorded in `results/raw/` or live execution.
- Any scanner not installed must be reported as `not_run`, never assigned an assumed detection rate.
- Control mappings in `evaluation/control_map.json` must be grounded in verified native rule identifiers.

## 4. Testing & Validation Workflow

- Before committing or completing any task:
  1. Run `.venv/bin/pytest -v` (All 137 tests across `evaluation/tests/` and `security_framework/tests/` MUST pass).
  2. Run `.venv/bin/python -m evaluation.corpus --report --mode structural` (Must confirm 56 admissible cases, 0 inadmissible).
  3. Run `make -C paper check` (Must report 0 unresolved author TODOs, abstract in range, 0 missing citations).
  4. Run `.venv/bin/ruff check .` (Must pass without linting errors).
