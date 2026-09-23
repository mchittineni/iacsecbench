# IaCSecBench — Replication Package Guide

[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.21645016-purple.svg)](https://doi.org/10.5281/zenodo.21645016)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](pyproject.toml)

This document provides complete instructions for replicating all empirical results, statistical tests, LaTeX tables, and diagrams presented in the manuscript:

> **IaCSecBench: A Finding-Normalization Methodology and Reproducible Harness for Evaluating Infrastructure-as-Code Security Validation**  
> *Target Venue:* Empirical Software Engineering (Springer)  
> *Author:* Manideep Chittineni (ORCID: [0009-0003-9709-5842](https://orcid.org/0009-0003-9709-5842))  
> *Permanent Archive:* [https://doi.org/10.5281/zenodo.21645016](https://doi.org/10.5281/zenodo.21645016)

---

## 1. System Requirements & Environment

### Hardware
- Any standard x86_64 or ARM64 (Apple Silicon) system.
- Minimum 4 GB RAM and 2 GB free disk space.

### Software Prerequisites
- **Python**: `>= 3.11` (tested on Python 3.11, 3.12, 3.13, 3.14)
- **Terraform CLI**: `>= 1.5.0` (tested on 1.15.x)
- **LaTeX Engine (optional, for manuscript compilation)**: `tectonic` (recommended) or TeX Live (`pdflatex` + `bibtex`)
- **Comparative Static Scanners (for re-executing raw scans)**:
  - Checkov (`>= 3.3.0`)
  - tfsec (`>= v1.28.0`)
  - Trivy (`>= 0.50.0`)
  - Open Policy Agent (OPA) (`>= 1.0.0`)

> [!NOTE]
> All raw per-case tool execution outputs are recorded under `results/raw/`. You can reproduce all empirical tables, statistical tests, and diagrams **immediately without installing the third-party scanner binaries**.

---

## 2. Installation & Setup

Clone the repository and set up a virtual environment:

```bash
git clone https://github.com/mchittineni/iacsecbench.git
cd iacsecbench

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install editable package and dependencies
pip install -e '.[dev]'
```

Verify the environment and run the test suite:

```bash
pytest -v
```
All 137 tests across `evaluation/tests` and `security_framework/tests` should pass in less than a second.

---

## 3. Reproducing Results

### Fast Reproduction: Regenerate All Tables and Figures from Recorded Scans
To compute all confusion matrices, exact Clopper–Pearson confidence intervals, exact McNemar tests with Holm–Bonferroni corrections, and emit all LaTeX tables:

```bash
python -m evaluation.analyze --level control
```

To re-run the mechanical corpus admissibility gate across all 56 cases:

```bash
# Structural check (instant)
python -m evaluation.corpus --report --mode structural

# Full Terraform init + validate check (uses hermetic offline mirror)
python -m evaluation.corpus --report --mode terraform --latex --json results/corpus_report.json
```

To regenerate the paper figures from `results/evaluation.json` and `results/run_manifest.json`:

```bash
python experiments/generate_figures.py
```

### Full Re-execution: End-to-End Baseline Measurement
To execute all installed scanners against the corpus over 3 repetitions, record fresh telemetry, and regenerate the entire results suite:

```bash
bash experiments/run_baselines.sh
```

---

## 4. Mapping: Manuscript Results to Code and Data

Every results table in the manuscript is a generated artifact in `results/tables/`; only the replication map and the STRIDE summary are written by hand.

| Manuscript Element | Description | Emitted By | Source Telemetry / Input | Output Artifact |
| :--- | :--- | :--- | :--- | :--- |
| **Table 1 (`tab:admissibility`)** | Declared, present and admissible cases per collection | `evaluation/corpus.py` | `benchmark/`, `results/corpus_report.json` | `results/tables/corpus.tex` |
| **Table 2 (`tab:strictness`)** | Recall under the control, resource and any criteria, with the control-to-any spread (resource over cases naming an address) | `evaluation/analyze.py` | `results/raw/` | `results/tables/strictness.tex` |
| **Table 3 (`tab:performance`)** | Confusion-matrix counts and MCC at the control criterion | `evaluation/analyze.py` | `results/raw/`, `results/run_manifest.json` | `results/tables/performance.tex` |
| **Table 4 (`tab:rates`)** | Control-level true positive rate and specificity with exact intervals | `evaluation/analyze.py` | `results/raw/` | `results/tables/rates.tex` |
| **Table 5 (`tab:mcnemar`)** | Exact McNemar test against plan-level reference ($d_{\min}$, $p$-value, odds ratio) | `evaluation/stats.py` | `results/evaluation.json` | `results/tables/mcnemar.tex` |
| **Table 6 (`tab:allpairs`)** | All-pairs comparison matrix under Holm–Bonferroni correction | `evaluation/stats.py` | `results/evaluation.json` | `results/tables/allpairs.tex` |
| **Table 7 (`tab:latency`)** | Per-case execution latency, mean ± SD over 3 repetitions | `evaluation/analyze.py` | `results/run_manifest.json` | `results/tables/latency.tex` |
| **Table 8 (`tab:layers`)** | Detections by scored layer (L1, L3), their overlap and union | `evaluation/analyze.py` | `results/raw/` | `results/tables/layers.tex` |
| **Table 9 (`tab:external`)** | Alerts on the 25 unlabelled third-party repositories (no recall) | `evaluation/external.py` | `results/raw/external/`, `benchmark/external/aws_samples/manifest.json` | `results/tables/external.tex` |
| **Table 10 (`tab:external-agreement`)** | Pairwise Jaccard agreement on the unlabelled subset | `evaluation/external.py` | `results/external_subset.json` | `results/tables/external_agreement.tex` |
| **Figure 1 (`fig:pipeline`)** | Three-layer security validation architecture | `experiments/generate_figures.py` | `results/run_manifest.json` | `paper/figures/pipeline_architecture.pdf` |
| **Figure 2 (`fig:normalization`)** | Finding normalization and matching workflow | `experiments/generate_figures.py` | `results/evaluation.json` | `paper/figures/normalization_workflow.pdf` |

---

## 5. Compiling the Manuscript

The manuscript resides in `paper/iacsecbench.tex`. Build automation ensures that `make` will fail if any generated table is absent.

```bash
cd paper

# Verify compliance (abstract length, author TODOs, citations)
make check

# Compile the paper PDF
make paper

# Assemble and verify the self-contained submission bundle
make dist
```

The resulting `paper/iacsecbench-submission.tar.gz` is a flat, standalone bundle (no subfolders, as EMSE requires) that `make dist` has already compiled in isolation.

---

## 6. Offline Execution & Provider Mirroring

To guarantee hermetic, offline execution without flaky registry downloads or concurrent cache corruption:
- A local filesystem mirror is cached under `.terraform-provider-mirror/`.
- `evaluation/tfenv.py` coordinates concurrency-safe provider initialization through an exclusive file lock (`.terraform-provider-mirror.lock`).
- When offline or running in sandboxed CI, `terraform init` resolves required providers from the mirror using `-plugin-dir`.

---

## 7. Consistency Audit & Labelling Reproducibility

Section 4.3 of the manuscript evaluates ground-truth labelling consistency through an automated audit ($n=48, \kappa=0.958$):
- **Second labeller:** a large language model. Its identity and version, access route, decoding parameters and exact instruction were **not recorded**, so this pass cannot be re-run as it was run; κ can be recomputed from the recorded labels but not re-obtained.
- **Recorded:** the blinding procedure and every per-case label and reason, in [`benchmark/labelling/independent_relabelling.json`](benchmark/labelling/independent_relabelling.json). See [`benchmark/labelling/README.md`](benchmark/labelling/README.md) for the limitations.
