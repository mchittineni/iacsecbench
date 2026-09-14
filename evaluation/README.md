# 🧪 Evaluation Directory — Scoring Protocol & Baseline Evaluation Suite (`evaluation/`)

## 📋 Directory Overview

The `evaluation/` directory contains the evaluation protocol, statistical analysis tools, normalization engines, and baseline execution tools responsible for calculating precision, recall, F1 scores, latency metrics, zero-PII compliance, and generating leaderboard outputs for IaC scanners.

---

## 📁 Directory Structure & Key Files

```text
evaluation/
├── score.py               # Evaluation Protocol & Synthetic Leaderboard Guard Engine
├── run_baselines.py       # Baseline Evaluation Runner across IaC scanners
├── analyze.py             # Evaluation Analysis & Metric Summary Aggregator (CLI entry point)
├── tables.py              # LaTeX table emitters + the generated-table structural guard
├── metrics.py             # Metric dataclass for the deprecated score.py path only
├── corpus.py              # Infrastructure Corpus Analysis & Categorization
├── stats.py               # Statistical Significance & Confidence Interval Calculator
├── normalize.py           # Finding Normalization Engine & Canonical Schema Mapper
├── control_map.json       # Mapping between CIS AWS controls & benchmark test cases
├── paired_verification.py # Optional vulnerable-to-compliant transition verification
├── paired_verification_map.json # Reviewed exact-property mappings
└── tests/                 # Unit Tests for Evaluation Protocol & Baseline Tools
```

---

## ⚙️ Key Components & Workflows

### 1. Baseline Evaluation Suite (`run_baselines.py` & `experiments/run_baselines.sh`)

- Executes evaluations against Checkov, tfsec, Trivy, plan-level OPA, and the repository-edge IaCSecBench layer.
  Note that Trivy is tfsec's maintained successor and inherits its rule set, so the five columns represent
  **four** distinct rule sets, of which only **two** are independent _third-party_ ones: Checkov's and the
  tfsec/Trivy lineage. Plan-level OPA and the repository-edge layer are this project's own. The manuscript
  reports the two-third-party figure, and that is the number any comparative claim rests on. Sentinel and Terratest are _not_ evaluated; an earlier version of
  this file listed them, and no measurement against either has ever been recorded.
- Measures detection counts with exact Clopper-Pearson intervals, and per-case scan latency (ms) over repeats.
- A tool that is not installed is reported as absent and omitted from every table. It is never assigned an
  assumed detection rate.

### 2. Statistical Implementation (`stats.py`)

Pure standard library, so the replication package runs on a bare interpreter. Every
method is exact or explicitly labelled an approximation, and each is pinned by a
test to independently derived values rather than to its own output.

- Exact **Clopper-Pearson** intervals for recall, precision and specificity. Chosen
  for the coverage guarantee, not for width: coverage is never below nominal,
  whereas score and adjusted-Wald intervals undercover near the boundary, which is
  where most of these estimates sit. `wilson` is also provided so a reader who
  prefers the score interval can obtain it.
- The **exact binomial McNemar** test, used in preference to the chi-square
  approximation, which the module flags invalid when a discordant cell is small.
- `minimum_detectable_discordance` — the smallest $|b-c|$ the exact test could have
  called significant at a given discordant count, or `None` when no split could.
  This distinguishes "the tools are similar" from "the comparison had no power":
  at five or fewer discordant pairs the smallest attainable two-sided $p$ is
  0.0625, so no outcome can reject. Both McNemar tables carry it as a $d_{\min}$
  column.
- **Holm-Bonferroni** correction, Haldane-Anscombe-corrected odds ratios so a zero
  cell stays finite, Cohen's $g$, and MCC.

### 2a. Deprecated Scoring Path (`score.py`, `metrics.py`)

- `score.py` derives leaderboard metrics from hardcoded per-tool rates rather than
  from measurement, and `metrics.py` is the metric implementation it uses. Both are
  retained only so the gated path keeps working; **prefer `stats.py` and
  `analyze.py` for anything reported.**
- Running `score.py` requires `IACSECBENCH_ALLOW_SYNTHETIC=1`. CI asserts that it
  **refuses** without the opt-in, so the guard cannot rot unnoticed.

### 3. Finding Normalization Engine (`normalize.py`)

- Maps heterogeneous scanner output formats (SARIF, JSON, custom CLI text) into a canonical security finding taxonomy:
  $$\mathcal{F} = \langle \text{Case\_ID}, \text{Domain}, \text{Severity}, \text{Resource\_URN}, \text{Status} \rangle$$

### 4. Unlabelled External Subset (`external.py`)

Measures the three source-level scanners over the 25 third-party repositories
pinned in `benchmark/external/aws_samples/manifest.json`.

**These repositories carry no ground-truth label, and that is the point.** Nothing
in this module computes accuracy, precision, recall or a confusion matrix, and its
output must never be merged into `results/evaluation.json`; there is no key to
score against, so any such figure would be invented. `test_external.py` asserts
that no scored-metric field appears in the recorded output.

What it does measure needs no key:

| Measure | Question it answers |
| --- | --- |
| Alerts per kLOC | How much triage does adopting this scanner cost on real code? |
| Unmapped share | How much of a tool's real-world output falls outside the 26-control map? |
| In-module share | Does the scanner see past the top-level directory at all? |
| Pairwise Jaccard | How far do the scanners corroborate each other, by control and by resource? |

It deliberately does **not** reuse `run_baselines.run_tool_on_case`, which copies
`case_dir.glob("*.tf")` — flat, non-recursive — into a temporary directory. On a
real repository that silently discards every module subtree, which is exactly the
structure under test. The scanners are invoked on the work tree in place, using the
same command flags `TOOL_SPECS` records.

```bash
python -m experiments.fetch_external     # materialise the pinned commits first
python -m evaluation.external            # measure; writes results + two tables
```

Output is byte-reproducible: scan duration is neither timed nor recorded, because
latency describes the measuring host rather than the subset, and every other field
is deterministic.

### 5. Optional paired transition verification

`paired_verification.py` evaluates a different question from scanner scoring. It
uses the internal corpus metadata to bind each vulnerable and compliant member to
one canonical control and expected resource, then invokes an external IaC-Guard-V
executable for exact mappings reviewed in `paired_verification_map.json`.

This capability is optional. It does not contribute to scanner scores, confusion
matrices, confidence intervals, tables, or leaderboard rankings. Results are
written to a separate `results/paired_verification.json` artifact. See
[`docs/framework/paired-verification.md`](../docs/framework/paired-verification.md)
for the status model, dependency policy, and commands.

---

## 🧪 Testing & Execution

```bash
# Run baseline evaluation suite
python3 evaluation/run_baselines.py

# Run leaderboard scoring with synthetic override guard
IACSECBENCH_ALLOW_SYNTHETIC=1 python3 evaluation/score.py

# Run evaluation pytest suite
.venv/bin/pytest -v evaluation/tests/
```
