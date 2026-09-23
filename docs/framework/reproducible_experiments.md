# Reproducible Experiments Guide

> **Step-by-Step Instructions for Executing and Verifying Benchmark Telemetry**

This document details the exact methodology, environment prerequisites, and execution commands required to reproduce all evaluation metrics and comparative benchmarking results for the **IaC Security Benchmark Framework**.

---

## 📋 Prerequisites & Environment Setup

- **Python Version**: Python 3.11+
- **Terraform CLI**: >= 1.15.0 (for native `.tftest.hcl` execution)
- **Dependencies**: Installed via `pip install -e '.[dev]'`

---

## 🧪 Execution Steps

### 1. Run Corpus Admissibility & Security Validators

```bash
# Verify corpus admissibility across all 56 benchmark cases
python3 -m evaluation.corpus --report --mode structural

# Verify compliance framework mapping (SOC2, GDPR, etc.)
python3 scripts/compliance_checker.py --framework soc2
```

### 2. Run Reproducible Benchmark Experiments & Scoring Protocol

```bash
# Execute evaluation analysis and regenerate LaTeX tables from recorded output
python3 -m evaluation.analyze --level control

# Execute full one-command reproducibility suite
./experiments/run_all.sh
```

Expected output is a table of per-tool confusion-matrix counts, recall with an
exact Clopper-Pearson interval, and latency mean with standard deviation, followed
by the caveats that must accompany the numbers.

No sample numbers are reproduced here. A worked example in documentation gets
quoted as a result, and the figures this section previously showed --- including a
flawless 100% for the reference implementation --- were never measured. Run the
command and read your own output:

```bash
experiments/run_baselines.sh
```

Two things the real output will tell you that the old sample did not: the reference
implementation ranks **last** on this corpus (Layer 1 is a repository-edge secret
and PII scanner, and the corpus is cloud misconfigurations), and plan-level latency
excludes the `terraform init` and `terraform plan` invocations that produce the plan
it evaluates.

### 3. Run Framework Unit & Integration Test Suite

```bash
.venv/bin/pytest security_framework/tests/ evaluation/tests/ -v
```

---

## 📁 Artifact Locations

- **Master Benchmark Catalog**: [benchmark.json](../../benchmark/benchmark.json)
- **Benchmark Dataset Schema**: [benchmarks.json](../../benchmark/datasets/benchmarks.json)
- **Measured results JSON**: [evaluation.json](../../results/evaluation.json) — confusion matrices, exact intervals, McNemar tests, caveats
- **Run manifest**: [run_manifest.json](../../results/run_manifest.json) — tool versions, environment, latency samples
- **Leaderboard Export**: [results.csv](../../leaderboard/results.csv)
- **Framework Documentation**: [framework.md](framework.md)
