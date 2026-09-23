#!/usr/bin/env bash
set -e

echo "============================================================"
echo "IaCSecBench — One-Command Experiment Reproducibility Suite"
echo "============================================================"
echo ""

# Find Python binary
if [ -f ".venv/bin/python" ]; then
  PYTHON=".venv/bin/python"
elif [ -f ".venv/bin/python3" ]; then
  PYTHON=".venv/bin/python3"
else
  PYTHON="python3"
fi

# Find Pytest binary
if [ -f ".venv/bin/pytest" ]; then
  PYTEST=".venv/bin/pytest"
elif command -v pytest &> /dev/null; then
  PYTEST="pytest"
else
  PYTEST="$PYTHON -m pytest"
fi

# 1. Run Corpus Admissibility & Compliance Validation
echo "[Step 1/3] Running Corpus Admissibility & Security Compliance Validation..."
$PYTHON -m evaluation.corpus --report --mode structural
$PYTHON scripts/compliance_checker.py --framework soc2

# 2. Execute Pytest Test Suite
echo ""
echo "[Step 2/3] Executing Framework & Unit Tests with Coverage..."
if $PYTEST --help 2>&1 | grep -q "\--cov"; then
  COV_FLAG="--cov=security_framework"
else
  COV_FLAG=""
fi
$PYTEST security_framework/tests/ evaluation/tests/ $COV_FLAG -v

# 3. Measure. This is the only stage that produces results.
echo ""
echo "[Step 3/3] Measuring baselines (Checkov, tfsec, plan-level OPA, Layer 1)..."
bash experiments/run_baselines.sh

echo ""
echo "============================================================"
echo "SUCCESS: measurement complete."
echo "  results/run_manifest.json   tool versions, environment, latency samples"
echo "  results/evaluation.json     confusion matrices, intervals, tests"
echo "  results/tables/*.tex        LaTeX tables for the manuscript"
echo "  leaderboard/results.csv     measured leaderboard"
echo "============================================================"

# The stages below are deliberately NOT run here.
#
# pipeline/run_experiments.py and experiments/generate_charts.py do not execute a
# scanner. They multiply corpus counts by hardcoded per-tool rates and write the
# product to results/benchmark_results.json, results/charts/ and
# results/metrics.csv -- filenames indistinguishable from measured output. This
# script previously set IACSECBENCH_ALLOW_SYNTHETIC=1 and ran both, so any
# automated invocation (an editor task, a file watcher, a CI hook) would overwrite
# real measurements with assumed ones and then publish the result to an external
# Obsidian vault, where it outlives every caveat attached to it.
#
# Run them by hand if you want illustrative placeholders, and do not cite the
# output:
#
#   IACSECBENCH_ALLOW_SYNTHETIC=1 $PYTHON pipeline/run_experiments.py
#   IACSECBENCH_ALLOW_SYNTHETIC=1 $PYTHON experiments/generate_charts.py
#
# pipeline/sync_to_obsidian.py writes outside the repository into a personal
# vault. Publishing is a deliberate act, not a build step, so it is invoked
# explicitly:
#
#   $PYTHON pipeline/sync_to_obsidian.py
#
# It now renders its metrics table from results/evaluation.json, and reports that
# no measurement exists rather than showing numbers when that file is absent.
