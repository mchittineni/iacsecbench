#!/usr/bin/env bash
#
# IaCSecBench — reproducible baseline execution.
#
# Runs the full measurement pipeline end to end:
#
#   1. validate the corpus and report how many cases are admissible
#   2. execute every installed scanner over the admissible cases
#   3. audit the control map against the rule identifiers actually emitted
#   4. compute statistics and emit LaTeX tables
#
# Nothing in this script synthesises a result. A scanner that is not installed is
# reported as such and excluded; it is never represented by an assumed detection
# rate. If no case is admissible the pipeline stops with a non-zero status rather
# than producing an empty-but-plausible table.
#
# Usage:
#   experiments/run_baselines.sh                  # full run, 3 repeats
#   REPEATS=10 experiments/run_baselines.sh       # more latency samples
#   VALIDATE=structural experiments/run_baselines.sh   # skip terraform init/validate
#
set -euo pipefail

REPEATS="${REPEATS:-3}"
VALIDATE="${VALIDATE:-terraform}"
LEVEL="${LEVEL:-control}"

cd "$(dirname "$0")/.."

if [ -x ".venv/bin/python" ]; then
  PYTHON=".venv/bin/python"
  export PATH="$PWD/.venv/bin:$PATH"
else
  PYTHON="$(command -v python3)"
fi

hr() { printf '=%.0s' {1..76}; printf '\n'; }

hr
echo "IaCSecBench baseline execution"
hr
echo "python        : $($PYTHON --version 2>&1)"
echo "repeats       : ${REPEATS}"
echo "validation    : ${VALIDATE}"
echo "matching level: ${LEVEL}"
echo

echo "--- [1/4] tool availability ---------------------------------------------"
$PYTHON -m evaluation.run_baselines --list-tools
echo

echo "--- [2/4] corpus admissibility ------------------------------------------"
$PYTHON -m evaluation.corpus --report --mode "${VALIDATE}" --latex \
  --json results/corpus_report.json
echo

echo "--- [3/4] scanner execution ---------------------------------------------"
if ! $PYTHON -m evaluation.run_baselines --all --repeats "${REPEATS}" \
     --validate "${VALIDATE}"; then
  status=$?
  echo
  echo "Baseline execution did not complete (exit ${status})."
  echo "If the corpus is empty, fix the cases -- do not lower the bar." >&2
  exit "${status}"
fi
echo

echo "--- [4/4] control-map audit and analysis --------------------------------"
$PYTHON -m evaluation.normalize --emit-unmapped || true
echo
$PYTHON -m evaluation.analyze --level "${LEVEL}"

hr
echo "Artefacts"
hr
echo "  results/corpus_report.json   corpus admissibility, per case"
echo "  results/raw/<tool>/           unmodified scanner output"
echo "  results/run_manifest.json     tool versions, environment, latency samples"
echo "  results/evaluation.json       confusion matrices, intervals, tests"
echo "  results/tables/*.tex          LaTeX tables for the manuscript"
hr
