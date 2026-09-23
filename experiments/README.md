# 📊 Experiments Directory — One-Command Reproducibility Suite (`experiments/`)

## 📋 Directory Overview

The `experiments/` directory provides one-command reproducibility scripts for executing complete end-to-end benchmark experiments, running baseline tool scans, generating performance figures, and synchronizing workspace data with Obsidian.

---

## 📁 Directory Structure & Key Files

```text
experiments/
├── run_all.sh             # Master One-Command Reproduction Shell Script
├── run_baselines.sh       # Baseline Evaluation Runner Script
├── generate_charts.py     # Benchmark Performance Chart & Visual Figure Generator
├── environment.yml        # Conda / Virtual Environment specification
└── requirements.txt       # Python dependencies for experiments
```

---

## ⚙️ Key Execution Scripts

### 1. One-Command Reproduction Script (`run_all.sh`)

Three stages, none of which fabricates anything:

1. **Corpus Admissibility & Compliance Validation** — `python -m evaluation.corpus --report --mode structural` and `scripts/compliance_checker.py --framework soc2`.
2. **Pytest Verification** — the unit test suite. No `IACSECBENCH_ALLOW_SYNTHETIC` is
   exported: tests that exercise a fabricating stage opt in individually, and one
   asserts those stages refuse without it.
3. **Measurement** — delegates to `run_baselines.sh`.

It no longer runs `score.py`, `run_experiments.py`, `generate_charts.py` or
`sync_to_obsidian.py`. The first three derive metrics from hardcoded rates and used
to overwrite measured results with them; the fourth publishes outside the
repository, which is a deliberate act rather than a build step. All four still work
and are invoked by hand — the first three only under
`IACSECBENCH_ALLOW_SYNTHETIC=1`.

### 2. Figure Source Generator (`generate_figures.py`)

Writes the Mermaid sources for the manuscript's two diagrams from the recorded
results, so a figure cannot assert a corpus size or a tool version that disagrees
with a table. An earlier set of hand-drawn figures claimed 345 cases and named a
scanner the paper excludes; that is the class of defect this removes.

```bash
python -m experiments.generate_figures          # refresh paper/figures/*.mmd
python -m experiments.generate_figures --check  # exit 1 if they are stale (CI gate)
python -m experiments.generate_figures --check --strict   # ... also on latency drift
```

`--check` tolerates a difference confined to the pipeline figure's two measured
latency labels. Those track the host that ran the measurement, not the recorded
results, and CI measures on a shared runner whose latency the harness itself
declares unpublishable — so failing on them would force runner noise into the
published figures. Everything a table could contradict still fails the check. Use
`--strict` on the idle machine that produces publishable latency.

Rendering the `.mmd` to vector PDF is a separate manual step; see
`paper/figures/README.md`.

### 2a. External Subset Fetcher (`fetch_external.py`)

Materialises the unlabelled external subset at the exact commits pinned in
`benchmark/external/aws_samples/manifest.json`, and refuses to proceed on any
mismatch — so a measurement cannot quietly run against a moved upstream branch.

The working trees are **not** vendored into this repository. A pinned commit is
smaller and stronger evidence than a subtree: anyone can fetch the same bytes and
verify the hash, whereas vendored third-party code becomes indistinguishable, after
the fact, from code this project wrote. All 25 repositories are MIT-0, so vendoring
would be permitted; provenance is the reason not to.

```bash
python -m experiments.fetch_external          # clone or verify every repository
python -m experiments.fetch_external --check  # verify only; exit 1 if absent or moved
```

Fetched trees land in `.external-corpus/`, which is gitignored. See
`evaluation/external.py` for what is then measured, and why none of it may enter
the accuracy tables.

### 3. Baseline Evaluation Shell Script (`run_baselines.sh`)

**The only script that produces results.** Four stages: corpus admissibility,
scanner execution with repeats, a control-map audit against the rule identifiers
actually emitted, then statistics and LaTeX table generation. Requires Checkov,
tfsec, Trivy, OPA and Terraform; a tool that is absent is reported as absent and
excluded, never assigned an assumed detection rate.

Trivy runs with `--skip-check-update`, so its checks bundle must already be cached
before a measurement. Otherwise the first invocation fetches it from a registry and
that network time is recorded as scanner latency — or the fetch fails and the scan
is recorded as finding nothing, which is indistinguishable from a clean case.

Takes tens of minutes, largely in `terraform init`/`validate` per case.

> **Measure latency on an idle machine.** It is the one metric that reflects the
> host rather than the tool. The same corpus produced a Checkov standard deviation
> of 155 ms idle and 897 ms under load — a sixfold difference from the environment
> alone, with the mean barely moving. Detection counts are deterministic; latency
> is not.

### 4. In CI

`.github/workflows/benchmark.yml` runs this harness on manual dispatch and weekly,
installing all four tools and uploading `results/` as an artefact. It deliberately
does **not** commit results back, because CI latency would overwrite the only
publishable figures. Pull requests get the fast checks in `ci.yml` instead.

---

## 🚀 Running Experiments

```bash
# Run baseline evaluation suite
bash experiments/run_baselines.sh

# Run complete reproduction pipeline
bash experiments/run_all.sh
```
