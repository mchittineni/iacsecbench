# IaCSecBench

> **An Open Framework and Empirical Benchmark for Evaluating Infrastructure-as-Code Security Gates**

[![CI](https://github.com/mchittineni/IaCSecBench/actions/workflows/ci.yml/badge.svg)](https://github.com/mchittineni/IaCSecBench/actions/workflows/ci.yml)
[![Infra CI](https://github.com/mchittineni/IaCSecBench/actions/workflows/infra-ci.yml/badge.svg)](https://github.com/mchittineni/IaCSecBench/actions/workflows/infra-ci.yml)
[![Benchmark](https://github.com/mchittineni/IaCSecBench/actions/workflows/benchmark.yml/badge.svg)](https://github.com/mchittineni/IaCSecBench/actions/workflows/benchmark.yml)
[![Deploy](https://github.com/mchittineni/IaCSecBench/actions/workflows/deploy-pages.yml/badge.svg)](https://github.com/mchittineni/IaCSecBench/actions/workflows/deploy-pages.yml)
[![Control coverage 26/26](https://img.shields.io/badge/control_coverage-26%2F26_exercised-brightgreen.svg)](evaluation/control_map.json)
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.21645016-purple.svg)](https://doi.org/10.5281/zenodo.21645016)

<!-- The six badges above are the four live workflow-status ones plus two measured facts.
     Four static shields were removed rather than kept: "Tests Passing" and
     "Benchmark Reproducible" were hardcoded literals that stayed green regardless of
     the actual state, "Security Zero-PII Validated" asserted an outcome no badge can
     establish, and "IaC Coverage 100%" was simply false -- 22 of 26 canonical controls
     were exercised by the corpus at the time and rule mappings remained unverified. A badge that
     cannot change is decoration, and one that overstates coverage is worse. The
     coverage badge above is a hand-maintained number; re-derive it with
     `python -m evaluation.analyze` and see `results/evaluation.json`. -->

> **Measured state.** 56 admissible cases (30 vulnerable / 26 compliant); all 26
> canonical controls exercised; 2 rule mappings unverified. Every figure in
> `results/` and in the paper is generated from recorded scanner output by
> `evaluation/analyze.py` — see [`results/`](results/) and the caveat list in
> `results/evaluation.json`.

---

## 📌 Project Overview

IaCSecBench is an open-source Infrastructure-as-Code security evaluation framework
that benchmarks static analysis tools, policy engines, and secret detection suites
against a labelled corpus, under a mechanically enforced admission procedure.

It guards a reference deployment under [`infrastructure/`](infrastructure/) — an
AWS Terraform stack with native `terraform test` suites — which is what the
pipeline's module-testing layer validates.

> **Note.** This repository previously also held a real-estate discovery portal
> and its data pipeline, developed alongside the benchmark but sharing no code
> with it. That project now lives separately as `crowncorridor`; nothing it
> contained produced a number reported here.

---

## 💡 Why This Project Exists

Modern IaC security tools detect different classes of vulnerabilities with varying trade-offs in detection capabilities, false positive rates, and runtime latency.

This repository provides **IaCSecBench**, a unified evaluation framework to measure:

- **Detection Capability**: Evaluating true positives, recall, and edge-case coverage across AST scanners, policy engines, and integration tests.
- **Runtime Overhead**: Benchmarking execution latency (ms) per scanning pass.
- **Policy Coverage**: Measuring compliance against CIS AWS Foundations Benchmark standards.
- **Maintenance Complexity**: Assessing policy-as-code complexity, zero-PII compliance, and reproducible experiment workflows.

---

## ✨ What it provides

| Capability | Description |
| --- | --- |
| 🎯 **Canonical control taxonomy** | 26 controls that heterogeneous scanner output is normalized onto, so tools reporting different rule identifiers for the same misconfiguration are compared on equal terms ([`evaluation/control_map.json`](evaluation/control_map.json)) |
| 🧪 **Labelled corpus** | 56 admissible cases — 30 vulnerable, 26 compliant — each a minimal vulnerable/compliant pair generated from a specification, plus four CIS-illustrating examples of unrecorded provenance |
| 🚪 **Mechanical admission gate** | Every case must carry a ground-truth label, resolve to a canonical control, and pass `terraform init` + `validate` before it can enter a measurement |
| 📐 **Three matching criteria** | Control attribution, resource attribution, and any-finding — reported side by side, because which one is chosen moves apparent recall |
| 📊 **Exact statistics** | Clopper–Pearson intervals and exact McNemar tests under Holm–Bonferroni correction; metrics that are not estimable are reported as such rather than as zero |
| 🔬 **Unlabelled external subset** | 25 third-party AWS Terraform repositories pinned by commit, used for alert volume, cross-tool agreement, and module-boundary reach — never for accuracy |
| 🏗️ **Three-layer reference pipeline** | Repository-edge scanning, native `terraform test` module validation, and plan-level OPA policy over compiled plan JSON |
| ♻️ **Generated artefacts only** | Every table and figure in the manuscript is emitted from recorded scanner output; nothing is hand-copied |

---

## 📁 Project Structure

```
iacsecbench/
├── benchmark/               # The corpus
│   ├── generate_corpus.py   # case specifications — edit these, not the emitted cases
│   ├── internal/cases/      # 52 generated vulnerable/compliant cases
│   ├── external/            # third-party collections, incl. the unlabelled subset manifest
│   └── labelling/           # blind second-rater record for the labelling audit
│
├── evaluation/              # Normalization, scoring, statistics, table emission
│   ├── control_map.json     # native rule identifiers → canonical controls
│   ├── corpus.py            # loading and the admission gate
│   ├── normalize.py         # per-tool parsers and case scoring
│   ├── analyze.py           # confusion matrices, intervals, tests, LaTeX tables
│   ├── external.py          # the unlabelled subset measurement
│   ├── stats.py             # Clopper–Pearson, exact McNemar, Holm–Bonferroni
│   └── tfenv.py             # offline provider mirror
│
├── experiments/             # Measurement entry points
│   ├── run_baselines.sh     # the only script that produces results
│   ├── generate_figures.py  # figure sources, generated from recorded results
│   └── fetch_external.py    # materialises the pinned external subset
│
├── security_framework/      # Layer 1: repository-edge secret and personal-data scanner
├── infrastructure/          # Reference deployment: AWS Terraform + native tests (Layer 2)
├── results/                 # Recorded output: raw scanner JSON, evaluation.json, tables
├── leaderboard/             # Measured leaderboard CSV
├── paper/                   # Manuscript source and generated figures
├── scripts/                 # Local review utilities (not gates, not measured)
└── docs/                    # Protocol, taxonomy, framework documentation
```

---

## 📄 Research Paper & Replication Package

This repository accompanies the research manuscript:

> **IaCSecBench: A Finding-Normalization Methodology and Reproducible Harness for Evaluating Infrastructure-as-Code Security Validation**  
> *Target Venue:* Empirical Software Engineering (Springer)  
> *Author:* Manideep Chittineni (ORCID: [0009-0003-9709-5842](https://orcid.org/0009-0003-9709-5842))  
> *Permanent Archive:* [https://doi.org/10.5281/zenodo.21645016](https://doi.org/10.5281/zenodo.21645016)

For complete step-by-step instructions to reproduce all empirical tables, statistical tests, and diagrams, see [**REPLICATION.md**](REPLICATION.md).

To build the submission manuscript bundle:
```bash
cd paper
make check   # Verify EMSE format compliance and zero TODO markers
make paper   # Compile manuscript PDF
make dist    # Assemble standalone submission tarball
```

---

## 💻 Reproducing a measurement

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'

# Scanners under comparison must be on PATH; a missing tool is reported as
# not_run and omitted, never assigned an assumed detection rate.
python -m evaluation.run_baselines --list-tools

python -m evaluation.corpus --report --mode terraform   # admission gate
./experiments/run_baselines.sh                          # full measurement
```

Outputs land in `results/`: `corpus_report.json`, `raw/<tool>/`,
`run_manifest.json`, `evaluation.json`, and `tables/*.tex`. Read the `caveats`
list in `evaluation.json` before quoting any number from it.

The unlabelled external subset is measured separately, and never mixed into the
accuracy tables:

```bash
python -m experiments.fetch_external      # clone the pinned commits
python -m evaluation.external             # measure alert volume and agreement
```

---

## 🧪 Testing

```bash
pytest                                    # evaluation and security_framework suites
cd infrastructure && terraform test       # Layer 2: native module tests
```

---

## 🏗️ Reference deployment

[`infrastructure/`](infrastructure/) holds the AWS Terraform stack the pipeline
guards — VPC, compute, database, API gateway, CDN, WAF, auth, secrets, and
alerting modules — with native `terraform test` suites under
`infrastructure/tests/`. It is what the module-testing layer validates, and the
subject of the engineering-effort measurement reported in the manuscript.

This Terraform was originally authored as the deployment for a separate
application that once shared this repository. It is retained here as the
reference deployment because the pipeline needs real infrastructure to guard;
the application itself lives in its own project.

---

## 🔒 Privacy

The repository-edge layer refuses commits carrying secret material or personal
data, and its detections are scored on the same basis as every other tool rather
than asserted. No personal data is stored in this repository.

---

## 📄 License

MIT — see [LICENSE](LICENSE).

No third-party source file is vendored in this repository, so the MIT grant covers
all of it. The `LICENSE` file records what the benchmark refers to without
redistributing: the 25 MIT-0 repositories of the unlabelled external subset, which
are pinned by commit and fetched into a gitignored directory; the CIS control
identifiers the corpus cites without reproducing CIS Benchmark text; and the five
scanners, which are invoked as external subprocesses and pinned in
`results/run_manifest.json`.
