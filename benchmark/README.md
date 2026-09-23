# 🎯 Benchmark Directory — Ground-Truth Datasets & Test Scenarios

## 📋 Directory Overview

The `benchmark/` directory contains the controlled ground-truth evaluation datasets and external validation scenarios used by **IaCSecBench** to assess IaC security scanners and Policy-as-Code engines.

---

## 📁 Directory Structure & Key Files

```text
benchmark/
├── internal/                          # Controlled Internal Benchmark Suite (44 cases present)
│   ├── metadata.json                  # Canonical Labelled Ground-Truth Annotations
│   ├── cases/                         # 12 Domain HCL Configurations
│   └── baselines/                     # Secure Infrastructure Baselines
├── external/                          # External collection: 175 DECLARED, 4 present
│   ├── terraform_registry/            # metadata declares 50; modules/ is empty
│   │   └── metadata.json
│   ├── secureflag/                    # metadata declares 75; terraform/ is empty
│   │   └── metadata.json
│   └── cis_examples/                  # metadata declares 50; aws/ holds 4 .tf files
│       └── metadata.json

(There is no reports/ directory. See section 3 below.)
```

---

## ⚙️ Key Components Explained

### 1. Internal Controlled Benchmark (`benchmark/internal/`)

- Contains **52 labelled cases present on disk** (26 vulnerable / 26 compliant) across 9 domains: IAM, NET, STO, ENC, CMP, MON, SEC, SRV, K8S. Every one of the 26 canonical controls in `evaluation/control_map.json` now has a vulnerable/compliant pair; before, four controls had none, so no tool could be credited or faulted on them. The designed taxonomy targets 345 cases across 12 domains; the three remaining domains (ID, PII, TF) have no cases yet and nothing is measured over them.
- **Metadata Annotation Schema (`metadata.json`)**: Formats each case with canonical attributes: `case_id`, `domain`, `severity`, `target_resource_urn`, and ground-truth `status` (`VIOLATION` vs. `COMPLIANT`).
- Cases are generated from the specifications in `benchmark/generate_corpus.py`; edit those rather than the emitted files. Regenerate with `python -m benchmark.generate_corpus --write`.

#### Tool scope

A tool that does not read a resource type cannot be said to have missed a
misconfiguration in it, but the confusion matrix cannot tell the two apart:
`evaluation/normalize.py:score_case` records both as a non-detection, and both
land in the false-negative cell.

This is live for the three K8S controls. Measured, not assumed: **neither tfsec
1.28.14 nor Trivy 0.73.0 emits any finding on any `kubernetes_*` Terraform
resource** — not a different finding, none at all — on `kubernetes_pod` or
`kubernetes_pod_security_policy`, vulnerable and compliant variants alike. Only
Checkov inspects them, and only under `--framework terraform`, which is how the
harness invokes it.

The consequence is large enough to state numerically. Adding the four missing
pairs moves control-level recall by:

| Tool | Before | After | Change |
| --- | --- | --- | --- |
| checkov | 88.5% | 90.0% | +1.5% |
| tfsec | 84.6% | 76.7% | **−7.9%** |
| trivy | 80.8% | 73.3% | **−7.4%** |

Almost all of the tfsec and Trivy movement is scope, not detection quality. The
affected controls therefore carry `inapplicable_tools` in the control map, and
`evaluation/analyze.py` emits a caveat naming them in `results/evaluation.json`.
Any report of these figures must carry that caveat, or state the K8S controls
separately from the AWS ones.

Checkov's own K8S rule bindings are narrower than they look: `CKV_K8S_6`
(root containers) is bound to `kubernetes_pod_security_policy`, not
`kubernetes_pod` — setting `run_as_non_root = false` on a pod fires nothing —
which is why that pair is written against the resource the check inspects.

### 2. External Validation Collection (`benchmark/external/`)

Each `metadata.json` here declares more cases than there are configurations on
disk. The manifests are left unmodified on purpose: `evaluation/corpus.py` reads
the declared count precisely so it can report the gap, and correcting the
manifests would erase the evidence of it.

- **`terraform_registry/`**: declares 50 modules. `modules/` is empty — **0 usable cases.**
- **`secureflag/`**: declares 75 scenarios. `terraform/` is empty — **0 usable cases.**
- **`cis_examples/`**: declares 50 controls. `aws/` holds **4** Terraform configurations, and those 4 are the entire external contribution to every measurement in this repository.

A manifest entry with no configuration behind it is a citation, not a case, and
is never counted as one.

### 3. Generated Evaluation Telemetry — now under `results/`

Measured output lives in [`results/`](../results/), not here. `benchmark/reports/`
previously held `experiment_results.json`, written by `pipeline/run_experiments.py`
from hardcoded per-tool rates rather than from any scanner execution; it has been
deleted, and the stage that wrote it now refuses to run without
`IACSECBENCH_ALLOW_SYNTHETIC=1`.

Execution outputs, timing data, confusion matrices and precision/recall statistics
are in `results/run_manifest.json` and `results/evaluation.json`. See
[`results/README.md`](../results/README.md).

---

## Ground-truth labelling and its automated consistency audit

Labels are derived mechanically by `generate_corpus.py` from per-control
specifications, so rater disagreement is impossible by construction and
**specification error** is the threat that replaces it.

[`labelling/`](labelling/) records a blind second labelling pass run against that
threat: 47 of 48 cases agreed (Cohen's κ = 0.958, before reconciliation), and the
single disagreement was a genuine defect — a control whose stated text was weaker
than the requirement its label encoded. Read
[`labelling/README.md`](labelling/README.md) for the method, the reconciliation, and
the limitations that bound what κ means here.

## 🔗 Related Knowledge Base Links

- [[Research/RQ1-Internal-Metrics|📊 RQ1: Internal Controlled Benchmark Performance]]
- [[Research/RQ5-External-Generalizability|🌐 RQ5: External Validation Collection]]
- [[Project-Structure|📐 View Project Architecture]]
