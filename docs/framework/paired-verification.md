# Optional paired transition verification

IaCSecBench evaluates scanners on individual artifacts. Optional paired
verification asks a separate question: can an external verifier establish that
the labelled vulnerable to compliant transition resolves the selected property
on the exact expected resource?

The integration derives pairs only from existing internal-corpus metadata:

- `pair_id`
- `pair_variant`
- `canonical_controls`
- `expected_resources`, which is derived from the vulnerable member's
  `expected_violations`

Malformed or ambiguous metadata fails closed. Controls without a reviewed exact
mapping are reported as `NOT_SUPPORTED`; they are not silently omitted.

## Scope

Paired verification is:

- optional;
- separate from scanner evaluation;
- limited to the 26 canonical internal vulnerable and compliant pairs;
- read-only with respect to benchmark cases and recorded scanner results.

It is not part of scanner scoring, confusion matrices, confidence intervals,
LaTeX tables, or leaderboard rankings. It does not replace benchmark ground
truth and does not relabel a compliant member when complementary evidence is
inconclusive.

## Dependency model

IaCSecBench keeps its core Python dependency list empty. The module invokes an
external `iac-guard` executable as a subprocess and never installs it. The
reviewed mapping is pinned to:

```text
iac-guard-v==0.1.0b1
Checkov 3.3.0
```

If the executable is absent, the command exits cleanly and writes explicit
`NOT_SUPPORTED` records with reason `VERIFIER_UNAVAILABLE`. A supplied verifier
with a different version is also not executed.

## Status model

Each canonical pair receives exactly one status:

| Status | Meaning |
| --- | --- |
| `VERIFIED` | The external verifier established the requested transition. |
| `FAILED` | The verifier decisively rejected the requested transition. |
| `INCONCLUSIVE` | Evidence was insufficient for an authoritative verdict. |
| `REQUEST_REJECTED` | The verifier rejected the constructed request. |
| `NOT_SUPPORTED` | No exact mapping or usable pinned verifier was available. |

Reason codes and compact evidence digests are preserved. Full verifier reports
are stored in a sibling raw directory and referenced from the paired result.

## Commands

Review the supported and unsupported control mappings without invoking a tool:

```bash
python -m evaluation.paired_verification --list-supported
```

Freeze the metadata-derived manifest before execution:

```bash
python -m evaluation.paired_verification \
  --manifest-only \
  --output results/paired_verification_manifest.json
```

Run with the exact external verifier and scanner executables:

```bash
python -m evaluation.paired_verification \
  --iac-guard /path/to/iac-guard \
  --checkov /path/to/checkov \
  --output results/paired_verification.json
```

No network, cloud credentials, Terraform provider download, or model service is
used by this integration. Unit tests use recorded in-memory reports and mocked
subprocesses, so CI does not need either executable.

## Output isolation

The command writes only its requested paired-verification artifact and a sibling
raw-report directory. It does not read or modify:

- `results/evaluation.json`
- `results/tables/`
- `leaderboard/`
- scanner raw outputs
- benchmark case labels

`NET_NO_FLOW_LOGS` illustrates the separation. A paired result may remain
`INCONCLUSIVE` when evidence for the transition is incomplete while the benchmark
continues to preserve the canonical compliant label.
