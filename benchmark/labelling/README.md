# Independent relabelling of the corpus

Ground-truth labels in this corpus are derived mechanically: a generator emits each
vulnerable/compliant pair from a per-control specification, and the label follows
from which member of the pair is being written. That makes rater disagreement
impossible by construction and **specification error** the threat that replaces it —
a specification that misreads its control produces a wrong label, identically,
across the whole pair, and no amount of determinism detects it.

This directory records a second labelling pass designed to detect exactly that.

## Method

1. **Blinding.** For each of the 48 cases admissible when the pass was run, a review view was built
   containing only the Terraform configuration and the canonical control under
   test. Everything carrying the answer was removed:
   - every comment line, because the generator writes `# Expected: COMPLIANT` and
     `# Rationale: ...` into each file header;
   - `expected.json` and `metadata.json`;
   - the case ID, which ends in `SAFE` or `VULN`.
     Cases were presented in an order keyed on `sha256(case_id)` — reproducible, and
     uncorrelated with the label.
2. **Screening.** The blinded views were scanned for residual label words
   (`safe`, `vuln*`, `compliant`, `violation`, `insecure`, `secure`). Three hits
   were inspected: two were the control title `"...image vulnerability scanning"`,
   and one is CIS-illustrating content of unrecorded provenance, left in (see Limitations).
3. **Labelling.** Each view was assigned `VIOLATION` or `COMPLIANT` for the named
   control, with a one-line reason recorded before any comparison.
4. **Comparison.** Agreement computed **before** reconciliation. Reporting
   agreement after resolving disagreements would be circular: resolution
   guarantees consensus.

No script for the blinded views was recorded. Re-derive them from the corpus by
applying the five steps listed under `method.blinding` in
`independent_relabelling.json`; the blinding is a pure function of the case
directory.

## Agreement, before reconciliation

|                          | rater 2: VIOLATION | rater 2: COMPLIANT |
| :----------------------- | :----------------: | :----------------: |
| **generator: VIOLATION** |         25         |         1          |
| **generator: COMPLIANT** |         0          |         22         |

- Cases: **48**
- Raw agreement: **47/48 = 97.92%**
- Expected by chance: 50.17%
- **Cohen's κ = 0.958**

Machine-readable, with every per-case label and reason:
[`independent_relabelling.json`](independent_relabelling.json).

## The single disagreement

**`STO-UNENCRYPTED-BUCKET-VULN`** — recorded `VIOLATION`, second rater `COMPLIANT`.

The configuration declares an `aws_s3_bucket_server_side_encryption_configuration`
with `sse_algorithm = "AES256"`. The control was titled _"Object storage bucket
lacks server-side encryption"_ and cited CIS AWS 2.1.1, a v1.4.0 requirement
(encryption at rest) that v3.0.0 removed. An AES256 bucket does not lack
server-side encryption, and that requirement is satisfied by SSE-S3. Read against its own stated text, the case is compliant.

The generator's intent was different: its rationale reads _"Bucket encryption uses
AES256 rather than a customer-managed key."_ The label encodes a **customer-managed
key requirement** that the control text did not state.

This matters beyond one case, because the stricter reading is also what the
reference policy set enforces (`applied.sse_algorithm != "aws:kms"` → deny). The
ground truth agreed with the reference implementation rather than with the control
it cited — a concrete instance of the construct-validity threat the paper
discusses, rather than a hypothetical one.

### Reconciliation

The **control text was corrected, not the label.** Requiring a customer-managed key
is a defensible control, and it is what the corpus, the policy set, and the
CMK-specific rules in Checkov, tfsec and Trivy all actually test. Changing the label
instead would have made the vulnerable/compliant pair test nothing.

(This section originally said "both Checkov and tfsec", from when the comparison
covered two source-level scanners. Trivy was added later and maps the same control
via `AWS-0132`, tfsec's `aws-s3-encryption-customer-key`, so the reasoning holds
across all three rather than being weakened by the addition.)

`STO_UNENCRYPTED_BUCKET` is now titled _"Object storage bucket not encrypted with a
customer-managed key"_, matching the phrasing already used by
`MON_NO_LOG_ENCRYPTION`, and carries a `cis_aws_note` recording that it is **stricter than
CIS AWS v1.4.0 2.1.1** and has no v3.0.0 counterpart. No confusion-matrix entry changed.

A regression test (`evaluation/tests/test_control_map.py`) now pins the CIS citation
in the control map to the one in the generator specification, so the two cannot
drift apart silently again.

## Identity of the second rater

The second rater was a large language model, and that use is disclosed in the
paper's methods (Section 4.3) and its AI-use declaration. **Its identity and
version, access route, decoding parameters, and the exact instruction it was given
were not recorded when the pass was run.** They are not reconstructed here,
because a reconstructed prompt presented as the one sent would be a false record.

The consequence is stated in the paper: κ is a property of one model under one
instruction, and with neither identified the labelling cannot be repeated. κ can
be recomputed from the recorded labels but not re-obtained from the instrument.
Read it as a record of what was observed, not as a reproducible measurement.
`independent_relabelling.json` records `"rater2_identity_recorded": false` under
`method`, alongside the per-case labels and reasons, which are recorded.

## Limitations — read before citing κ

- **The second rater is an LLM, not an independent human investigator.** This does
  not establish human inter-rater reliability, and κ here should not be reported as
  if it did. What it does establish is that a reader working only from the
  configuration and the control text reaches the recorded label in 47 of 48 cases.
- **Shared provenance.** An LLM's reading of CIS controls derives from the same
  public documentation the specifications were written from, so the two raters are
  not fully independent. Agreement is therefore biased upward.
- **Five cases were contaminated by prior exposure.** During earlier debugging in
  the same session, the rater had already seen the configuration and label of
  `MON-NO-LOG-ENCRYPTION-SAFE`, `MON-NO-LOG-ENCRYPTION-VULN`,
  `IAM-WILDCARD-ACTION-SAFE`, `STO-NO-ACCESS-LOGGING-SAFE` and
  `NET-UNRESTRICTED-INGRESS-VULN`. Their agreement is not blind. Excluding all
  five, agreement is 42/43 with the same single disagreement outside that set.
- **One residual blinding leak.** `external/cis_examples/aws/cis_3_1_cloudtrail` declares
  `resource "aws_cloudtrail" "insecure_trail"`. The name hints at the label. It is
  CIS-illustrating content of unrecorded provenance and was left unmodified rather than renamed,
  since renaming would alter the case under test.
- **κ is inflated by a near-balanced corpus at high agreement.** With 26/22 class
  balance, chance agreement is ~50%, so a single disagreement moves κ by roughly
  0.04. The interval around 0.958 is wide at n=48.

**What this pass does not do:** it does not remove the construct-validity threat.
One investigator still wrote every specification, and a second reading that shares
source material with the first cannot certify the first. Independent relabelling by
a second human, ideally one who has not read the policy set, remains the correct
mitigation.
