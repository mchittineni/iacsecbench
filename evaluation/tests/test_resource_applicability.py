"""Tests that the resource criterion is scored only where it applies.

Motivated by a real defect. A case whose ground truth names no resource address
cannot be scored under the resource criterion, and ``score_case`` already marked
such cases inapplicable, but ``aggregate`` counted them as misses anyway. The four
external CIS cases name no address, so every tool lost four true positives at the
resource level and the manuscript reported resource as stricter than control for
every tool. Over the cases where it applies, four of the five tools score higher
under resource, not lower. The defect produced a plausible number rather than an
error, which is why it is pinned here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from evaluation import analyze
from evaluation.corpus import Case
from evaluation.normalize import CaseOutcome, ControlMap


def _case(case_id: str, resources: list[str]) -> Case:
    return Case(
        case_id=case_id,
        path=Path("."),
        collection="internal",
        subset="controlled",
        domain="STO",
        expected="VIOLATION",
        canonical_controls=["STO_UNENCRYPTED_BUCKET"],
        expected_resources=resources,
    )


@pytest.fixture
def outcomes(monkeypatch: pytest.MonkeyPatch) -> dict[str, CaseOutcome]:
    """Every case is detected at every level; only applicability differs."""

    def fake_score_case(*, case_id: str, tool: str, expected_resources, **_: object):
        outcome = CaseOutcome(case_id=case_id, tool=tool, expected="VIOLATION")
        outcome.detected = {"control": True, "resource": True, "any": True}
        outcome.resource_matching_applicable = any("." in r for r in expected_resources)
        return outcome

    monkeypatch.setattr(analyze, "score_case", fake_score_case)
    monkeypatch.setattr(analyze, "_load_raw", lambda tool, case_id: None)
    return {}


def test_inapplicable_cases_are_left_out_of_the_resource_matrix(outcomes) -> None:
    cases = [
        _case("NAMED-ADDRESS", ["aws_s3_bucket.data"]),
        _case("NO-ADDRESS", []),
    ]
    manifest = {
        "runs": [
            {"tool": "checkov", "case_id": c.case_id, "status": "ok", "latency_ms": [1.0]}
            for c in cases
        ]
    }
    results, _ = analyze.aggregate(cases, manifest, ControlMap.load())
    checkov = results["checkov"]

    # Both cases count at the control and any levels.
    assert checkov["control"].matrix.positives == 2
    assert checkov["any"].matrix.positives == 2
    # Only the case naming an address counts at the resource level, and it is a
    # true positive there -- not a false negative dragging recall down.
    resource = checkov["resource"].matrix
    assert resource.positives == 1
    assert (resource.tp, resource.fn) == (1, 0)
    assert "NO-ADDRESS" not in checkov["resource"].outcomes
