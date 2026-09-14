"""Hermetic tests for optional paired transition verification."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from evaluation.corpus import Case
from evaluation.paired_verification import (
    CanonicalPair,
    MappingCatalog,
    PairMetadataError,
    PropertyMapping,
    _not_supported_record,
    _run_pair,
    build_manifest,
    derive_pairs,
    normalize_verifier_result,
    run_verification,
    write_json,
)

CONTROL = "ENC_UNENCRYPTED_VOLUME"
PROPERTY = "CHECKOV:3.3.0:CKV_AWS_3"
TARGET = "aws_ebs_volume.target"


def _case(tmp_path: Path, variant: str, **metadata_changes: object) -> Case:
    case_id = f"{CONTROL}-{variant.upper()}"
    path = tmp_path / case_id
    path.mkdir()
    (path / "main.tf").write_text(f"# {variant}\n", encoding="utf-8")
    metadata: dict[str, object] = {
        "pair_id": CONTROL,
        "pair_variant": variant,
        "canonical_controls": [CONTROL],
    }
    metadata.update(metadata_changes)
    return Case(
        case_id=case_id,
        path=path,
        collection="internal",
        subset="internal",
        domain="ENC",
        expected="VIOLATION" if variant == "vulnerable" else "COMPLIANT",
        canonical_controls=list(metadata.get("canonical_controls", [CONTROL])),
        expected_resources=[TARGET] if variant == "vulnerable" else [],
        metadata=metadata,
    )


def _pair(tmp_path: Path) -> CanonicalPair:
    return derive_pairs([_case(tmp_path, "vulnerable"), _case(tmp_path, "compliant")], {CONTROL})[0]


def _mapping(*, supported: bool = True) -> PropertyMapping:
    return PropertyMapping(
        control_id=CONTROL,
        semantic_mapping="EXACT_SAME_PROPERTY",
        supported=supported,
        property_ids=(PROPERTY,) if supported else (),
        rationale="Exact attribute transition.",
        reason_code="NO_PUBLIC_EXACT_PROPERTY" if not supported else "",
    )


def _catalog(*, supported: bool = True) -> MappingCatalog:
    return MappingCatalog(
        verifier_version="0.1.0b1",
        scanner_version="3.3.0",
        mappings={CONTROL: _mapping(supported=supported)},
        sha256="a" * 64,
    )


def _manifest_record(tmp_path: Path) -> tuple[CanonicalPair, dict[str, object]]:
    pair = _pair(tmp_path)
    manifest = build_manifest([pair], _catalog())
    return pair, manifest["pairs"][0]


def _report(verdict: str, *, reason_code: str | None = None) -> dict[str, object]:
    exit_code = {"VERIFIED": 0, "FAILED": 1, "INCONCLUSIVE": 3}[verdict]
    target = {"rule_id": "CKV_AWS_3", "scope": TARGET}
    payload: dict[str, object] = {
        "schema_version": "report-v1",
        "result_kind": "verification",
        "verdict": verdict,
        "exit_code": exit_code,
        "policy": {"decisions": [{"identity": target, "outcome": "FIXED"}]},
        "verification": {
            "baseline_run": {
                "evaluations": [
                    {
                        "rule_id": "CKV_AWS_3",
                        "resource_address": TARGET,
                        "native_result": "FAILED",
                        "source_bucket": "authoritative",
                    }
                ]
            },
            "candidate_run": {
                "evaluations": [
                    {
                        "rule_id": "CKV_AWS_3",
                        "resource_address": TARGET,
                        "native_result": "PASSED" if verdict == "VERIFIED" else "FAILED",
                        "source_bucket": "authoritative",
                    }
                ]
            },
            "targets": [],
            "regression": {"reason_code": reason_code or "NO_REGRESSION"},
        },
    }
    return payload


def _normalized(
    tmp_path: Path, verdict: str, *, reason_code: str | None = None
) -> dict[str, object]:
    _, record = _manifest_record(tmp_path)
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_report(verdict, reason_code=reason_code)), encoding="utf-8")
    completed = subprocess.CompletedProcess(
        args=["iac-guard"],
        returncode={"VERIFIED": 0, "FAILED": 1, "INCONCLUSIVE": 3}[verdict],
        stdout="",
        stderr="",
    )
    return normalize_verifier_result(
        completed, report, "paired_verification_raw/report.json", record, _mapping(), "0.1.0b1"
    )


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_derives_valid_pair_from_explicit_metadata(tmp_path: Path) -> None:
    pair = _pair(tmp_path)
    assert pair.pair_id == CONTROL
    assert pair.expected_resource == TARGET
    assert pair.vulnerable.expected == "VIOLATION"
    assert pair.compliant.expected == "COMPLIANT"


def test_rejects_missing_vulnerable_member(tmp_path: Path) -> None:
    with pytest.raises(PairMetadataError, match="expected one vulnerable member"):
        derive_pairs([_case(tmp_path, "compliant")], {CONTROL})


def test_rejects_missing_compliant_member(tmp_path: Path) -> None:
    with pytest.raises(PairMetadataError, match="expected one compliant member"):
        derive_pairs([_case(tmp_path, "vulnerable")], {CONTROL})


def test_rejects_mismatched_pair_id(tmp_path: Path) -> None:
    cases = [
        _case(tmp_path, "vulnerable"),
        _case(tmp_path, "compliant", pair_id="OTHER_CONTROL"),
    ]
    with pytest.raises(PairMetadataError, match="unknown pair_id"):
        derive_pairs(cases, {CONTROL})


def test_rejects_mismatched_canonical_control(tmp_path: Path) -> None:
    cases = [
        _case(tmp_path, "vulnerable"),
        _case(tmp_path, "compliant", canonical_controls=["OTHER_CONTROL"]),
    ]
    with pytest.raises(PairMetadataError, match="canonical_controls"):
        derive_pairs(cases, {CONTROL})


def test_rejects_ambiguous_expected_resource(tmp_path: Path) -> None:
    cases = [_case(tmp_path, "vulnerable"), _case(tmp_path, "compliant")]
    cases[0].expected_resources.append("aws_ebs_volume.other")
    with pytest.raises(PairMetadataError, match="expected one vulnerable target resource"):
        derive_pairs(cases, {CONTROL})


def test_exact_mapping_enters_manifest(tmp_path: Path) -> None:
    manifest = build_manifest([_pair(tmp_path)], _catalog())
    assert manifest["exact_supported"] == 1
    assert manifest["pairs"][0]["property_ids"] == [PROPERTY]
    assert manifest["pairs"][0]["mapping_supported"] is True


def test_unsupported_mapping_is_explicit(tmp_path: Path) -> None:
    pair = _pair(tmp_path)
    catalog = _catalog(supported=False)
    manifest = build_manifest([pair], catalog)
    result = run_verification([pair], catalog, manifest, None, None, tmp_path / "result.json")
    assert result["records"][0]["transition_result"] == "NOT_SUPPORTED"
    assert result["records"][0]["reason_code"] == "NO_PUBLIC_EXACT_PROPERTY"


def test_missing_verifier_is_graceful(tmp_path: Path) -> None:
    pair = _pair(tmp_path)
    catalog = _catalog()
    manifest = build_manifest([pair], catalog)
    result = run_verification([pair], catalog, manifest, None, None, tmp_path / "result.json")
    assert result["tool"]["available"] is False
    assert result["records"][0]["transition_result"] == "NOT_SUPPORTED"
    assert result["records"][0]["reason_code"] == "VERIFIER_UNAVAILABLE"
    assert result["summary"]["execution_errors"] == 0


def test_mismatched_verifier_version_is_not_executed(tmp_path: Path) -> None:
    pair = _pair(tmp_path)
    catalog = _catalog()
    manifest = build_manifest([pair], catalog)
    with patch("evaluation.paired_verification._probe_version", return_value=("0.1.0a10", None)):
        result = run_verification(
            [pair], catalog, manifest, "/tools/iac-guard", None, tmp_path / "result.json"
        )
    assert result["tool"]["available"] is False
    assert result["records"][0]["reason_code"] == "VERIFIER_VERSION_MISMATCH"
    assert result["records"][0]["transition_result"] == "NOT_SUPPORTED"


def test_malformed_verifier_json_is_execution_error(tmp_path: Path) -> None:
    _, record = _manifest_record(tmp_path)
    report = tmp_path / "bad.json"
    report.write_text("not-json", encoding="utf-8")
    completed = subprocess.CompletedProcess(["iac-guard"], 0, "", "")
    result = normalize_verifier_result(
        completed, report, "raw/bad.json", record, _mapping(), "0.1.0b1"
    )
    assert result["transition_result"] == "INCONCLUSIVE"
    assert result["reason_code"] == "VERIFIER_REPORT_MALFORMED"
    assert result["execution_error"] is True


def test_nonzero_operational_failure_is_execution_error(tmp_path: Path) -> None:
    _, record = _manifest_record(tmp_path)
    completed = subprocess.CompletedProcess(["iac-guard"], 4, "", "internal error")
    result = normalize_verifier_result(
        completed, tmp_path / "missing.json", "raw/missing.json", record, _mapping(), "0.1.0b1"
    )
    assert result["transition_result"] == "INCONCLUSIVE"
    assert result["reason_code"] == "VERIFIER_REPORT_MISSING"
    assert result["execution_error"] is True


def test_verified_normalization(tmp_path: Path) -> None:
    result = _normalized(tmp_path, "VERIFIED")
    assert result["transition_result"] == "VERIFIED"
    assert result["reason_code"] == "ALL_TARGETS_FIXED"
    assert result["vulnerable_evidence"]["evaluations"][0]["native_result"] == "FAILED"
    assert result["compliant_evidence"]["evaluations"][0]["native_result"] == "PASSED"


def test_failed_normalization(tmp_path: Path) -> None:
    result = _normalized(tmp_path, "FAILED", reason_code="TARGET_NOT_FIXED")
    assert result["transition_result"] == "FAILED"
    assert result["reason_code"] == "TARGET_NOT_FIXED"


def test_inconclusive_normalization(tmp_path: Path) -> None:
    result = _normalized(tmp_path, "INCONCLUSIVE", reason_code="NEW_FINDING_SEVERITY_UNKNOWN")
    assert result["transition_result"] == "INCONCLUSIVE"
    assert result["reason_code"] == "NEW_FINDING_SEVERITY_UNKNOWN"


def test_operational_uncertainty_normalization(tmp_path: Path) -> None:
    _, record = _manifest_record(tmp_path)
    report = tmp_path / "operational.json"
    payload = {
        "schema_version": "report-v1",
        "result_kind": "operational_uncertainty",
        "verdict": "INCONCLUSIVE",
        "exit_code": 3,
        "diagnostic": {
            "reason_code": "BASELINE_TARGET_DISCOVERY_UNAVAILABLE",
            "detail": "target inventory is incomplete",
        },
    }
    report.write_text(json.dumps(payload), encoding="utf-8")
    completed = subprocess.CompletedProcess(["iac-guard"], 3, "", "")
    result = normalize_verifier_result(
        completed, report, "raw/operational.json", record, _mapping(), "0.1.0b1"
    )
    assert result["transition_result"] == "INCONCLUSIVE"
    assert result["reason_code"] == "BASELINE_TARGET_DISCOVERY_UNAVAILABLE"
    assert result["execution_error"] is False


def test_request_rejected_normalization(tmp_path: Path) -> None:
    _, record = _manifest_record(tmp_path)
    error = {
        "schema_version": "request-error-v1",
        "reason_code": "INVALID_REQUEST",
        "detail": "bad target",
    }
    completed = subprocess.CompletedProcess(["iac-guard"], 2, "", json.dumps(error))
    result = normalize_verifier_result(
        completed, tmp_path / "missing.json", "raw/missing.json", record, _mapping(), "0.1.0b1"
    )
    assert result["transition_result"] == "REQUEST_REJECTED"
    assert result["reason_code"] == "INVALID_REQUEST"
    assert result["execution_error"] is False


def test_rejects_verifier_target_binding_mismatch(tmp_path: Path) -> None:
    _, record = _manifest_record(tmp_path)
    payload = _report("VERIFIED")
    payload["policy"]["decisions"][0]["identity"]["scope"] = "aws_ebs_volume.other"
    report = tmp_path / "wrong-target.json"
    report.write_text(json.dumps(payload), encoding="utf-8")
    completed = subprocess.CompletedProcess(["iac-guard"], 0, "", "")
    result = normalize_verifier_result(
        completed, report, "raw/wrong-target.json", record, _mapping(), "0.1.0b1"
    )
    assert result["transition_result"] == "INCONCLUSIVE"
    assert result["reason_code"] == "VERIFIER_TARGET_BINDING_MISMATCH"
    assert result["execution_error"] is True


def test_external_invocation_uses_no_shell_and_exact_target(tmp_path: Path) -> None:
    pair, record = _manifest_record(tmp_path)
    report = tmp_path / "raw.json"

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs.get("shell") is None
        assert f"CKV_AWS_3={TARGET}" in command
        assert command[command.index("--before") + 1] == str(pair.vulnerable.path)
        assert command[command.index("--after") + 1] == str(pair.compliant.path)
        report.write_text(json.dumps(_report("VERIFIED")), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    with patch("evaluation.paired_verification.subprocess.run", side_effect=fake_run):
        result = _run_pair(
            pair,
            record,
            _mapping(),
            "/tools/iac-guard",
            "/tools/checkov",
            report,
            "paired_verification_raw/raw.json",
            "0.1.0b1",
        )
    assert result["transition_result"] == "VERIFIED"


def test_external_invocation_does_not_reuse_stale_report(tmp_path: Path) -> None:
    pair, record = _manifest_record(tmp_path)
    report = tmp_path / "raw.json"
    report.write_text(json.dumps(_report("VERIFIED")), encoding="utf-8")
    completed = subprocess.CompletedProcess(["iac-guard"], 4, "", "internal error")
    with patch("evaluation.paired_verification.subprocess.run", return_value=completed):
        result = _run_pair(
            pair,
            record,
            _mapping(),
            "/tools/iac-guard",
            None,
            report,
            "paired_verification_raw/raw.json",
            "0.1.0b1",
        )
    assert report.exists() is False
    assert result["reason_code"] == "VERIFIER_REPORT_MISSING"
    assert result["execution_error"] is True


def test_deterministic_json_serialization(tmp_path: Path) -> None:
    payload = {"z": [3, 2, 1], "a": {"b": True}}
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    write_json(first, payload)
    write_json(second, payload)
    assert first.read_bytes() == second.read_bytes()


def test_writing_paired_result_leaves_existing_outputs_unchanged(tmp_path: Path) -> None:
    paths = [
        tmp_path / "results" / "evaluation.json",
        tmp_path / "results" / "tables" / "rates.tex",
        tmp_path / "leaderboard" / "results.csv",
    ]
    for index, path in enumerate(paths):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"existing-{index}\n", encoding="utf-8")
    before = {path: _sha(path) for path in paths}
    write_json(tmp_path / "results" / "paired_verification.json", {"status": "VERIFIED"})
    assert {path: _sha(path) for path in paths} == before


def test_not_supported_record_uses_closed_status(tmp_path: Path) -> None:
    _, record = _manifest_record(tmp_path)
    result = _not_supported_record(record, "0.1.0b1", "PROPERTY_NOT_SUPPORTED")
    assert result["transition_result"] == "NOT_SUPPORTED"
    assert result["reason_code"] == "PROPERTY_NOT_SUPPORTED"
