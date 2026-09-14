"""Optional paired transition verification for the internal benchmark corpus.

Scanner evaluation asks whether a tool reports a finding on one artifact. This
module asks a separate question: whether an external verifier can establish the
vulnerable-to-compliant transition for the exact benchmark target and property.
It does not read or modify scanner results, scoring, tables, or leaderboards.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evaluation.corpus import Case, load_internal
from evaluation.normalize import ControlMap

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MAP = Path(__file__).resolve().parent / "paired_verification_map.json"
DEFAULT_OUTPUT = ROOT / "results" / "paired_verification.json"
MANIFEST_SCHEMA = "iacsecbench-paired-verification-manifest-v1"
RESULT_SCHEMA = "iacsecbench-paired-verification-v1"
VALID_STATUSES = {"VERIFIED", "FAILED", "INCONCLUSIVE", "REQUEST_REJECTED", "NOT_SUPPORTED"}
PROPERTY_RE = re.compile(r"^CHECKOV:3\.3\.0:(CKV(?:2)?_[A-Z0-9_]+)$")


class PairMetadataError(ValueError):
    """Raised when canonical pair metadata is missing or ambiguous."""


class MappingError(ValueError):
    """Raised when the reviewed property map is malformed."""


@dataclass(frozen=True)
class PropertyMapping:
    """One reviewed canonical-control to verifier-property mapping."""

    control_id: str
    semantic_mapping: str
    supported: bool
    property_ids: tuple[str, ...]
    rationale: str
    reason_code: str = ""

    @property
    def rules(self) -> tuple[str, ...]:
        rules: list[str] = []
        for property_id in self.property_ids:
            match = PROPERTY_RE.fullmatch(property_id)
            if not match:
                raise MappingError(f"invalid public property identity: {property_id}")
            rules.append(match.group(1))
        return tuple(rules)


@dataclass(frozen=True)
class MappingCatalog:
    """Validated mapping file and verifier identities."""

    verifier_version: str
    scanner_version: str
    mappings: dict[str, PropertyMapping]
    sha256: str


@dataclass(frozen=True)
class CanonicalPair:
    """One exact vulnerable and compliant member pair."""

    pair_id: str
    vulnerable: Case
    compliant: Case
    canonical_control: str
    expected_resource: str


def _reject_duplicate_keys(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle, object_pairs_hook=_reject_duplicate_keys)


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _case_digest(path: Path) -> str:
    files: list[dict[str, Any]] = []
    for candidate in sorted(path.rglob("*")):
        if candidate.is_symlink():
            raise PairMetadataError(f"case contains a symlink: {candidate}")
        if candidate.is_file():
            files.append(
                {
                    "path": candidate.relative_to(path).as_posix(),
                    "sha256": _file_sha256(candidate),
                    "size": candidate.stat().st_size,
                }
            )
    if not files:
        raise PairMetadataError(f"case contains no files: {path}")
    return _digest(files)


def load_mapping_catalog(path: Path, control_ids: set[str]) -> MappingCatalog:
    """Loads the reviewed mapping catalog and rejects silent omissions."""
    try:
        payload = _read_json(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise MappingError(f"cannot read mapping catalog {path}: {exc}") from exc

    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != "iacsecbench-paired-verification-map-v1"
    ):
        raise MappingError("unsupported property mapping schema")

    verifier = payload.get("verifier")
    controls = payload.get("controls")
    if not isinstance(verifier, dict) or not isinstance(controls, dict):
        raise MappingError("mapping catalog must define verifier and controls objects")
    if set(controls) != control_ids:
        missing = sorted(control_ids - set(controls))
        extra = sorted(set(controls) - control_ids)
        raise MappingError(
            f"mapping controls differ from benchmark controls; missing={missing}, extra={extra}"
        )

    version = verifier.get("version")
    scanner_version = verifier.get("scanner_version")
    if version != "0.1.0b1" or scanner_version != "3.3.0":
        raise MappingError(
            "the mapping catalog must remain pinned to IaC-Guard-V 0.1.0b1 and Checkov 3.3.0"
        )

    mappings: dict[str, PropertyMapping] = {}
    for control_id in sorted(control_ids):
        raw = controls[control_id]
        if not isinstance(raw, dict):
            raise MappingError(f"mapping for {control_id} must be an object")
        semantic_mapping = raw.get("semantic_mapping")
        supported = raw.get("supported")
        property_ids = raw.get("property_ids")
        rationale = raw.get("rationale")
        reason_code = raw.get("reason_code", "")
        if not isinstance(semantic_mapping, str) or not isinstance(supported, bool):
            raise MappingError(f"mapping for {control_id} has invalid mapping fields")
        if not isinstance(property_ids, list) or not all(
            isinstance(item, str) for item in property_ids
        ):
            raise MappingError(f"mapping for {control_id} has invalid property_ids")
        if not isinstance(rationale, str) or not rationale.strip():
            raise MappingError(f"mapping for {control_id} requires a rationale")
        if supported and (semantic_mapping != "EXACT_SAME_PROPERTY" or not property_ids):
            raise MappingError(f"supported mapping for {control_id} must be exact and nonempty")
        if not supported and (not isinstance(reason_code, str) or not reason_code):
            raise MappingError(f"unsupported mapping for {control_id} requires a reason code")
        mapping = PropertyMapping(
            control_id=control_id,
            semantic_mapping=semantic_mapping,
            supported=supported,
            property_ids=tuple(property_ids),
            rationale=rationale,
            reason_code=reason_code,
        )
        _ = mapping.rules
        mappings[control_id] = mapping

    return MappingCatalog(
        verifier_version=version,
        scanner_version=scanner_version,
        mappings=mappings,
        sha256=_file_sha256(path),
    )


def derive_pairs(cases: list[Case], control_ids: set[str]) -> list[CanonicalPair]:
    """Derives canonical pairs from explicit benchmark metadata only."""
    grouped: defaultdict[str, list[Case]] = defaultdict(list)
    problems: list[str] = []

    for case in cases:
        pair_id = case.metadata.get("pair_id")
        variant = case.metadata.get("pair_variant")
        if not isinstance(pair_id, str) or not pair_id:
            problems.append(f"{case.case_id}: missing pair_id")
            continue
        if pair_id not in control_ids:
            problems.append(f"{case.case_id}: unknown pair_id {pair_id}")
            continue
        if variant not in {"vulnerable", "compliant"}:
            problems.append(f"{case.case_id}: invalid pair_variant {variant!r}")
            continue
        grouped[pair_id].append(case)

    pairs: list[CanonicalPair] = []
    for pair_id in sorted(control_ids):
        members = grouped.get(pair_id, [])
        vulnerable = [case for case in members if case.metadata.get("pair_variant") == "vulnerable"]
        compliant = [case for case in members if case.metadata.get("pair_variant") == "compliant"]
        if len(vulnerable) != 1:
            problems.append(f"{pair_id}: expected one vulnerable member, found {len(vulnerable)}")
            continue
        if len(compliant) != 1:
            problems.append(f"{pair_id}: expected one compliant member, found {len(compliant)}")
            continue

        before = vulnerable[0]
        after = compliant[0]
        for member in (before, after):
            if member.canonical_controls != [pair_id]:
                problems.append(
                    f"{member.case_id}: canonical_controls {member.canonical_controls!r} do not equal [{pair_id!r}]"
                )
        if before.expected != "VIOLATION" or after.expected != "COMPLIANT":
            problems.append(f"{pair_id}: pair variants do not match ground-truth labels")

        resources = sorted(set(before.expected_resources))
        if len(resources) != 1:
            problems.append(
                f"{pair_id}: expected one vulnerable target resource, found {resources!r}"
            )
            continue
        pairs.append(
            CanonicalPair(
                pair_id=pair_id,
                vulnerable=before,
                compliant=after,
                canonical_control=pair_id,
                expected_resource=resources[0],
            )
        )

    if problems:
        raise PairMetadataError("; ".join(problems))
    return pairs


def _pair_manifest_record(pair: CanonicalPair, mapping: PropertyMapping) -> dict[str, Any]:
    before_digest = _case_digest(pair.vulnerable.path)
    after_digest = _case_digest(pair.compliant.path)
    request = {
        "pair_id": pair.pair_id,
        "vulnerable_case_id": pair.vulnerable.case_id,
        "compliant_case_id": pair.compliant.case_id,
        "canonical_control": pair.canonical_control,
        "expected_resource": pair.expected_resource,
        "property_ids": list(mapping.property_ids),
        "vulnerable_input_sha256": before_digest,
        "compliant_input_sha256": after_digest,
    }
    return {
        **request,
        "semantic_mapping": mapping.semantic_mapping,
        "mapping_supported": mapping.supported,
        "mapping_reason_code": mapping.reason_code or None,
        "mapping_rationale": mapping.rationale,
        "request_digest": _digest(request),
    }


def build_manifest(pairs: list[CanonicalPair], catalog: MappingCatalog) -> dict[str, Any]:
    """Builds the deterministic pre-execution pair manifest."""
    records = [_pair_manifest_record(pair, catalog.mappings[pair.pair_id]) for pair in pairs]
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "tool_type": "paired_verifier",
        "tool": "iac-guard-v",
        "tool_version": catalog.verifier_version,
        "scanner_version": catalog.scanner_version,
        "mapping_sha256": catalog.sha256,
        "total_canonical_pairs": len(records),
        "exact_supported": sum(record["mapping_supported"] for record in records),
        "pairs": records,
    }
    manifest["manifest_sha256"] = _digest(manifest)
    return manifest


def write_json(path: Path, payload: Any) -> None:
    """Atomically writes stable, sorted JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "wb", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as handle:
        temp_path = Path(handle.name)
        handle.write(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True).encode())
        handle.write(b"\n")
    os.replace(temp_path, path)


def _resolve_executable(value: str | None) -> str | None:
    candidate = value or "iac-guard"
    if os.sep in candidate or (os.altsep and os.altsep in candidate):
        path = Path(candidate).expanduser().resolve()
        return str(path) if path.is_file() and os.access(path, os.X_OK) else None
    return shutil.which(candidate)


def _probe_version(executable: str) -> tuple[str | None, str | None]:
    try:
        completed = subprocess.run(
            [executable, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, str(exc)
    if completed.returncode != 0:
        return None, (completed.stderr or completed.stdout or "version probe failed").strip()
    output = (completed.stdout or completed.stderr).strip()
    match = re.search(r"(?<![0-9])([0-9]+\.[0-9]+\.[0-9]+(?:[a-z]+[0-9]+)?)(?![0-9])", output)
    return (match.group(1), None) if match else (None, f"unrecognized version output: {output}")


def _base_record(manifest_record: dict[str, Any], version: str | None) -> dict[str, Any]:
    return {
        "pair_id": manifest_record["pair_id"],
        "vulnerable_case_id": manifest_record["vulnerable_case_id"],
        "compliant_case_id": manifest_record["compliant_case_id"],
        "canonical_control": manifest_record["canonical_control"],
        "expected_resource": manifest_record["expected_resource"],
        "property_ids": manifest_record["property_ids"],
        "iac_guard_v_version": version,
        "request_digest": manifest_record["request_digest"],
    }


def _not_supported_record(
    manifest_record: dict[str, Any], version: str | None, reason_code: str
) -> dict[str, Any]:
    return {
        **_base_record(manifest_record, version),
        "vulnerable_evidence": None,
        "compliant_evidence": None,
        "transition_result": "NOT_SUPPORTED",
        "reason_code": reason_code,
        "witness_digest": None,
        "raw_report": None,
        "raw_report_sha256": None,
        "execution_error": False,
    }


def _target_evidence(
    payload: dict[str, Any], phase: str, rules: tuple[str, ...], target: str
) -> dict[str, Any]:
    verification = payload.get("verification") or {}
    run = verification.get(phase) or {}
    evaluations = run.get("evaluations") or []
    selected: list[dict[str, Any]] = []
    for item in evaluations:
        if (
            not isinstance(item, dict)
            or item.get("rule_id") not in rules
            or item.get("resource_address") != target
        ):
            continue
        selected.append(
            {
                "rule": item.get("rule_id"),
                "resource": item.get("resource_address"),
                "native_result": item.get("native_result"),
                "source_bucket": item.get("source_bucket"),
                "graph_status": (item.get("graph_evidence") or {}).get("status"),
                "graph_reason_code": (item.get("graph_evidence") or {}).get("reason_code"),
            }
        )
    selected.sort(key=lambda item: (str(item["rule"]), str(item["resource"])))
    return {"evaluations": selected, "evidence_digest": _digest(selected)}


def _collect_reason_codes(
    payload: dict[str, Any], rules: tuple[str, ...], target_resource: str
) -> list[str]:
    reasons: list[str] = []
    verification = payload.get("verification") or {}
    diagnostic = payload.get("diagnostic") or {}
    regression = verification.get("regression") or {}
    for candidate in (diagnostic.get("reason_code"), regression.get("reason_code")):
        if (
            isinstance(candidate, str)
            and candidate
            and candidate
            not in {
                "PASS",
                "NO_REGRESSION",
                "NO_DECISIVE_REGRESSION",
            }
        ):
            reasons.append(candidate)
    for phase in ("baseline_run", "candidate_run"):
        for evaluation in (verification.get(phase) or {}).get("evaluations") or []:
            if (
                not isinstance(evaluation, dict)
                or evaluation.get("rule_id") not in rules
                or evaluation.get("resource_address") != target_resource
            ):
                continue
            graph = evaluation.get("graph_evidence")
            candidate = graph.get("reason_code") if isinstance(graph, dict) else None
            if isinstance(candidate, str) and candidate and candidate != "GRAPH_EVIDENCE_COMPLETE":
                reasons.append(candidate)
    for target in verification.get("targets") or []:
        candidate = target.get("target_reason") if isinstance(target, dict) else None
        if isinstance(candidate, str) and candidate:
            reasons.append(candidate)
    for decision in (payload.get("policy") or {}).get("decisions") or []:
        candidate = decision.get("rejection_reason") if isinstance(decision, dict) else None
        if isinstance(candidate, str) and candidate:
            reasons.append(candidate)
    return reasons


def _execution_error_record(
    manifest_record: dict[str, Any], version: str | None, reason_code: str
) -> dict[str, Any]:
    record = _not_supported_record(manifest_record, version, reason_code)
    record["transition_result"] = "INCONCLUSIVE"
    record["execution_error"] = True
    return record


def normalize_verifier_result(
    completed: subprocess.CompletedProcess[str],
    raw_report: Path,
    raw_reference: str,
    manifest_record: dict[str, Any],
    mapping: PropertyMapping,
    version: str,
) -> dict[str, Any]:
    """Normalizes one public CLI result into the closed paired status model."""
    # Each early return corresponds to one fail-closed report boundary.
    # pylint: disable=too-many-return-statements
    base = _base_record(manifest_record, version)
    if completed.returncode == 2 and not raw_report.exists():
        try:
            error = json.loads(completed.stderr)
        except (TypeError, json.JSONDecodeError):
            return _execution_error_record(manifest_record, version, "MALFORMED_REQUEST_ERROR")
        if error.get("schema_version") == "request-error-v1":
            return {
                **base,
                "vulnerable_evidence": None,
                "compliant_evidence": None,
                "transition_result": "REQUEST_REJECTED",
                "reason_code": error.get("reason_code") or "REQUEST_REJECTED",
                "witness_digest": _digest(error),
                "raw_report": None,
                "raw_report_sha256": None,
                "execution_error": False,
            }

    if not raw_report.is_file():
        return _execution_error_record(manifest_record, version, "VERIFIER_REPORT_MISSING")
    try:
        payload = _read_json(raw_report)
    except (OSError, ValueError, json.JSONDecodeError):
        return _execution_error_record(manifest_record, version, "VERIFIER_REPORT_MALFORMED")
    if not isinstance(payload, dict) or payload.get("schema_version") != "report-v1":
        return _execution_error_record(manifest_record, version, "VERIFIER_REPORT_SCHEMA_INVALID")

    verdict = payload.get("verdict")
    report_exit = payload.get("exit_code")
    if verdict not in {"VERIFIED", "FAILED", "INCONCLUSIVE"} or report_exit != completed.returncode:
        return _execution_error_record(manifest_record, version, "VERIFIER_REPORT_INTEGRITY_ERROR")
    if payload.get("result_kind") not in {"verification", "operational_uncertainty"}:
        return _execution_error_record(manifest_record, version, "VERIFIER_RESULT_KIND_UNSUPPORTED")

    decisions = (payload.get("policy") or {}).get("decisions") or []
    if payload.get("result_kind") == "verification" and decisions:
        identities = {
            (item.get("identity") or {}).get("rule_id"): (item.get("identity") or {}).get("scope")
            for item in decisions
            if isinstance(item, dict)
        }
        if any(
            identities.get(rule) != manifest_record["expected_resource"] for rule in mapping.rules
        ):
            return _execution_error_record(
                manifest_record, version, "VERIFIER_TARGET_BINDING_MISMATCH"
            )

    vulnerable = _target_evidence(
        payload, "baseline_run", mapping.rules, manifest_record["expected_resource"]
    )
    compliant = _target_evidence(
        payload, "candidate_run", mapping.rules, manifest_record["expected_resource"]
    )
    witness = {
        "decisions": decisions,
        "vulnerable_evidence": vulnerable,
        "compliant_evidence": compliant,
        "regression": (payload.get("verification") or {}).get("regression"),
        "diagnostic": payload.get("diagnostic"),
    }
    reasons = _collect_reason_codes(payload, mapping.rules, manifest_record["expected_resource"])
    if verdict == "VERIFIED":
        reason_code = "ALL_TARGETS_FIXED"
    elif reasons:
        reason_code = reasons[0]
    else:
        reason_code = f"VERIFIER_REPORTED_{verdict}"
    return {
        **base,
        "vulnerable_evidence": vulnerable,
        "compliant_evidence": compliant,
        "transition_result": verdict,
        "reason_code": reason_code,
        "witness_digest": _digest(witness),
        "raw_report": raw_reference,
        "raw_report_sha256": _file_sha256(raw_report),
        "execution_error": False,
    }


def _run_pair(
    pair: CanonicalPair,
    manifest_record: dict[str, Any],
    mapping: PropertyMapping,
    executable: str,
    checkov: str | None,
    raw_report: Path,
    raw_reference: str,
    version: str,
) -> dict[str, Any]:
    raw_report.unlink(missing_ok=True)
    command = [
        executable,
        "verify",
        "--before",
        str(pair.vulnerable.path),
        "--after",
        str(pair.compliant.path),
        "--framework",
        "terraform",
        "--local-trusted",
        "--format",
        "json",
        "--output",
        str(raw_report),
        "--quiet",
    ]
    if checkov:
        command.extend(["--checkov-executable", checkov])
    for rule in mapping.rules:
        command.extend(["--target", f"{rule}={pair.expected_resource}"])
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=900,
            cwd=ROOT,
        )
    except subprocess.TimeoutExpired:
        return _execution_error_record(manifest_record, version, "VERIFIER_TIMEOUT")
    except OSError:
        return _execution_error_record(manifest_record, version, "VERIFIER_EXECUTION_FAILED")
    return normalize_verifier_result(
        completed, raw_report, raw_reference, manifest_record, mapping, version
    )


def run_verification(
    pairs: list[CanonicalPair],
    catalog: MappingCatalog,
    manifest: dict[str, Any],
    executable: str | None,
    checkov: str | None,
    output: Path,
) -> dict[str, Any]:
    """Runs supported pairs, while keeping unavailable tools non-fatal."""
    version: str | None = None
    availability_reason: str | None = None
    if executable is None:
        availability_reason = "VERIFIER_UNAVAILABLE"
    else:
        version, probe_error = _probe_version(executable)
        if probe_error:
            availability_reason = "VERIFIER_VERSION_UNAVAILABLE"
        elif version != catalog.verifier_version:
            availability_reason = "VERIFIER_VERSION_MISMATCH"

    checkov_path = _resolve_executable(checkov) if checkov else None
    if checkov and not checkov_path:
        availability_reason = "CHECKOV_UNAVAILABLE"

    pair_by_id = {pair.pair_id: pair for pair in pairs}
    raw_dir = output.with_suffix("").with_name(f"{output.stem}_raw")
    records: list[dict[str, Any]] = []
    for manifest_record in manifest["pairs"]:
        mapping = catalog.mappings[manifest_record["pair_id"]]
        if not mapping.supported:
            records.append(
                _not_supported_record(
                    manifest_record, version, mapping.reason_code or "PROPERTY_NOT_SUPPORTED"
                )
            )
            continue
        if availability_reason:
            records.append(_not_supported_record(manifest_record, version, availability_reason))
            continue
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_report = raw_dir / f"{manifest_record['pair_id']}.json"
        raw_reference = f"{raw_dir.name}/{raw_report.name}"
        records.append(
            _run_pair(
                pair_by_id[manifest_record["pair_id"]],
                manifest_record,
                mapping,
                executable,
                checkov_path,
                raw_report,
                raw_reference,
                version or catalog.verifier_version,
            )
        )

    counts = Counter(record["transition_result"] for record in records)
    result = {
        "schema_version": RESULT_SCHEMA,
        "tool_type": "paired_verifier",
        "tool": {
            "name": "iac-guard-v",
            "version": version,
            "required_version": catalog.verifier_version,
            "available": availability_reason is None,
            "availability_reason": availability_reason,
        },
        "pair_manifest_sha256": manifest["manifest_sha256"],
        "mapping_sha256": catalog.sha256,
        "summary": {
            "total_canonical_pairs": len(records),
            "exact_supported": manifest["exact_supported"],
            **{status: counts[status] for status in sorted(VALID_STATUSES)},
            "execution_errors": sum(bool(record["execution_error"]) for record in records),
        },
        "records": records,
    }
    return result


def _load_inputs() -> tuple[list[CanonicalPair], MappingCatalog, dict[str, Any]]:
    control_map = ControlMap.load()
    control_ids = set(control_map.controls)
    catalog = load_mapping_catalog(DEFAULT_MAP, control_ids)
    pairs = derive_pairs(load_internal(control_map), control_ids)
    manifest = build_manifest(pairs, catalog)
    return pairs, catalog, manifest


def _output_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iac-guard", help="IaC-Guard-V executable path or command name")
    parser.add_argument("--checkov", help="Optional exact Checkov executable path or command name")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Output JSON path")
    parser.add_argument(
        "--manifest-only", action="store_true", help="Write the frozen pair manifest only"
    )
    parser.add_argument(
        "--list-supported", action="store_true", help="List reviewed control mappings and exit"
    )
    args = parser.parse_args(argv)

    try:
        pairs, catalog, manifest = _load_inputs()
    except (MappingError, PairMetadataError, OSError, ValueError) as exc:
        print(json.dumps({"error": type(exc).__name__, "detail": str(exc)}), file=sys.stderr)
        return 2

    if args.list_supported:
        for pair in pairs:
            mapping = catalog.mappings[pair.pair_id]
            status = "SUPPORTED" if mapping.supported else "NOT_SUPPORTED"
            properties = ",".join(mapping.property_ids) or "none"
            print(f"{pair.pair_id}\t{status}\t{properties}")
        return 0

    output = _output_path(args.output)
    if args.manifest_only:
        write_json(output, manifest)
        return 0

    executable = _resolve_executable(args.iac_guard)
    result = run_verification(pairs, catalog, manifest, executable, args.checkov, output)
    write_json(output, result)
    return 1 if result["summary"]["execution_errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
