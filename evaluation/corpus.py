"""IaCSecBench — benchmark corpus loading and validation.

A case is only admissible if it satisfies the inclusion criteria the manuscript
states: it must be syntactically valid HCL2, must reference resource types that
exist in the declared provider, must carry an unambiguous ground-truth label,
and must map to at least one canonical control so that a tool's finding can be
credited or not on principled grounds.

This module enforces those criteria mechanically and reports every case that
fails, rather than assuming the declared corpus size is the usable corpus size.
Run::

    python -m evaluation.corpus --report
    python -m evaluation.corpus --report --mode terraform   # authoritative

The ``terraform`` mode runs ``terraform init -backend=false`` and
``terraform validate`` per case. It requires network access on first use to
fetch provider schemas, and it is the only mode that detects a case referencing
a resource type the provider does not define.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from evaluation.tfenv import ensure_provider_mirror, init_args, terraform_env

ROOT = Path(__file__).resolve().parent.parent
INTERNAL_CASES = ROOT / "benchmark" / "internal" / "cases"
EXTERNAL_ROOT = ROOT / "benchmark" / "external"

RESOURCE_RE = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"', re.MULTILINE)
DATA_RE = re.compile(r'^\s*data\s+"([^"]+)"\s+"([^"]+)"', re.MULTILINE)
VARIABLE_RE = re.compile(r'^\s*variable\s+"([^"]+)"', re.MULTILINE)
MODULE_RE = re.compile(r'^\s*module\s+"([^"]+)"', re.MULTILINE)

__all__ = ["Case", "CaseStatus", "ValidationResult", "load_corpus", "validate_corpus"]


def _display_path(path: Path) -> str:
    """Repo-relative when possible, absolute otherwise.

    ``Path.relative_to`` raises for paths outside the repository, so a
    ``--json`` target elsewhere on disk must not be forced through it.
    """
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


class CaseStatus(str, Enum):
    """Admissibility status of a benchmark case."""

    OK = "ok"
    MISSING_CONFIG = "missing_config"
    NO_GROUND_TRUTH = "no_ground_truth"
    NO_CANONICAL_CONTROL = "no_canonical_control"
    AMBIGUOUS_CONTROL = "ambiguous_control"
    INVALID_HCL = "invalid_hcl"
    UNKNOWN_RESOURCE_TYPE = "unknown_resource_type"
    NO_RESOURCES = "no_resources"


@dataclass
class Case:
    """One benchmark case."""

    case_id: str
    path: Path
    collection: Literal["internal", "external"]
    subset: str
    domain: str
    expected: Literal["VIOLATION", "COMPLIANT"]
    canonical_controls: list[str] = field(default_factory=list)
    expected_resources: list[str] = field(default_factory=list)
    cis_control: str = ""
    severity: str = "UNKNOWN"
    metadata: dict[str, Any] = field(default_factory=dict)

    # Structural statistics, populated by :func:`measure_complexity`.
    n_resources: int = 0
    n_variables: int = 0
    n_modules: int = 0
    n_data_sources: int = 0
    sloc: int = 0
    resource_types: list[str] = field(default_factory=list)

    @property
    def tf_files(self) -> list[Path]:
        return sorted(self.path.glob("*.tf"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "path": str(self.path.relative_to(ROOT)),
            "collection": self.collection,
            "subset": self.subset,
            "domain": self.domain,
            "expected": self.expected,
            "canonical_controls": self.canonical_controls,
            "expected_resources": self.expected_resources,
            "cis_control": self.cis_control,
            "severity": self.severity,
            "n_resources": self.n_resources,
            "n_variables": self.n_variables,
            "n_modules": self.n_modules,
            "n_data_sources": self.n_data_sources,
            "sloc": self.sloc,
            "resource_types": self.resource_types,
        }


@dataclass
class ValidationResult:
    """Admissibility verdict for one case."""

    case_id: str
    status: CaseStatus
    detail: str = ""

    @property
    def admissible(self) -> bool:
        return self.status is CaseStatus.OK

    def to_dict(self) -> dict[str, Any]:
        return {"case_id": self.case_id, "status": self.status.value, "detail": self.detail}


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #


def _expected_from_metadata(metadata: dict[str, Any]) -> str | None:
    """Derives the ground-truth label, requiring the sources to agree.

    Cases historically carried both ``expected_result`` (FAIL/PASS) and
    ``has_violation`` (bool). If both are present and contradict each other the
    case has no usable label and is rejected rather than resolved by precedence.
    """
    result = metadata.get("expected_result")
    has_violation = metadata.get("has_violation")

    from_result: str | None = None
    if result in ("FAIL", "VIOLATION"):
        from_result = "VIOLATION"
    elif result in ("PASS", "COMPLIANT"):
        from_result = "COMPLIANT"

    from_flag: str | None = None
    if isinstance(has_violation, bool):
        from_flag = "VIOLATION" if has_violation else "COMPLIANT"

    if from_result and from_flag and from_result != from_flag:
        return None
    return from_result or from_flag


def _canonical_controls(metadata: dict[str, Any], control_map: Any | None) -> list[str]:
    """Resolves a case's canonical control identifiers.

    Resolution order:

    1. An explicit ``canonical_controls`` list in the case metadata. This is the
       only unambiguous source and is what new cases should carry.
    2. Inference from ``cis_control`` by matching the ``cis_aws`` field of the
       control map. Inference is best-effort: a CIS control number can map to
       several canonical controls, and a case that resolves this way should be
       reviewed before its result is reported.

    Returns an empty list when neither succeeds, which marks the case
    inadmissible for control-level scoring.
    """
    explicit = metadata.get("canonical_controls")
    if isinstance(explicit, list) and explicit:
        return [str(c) for c in explicit]

    if control_map is None:
        return []

    cis = str(metadata.get("cis_control") or metadata.get("control") or "").strip()
    if not cis:
        return []

    # Prefix matching is bidirectional: a case annotated "2.1" and a control
    # annotated "2.1.5" refer to the same section at different granularities.
    matches = []
    for control_id, spec in control_map.controls.items():
        spec_cis = str(spec.get("cis_aws", "")).strip()
        if not spec_cis or spec_cis == "n/a":
            continue
        if cis == spec_cis or cis.startswith(f"{spec_cis}.") or spec_cis.startswith(f"{cis}."):
            matches.append(control_id)
    return sorted(matches)


def _expected_resources(metadata: dict[str, Any]) -> list[str]:
    resources: list[str] = []
    for violation in metadata.get("expected_violations") or []:
        if isinstance(violation, dict) and violation.get("resource"):
            resources.append(str(violation["resource"]))
    return resources


def _normalise_id(raw: str) -> str:
    """Reduces an identifier to alphanumerics for cross-format comparison.

    External manifests and filenames use different conventions for the same
    case: the CIS subset declares ``CIS-AWS-2.1`` while the corresponding file is
    ``cis_2_1_s3_public.tf``. Normalising both to ``cisaws21`` / ``cis21s3public``
    lets the two be reconciled by prefix without hand-maintained aliases.
    """
    return re.sub(r"[^a-z0-9]", "", raw.lower())


def _control_digits(text: str) -> str:
    """Extracts the leading control number from an identifier.

    Tokens are split on separators and the leading run of purely numeric tokens
    is joined. Naive digit extraction is wrong here: ``cis_2_1_s3_public`` would
    yield ``213`` because ``s3`` contains a digit, so it would fail to reconcile
    with ``CIS-AWS-2.1``. Restricting to whole numeric tokens yields ``21`` for
    both.
    """
    tokens = re.split(r"[^A-Za-z0-9]+|(?<=[A-Za-z])(?=\d)", text)
    digits: list[str] = []
    seen_number = False
    for token in tokens:
        if not token:
            continue
        if token.isdigit():
            digits.append(token)
            seen_number = True
        elif seen_number:
            break
    return "".join(digits)


def _match_manifest_entry(filename_stem: str, by_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Reconciles a configuration filename with its manifest entry.

    Exact normalised match is preferred. Failing that, the leading control number
    is compared: ``cis_2_1_s3_public`` and ``CIS-AWS-2.1`` both reduce to ``21``.
    An ambiguous match resolves to no entry, so the case is reported as lacking
    ground truth rather than silently attributed to the wrong control.
    """
    key = _normalise_id(filename_stem)
    if key in by_id:
        return by_id[key]

    target = _control_digits(filename_stem)
    if not target:
        return {}

    candidates = [
        entry
        for norm, entry in by_id.items()
        if _control_digits(norm) and _control_digits(norm) == target
    ]
    return candidates[0] if len(candidates) == 1 else {}


def measure_complexity(case: Case) -> Case:
    """Populates structural statistics from the case's HCL sources."""
    resource_types: list[str] = []
    n_resources = n_variables = n_modules = n_data = sloc = 0

    for tf_file in case.tf_files:
        text = tf_file.read_text(encoding="utf-8", errors="replace")
        sloc += sum(
            1 for line in text.splitlines() if line.strip() and not line.strip().startswith("#")
        )
        found = RESOURCE_RE.findall(text)
        n_resources += len(found)
        resource_types.extend(rtype for rtype, _ in found)
        n_variables += len(VARIABLE_RE.findall(text))
        n_modules += len(MODULE_RE.findall(text))
        n_data += len(DATA_RE.findall(text))

    case.n_resources = n_resources
    case.n_variables = n_variables
    case.n_modules = n_modules
    case.n_data_sources = n_data
    case.sloc = sloc
    case.resource_types = sorted(set(resource_types))
    return case


def load_internal(control_map: Any | None = None) -> Iterator[Case]:
    """Loads the internal controlled corpus from on-disk case directories.

    Only directories that exist on disk are yielded. A catalogue entry without a
    corresponding directory is not a case; it is an unimplemented placeholder,
    and :func:`load_catalogue_gap` reports the difference.

    Args:
        control_map: Optional loaded control map, used to resolve each case's
            expected label. When omitted, labels are taken from metadata alone.

    Yields:
        One complexity-measured ``Case`` per internal case directory.
    """
    if not INTERNAL_CASES.is_dir():
        return

    for case_dir in sorted(p for p in INTERNAL_CASES.iterdir() if p.is_dir()):
        metadata_file = case_dir / "metadata.json"
        metadata: dict[str, Any] = {}
        if metadata_file.is_file():
            try:
                metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                metadata = {}

        expected_file = case_dir / "expected.json"
        if expected_file.is_file():
            try:
                expected_payload = json.loads(expected_file.read_text(encoding="utf-8"))
                metadata.setdefault("expected_result", expected_payload.get("expected_result"))
                if expected_payload.get("violations"):
                    metadata.setdefault("expected_violations", expected_payload["violations"])
            except json.JSONDecodeError:
                pass

        expected = _expected_from_metadata(metadata)
        case = Case(
            case_id=metadata.get("id") or case_dir.name,
            path=case_dir,
            collection="internal",
            subset="controlled",
            domain=str(metadata.get("benchmark_category") or case_dir.name.split("-")[0]),
            expected=expected or "COMPLIANT",
            canonical_controls=_canonical_controls(metadata, control_map),
            expected_resources=_expected_resources(metadata),
            cis_control=str(metadata.get("cis_control") or ""),
            severity=str(metadata.get("severity") or "UNKNOWN"),
            metadata={**metadata, "_label_resolved": expected is not None},
        )
        yield measure_complexity(case)


def load_external(control_map: Any | None = None) -> Iterator[Case]:
    """Loads external validation cases that have configuration on disk.

    A ``metadata.json`` entry describing a case with no corresponding ``.tf``
    file is not loaded. External datasets are declared by manifest but scored
    only on material that is present.

    Args:
        control_map: Optional loaded control map, used to resolve each case's
            expected label. When omitted, labels are taken from metadata alone.

    Yields:
        One complexity-measured ``Case`` per external ``.tf`` file found.

    Raises:
        ValueError: If two cases share a directory. A case is scanned as a
            directory, so siblings would be one observation counted twice.
    """
    if not EXTERNAL_ROOT.is_dir():
        return

    for subset_dir in sorted(p for p in EXTERNAL_ROOT.iterdir() if p.is_dir()):
        manifest_file = subset_dir / "metadata.json"
        manifest: dict[str, Any] = {}
        if manifest_file.is_file():
            try:
                manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                manifest = {}

        by_id: dict[str, dict[str, Any]] = {}
        for entry in manifest.get("cases") or []:
            if not isinstance(entry, dict):
                continue
            raw_id = str(entry.get("id") or entry.get("name") or "")
            if raw_id:
                by_id[_normalise_id(raw_id)] = entry

        for tf_file in sorted(subset_dir.rglob("*.tf")):
            case_id = tf_file.stem
            entry = _match_manifest_entry(case_id, by_id)

            # A case is scanned as a directory, not as a file, so two cases sharing
            # a directory are not two observations -- they are one scan scored twice.
            # These four CIS examples originally sat side by side in a single
            # directory, and every tool consequently returned a byte-identical
            # finding set for all four: identical input, four rows in the confusion
            # matrix, four contributions to a denominator that should have counted
            # one. That does not merely add noise, it narrows the confidence
            # intervals, because interval width is driven by the count of
            # independent observations. Each external configuration now lives in its
            # own directory; the guard below refuses to load a corpus that
            # reintroduces the collision rather than scoring it.
            siblings = sorted(p.name for p in tf_file.parent.glob("*.tf"))
            if len(siblings) > 1:
                raise ValueError(
                    f"external case {subset_dir.name}/{case_id} shares its directory "
                    f"{_display_path(tf_file.parent)} with {len(siblings) - 1} other "
                    f"configuration(s): {siblings}.\n"
                    "Every tool would receive identical input for each of these cases "
                    "and produce identical findings, so they would be counted as "
                    "independent observations while being one. Give each "
                    "configuration its own directory."
                )
            expected = _expected_from_metadata(entry) or (
                "VIOLATION" if entry.get("expected") == "VIOLATION" else None
            )

            case = Case(
                case_id=f"{subset_dir.name}/{case_id}",
                path=tf_file.parent,
                collection="external",
                subset=subset_dir.name,
                domain=str(entry.get("domain") or entry.get("category") or "unknown"),
                expected=expected or "COMPLIANT",
                canonical_controls=_canonical_controls(entry, control_map),
                expected_resources=_expected_resources(entry),
                cis_control=str(entry.get("control") or entry.get("cis_control") or ""),
                severity=str(entry.get("severity") or "UNKNOWN"),
                metadata={
                    **entry,
                    "_label_resolved": expected is not None,
                    "_single_file": str(tf_file.relative_to(ROOT)),
                },
            )
            yield measure_complexity(case)


def load_catalogue_gap() -> dict[str, Any]:
    """Compares the declared catalogue against cases that exist on disk.

    The manuscript's corpus size must be the number of cases that exist and are
    admissible, not the number of entries in ``benchmark.json``. This function
    quantifies the difference so the discrepancy cannot be reported by accident.
    """
    catalogue_file = ROOT / "benchmark" / "benchmark.json"
    declared_ids: set[str] = set()
    if catalogue_file.is_file():
        try:
            payload = json.loads(catalogue_file.read_text(encoding="utf-8"))
            declared_ids = {
                str(case.get("id")) for case in payload.get("test_cases") or [] if case.get("id")
            }
        except json.JSONDecodeError:
            pass

    on_disk = (
        {p.name for p in INTERNAL_CASES.iterdir() if p.is_dir()}
        if INTERNAL_CASES.is_dir()
        else set()
    )

    external_declared = 0
    external_on_disk = 0
    if EXTERNAL_ROOT.is_dir():
        for subset_dir in sorted(p for p in EXTERNAL_ROOT.iterdir() if p.is_dir()):
            manifest = subset_dir / "metadata.json"
            if manifest.is_file():
                try:
                    payload = json.loads(manifest.read_text(encoding="utf-8"))
                    external_declared += int(payload.get("total_cases") or 0)
                except json.JSONDecodeError:
                    pass
            external_on_disk += len(list(subset_dir.rglob("*.tf")))

    return {
        "internal_declared": len(declared_ids),
        "internal_on_disk": len(on_disk),
        "internal_missing": sorted(declared_ids - on_disk),
        "external_declared": external_declared,
        "external_on_disk": external_on_disk,
    }


def load_corpus(control_map: Any | None = None, include_external: bool = True) -> list[Case]:
    """Loads every case present on disk."""
    cases = list(load_internal(control_map))
    if include_external:
        cases.extend(load_external(control_map))
    return cases


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


def _validate_structural(case: Case) -> ValidationResult:
    if not case.tf_files:
        return ValidationResult(case.case_id, CaseStatus.MISSING_CONFIG, "no .tf files present")
    if not case.metadata.get("_label_resolved"):
        return ValidationResult(
            case.case_id,
            CaseStatus.NO_GROUND_TRUTH,
            "expected_result and has_violation absent or contradictory",
        )
    if case.n_resources == 0 and case.n_modules == 0:
        return ValidationResult(
            case.case_id, CaseStatus.NO_RESOURCES, "declares no resource or module blocks"
        )
    if not case.canonical_controls:
        return ValidationResult(
            case.case_id,
            CaseStatus.NO_CANONICAL_CONTROL,
            "no canonical_controls and cis_control did not resolve against the control map",
        )
    # A CIS section number can span several canonical controls: "2.1" covers
    # public access, encryption and logging. Inference cannot choose between
    # them, and guessing would silently decide what counts as a correct
    # detection. The case must carry an explicit canonical_controls list.
    if not metadata_has_explicit_controls(case) and len(case.canonical_controls) > 1:
        return ValidationResult(
            case.case_id,
            CaseStatus.AMBIGUOUS_CONTROL,
            f"CIS {case.cis_control} infers {len(case.canonical_controls)} controls "
            f"({', '.join(case.canonical_controls)}); add explicit canonical_controls",
        )
    return ValidationResult(case.case_id, CaseStatus.OK)


def metadata_has_explicit_controls(case: Case) -> bool:
    """True when the case declares ``canonical_controls`` rather than inferring them."""
    explicit = case.metadata.get("canonical_controls")
    return isinstance(explicit, list) and bool(explicit)


# Human-readable rejection reasons for the manuscript table.
STATUS_DESCRIPTIONS = {
    CaseStatus.OK: "Admitted",
    CaseStatus.MISSING_CONFIG: "No configuration present",
    CaseStatus.NO_GROUND_TRUTH: "Label absent or self-contradictory",
    CaseStatus.NO_CANONICAL_CONTROL: "No canonical control resolved",
    CaseStatus.AMBIGUOUS_CONTROL: "Control resolution ambiguous",
    CaseStatus.INVALID_HCL: "Configuration does not initialise or validate",
    CaseStatus.UNKNOWN_RESOURCE_TYPE: "References an undefined resource type",
    CaseStatus.NO_RESOURCES: "Declares no resource or module block",
}


def emit_admissibility_table(cases: list[Case], results: list[ValidationResult], mode: str) -> str:
    """Emits the corpus admissibility table for the manuscript.

    The table states the admissible count alongside every rejection reason. This
    is the corpus size that may be reported: a catalogue entry without
    configuration is not a case, and a case without a defensible label cannot
    contribute to a confusion matrix.
    """
    gap = load_catalogue_gap()
    counts: dict[CaseStatus, int] = {}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1

    admissible_ids = {r.case_id for r in results if r.admissible}
    usable = [c for c in cases if c.case_id in admissible_ids]
    n_violation = sum(1 for c in usable if c.expected == "VIOLATION")

    lines = [
        "% Generated by evaluation/corpus.py -- do not edit by hand.",
        "% Regenerate with: python -m evaluation.corpus --latex",
        f"% Validation mode: {mode}",
        "\\begin{table}[!t]",
        "\\caption{Corpus admissibility. The admissible count is the corpus size "
        "reported throughout; catalogue entries without configuration are not "
        "cases. The declared and present counts are given per collection because "
        "the two collections diverge by very different factors. Rejection "
        "reasons are determined mechanically by \\texttt{evaluation/corpus.py}.}",
        "\\label{tab:admissibility}",
        "\\centering",
        "\\small",
        "\\begin{tabularx}{\\linewidth}{X r r r}",
        "\\toprule",
        "\\textbf{Corpus status} & \\textbf{Internal} & \\textbf{External} & \\textbf{Total} \\\\",
        "\\midrule",
        # Split by collection. Reported only as a combined 520 against 48, the
        # table let a reader compute a single ratio of 10.8 and no more, while the
        # generalization argument turns on the external collection's own ratio of
        # 43.8 -- a number the table did not contain.
        f"Catalogue entries declared & {gap['internal_declared']} & "
        f"{gap['external_declared']} & "
        f"{gap['internal_declared'] + gap['external_declared']} \\\\",
        f"Configurations present on disk & {gap['internal_on_disk']} & "
        f"{gap['external_on_disk']} & {len(cases)} \\\\",
        "\\midrule",
    ]

    # Rejections and admissions are split by the same collection boundary as the
    # counts above, so every row of the table reads across consistently.
    collection_of = {case.case_id: case.collection for case in cases}

    def split(predicate: Any) -> tuple[int, int, int]:
        internal = sum(
            1
            for item in results
            if predicate(item) and collection_of.get(item.case_id) == "internal"
        )
        external = sum(
            1
            for item in results
            if predicate(item) and collection_of.get(item.case_id) == "external"
        )
        return internal, external, internal + external

    rejected_rows = 0
    for status in CaseStatus:
        count = counts.get(status, 0)
        if count == 0 or status is CaseStatus.OK:
            continue
        i, e, t = split(lambda r, s=status: r.status is s)
        lines.append(
            f"\\quad rejected: {STATUS_DESCRIPTIONS[status].lower()} & {i} & {e} & {t} \\\\"
        )
        rejected_rows += 1
    # With nothing rejected the block would be empty and the two rules around it
    # would print as a doubled line. A zero row says the same thing legibly, and
    # "the gate rejected nothing" is a result the manuscript reports.
    if rejected_rows == 0:
        lines.append("Rejected & 0 & 0 & 0 \\\\")

    n_int = sum(1 for c in usable if c.collection == "internal")
    n_ext = len(usable) - n_int
    viol_int = sum(1 for c in usable if c.collection == "internal" and c.expected == "VIOLATION")
    viol_ext = n_violation - viol_int

    lines += [
        "\\midrule",
        f"\\textbf{{Admissible}} & \\textbf{{{n_int}}} & \\textbf{{{n_ext}}} & "
        f"\\textbf{{{len(usable)}}} \\\\",
        f"\\quad vulnerable & {viol_int} & {viol_ext} & {n_violation} \\\\",
        f"\\quad compliant baseline & {n_int - viol_int} & {n_ext - viol_ext} & "
        f"{len(usable) - n_violation} \\\\",
        "\\bottomrule",
        "\\end{tabularx}",
        "\\end{table}",
    ]
    return "\n".join(lines)


def _validate_terraform(case: Case, provider_mirror: Path) -> ValidationResult:
    """Runs ``terraform init -backend=false`` and ``terraform validate``.

    Executes in a scratch copy so that no ``.terraform`` directory or lock file
    is written into the corpus.
    """
    terraform = shutil.which("terraform")
    if terraform is None:
        return ValidationResult(case.case_id, CaseStatus.OK, "terraform not installed; skipped")

    with tempfile.TemporaryDirectory(prefix=f"iacsb-{case.case_id.replace('/', '_')}-") as tmp:
        workdir = Path(tmp) / "case"
        workdir.mkdir()
        for tf_file in case.tf_files:
            shutil.copy2(tf_file, workdir / tf_file.name)

        env = terraform_env()

        init = subprocess.run(
            [terraform, *init_args(provider_mirror)],
            cwd=workdir,
            capture_output=True,
            text=True,
            env=env,
            timeout=600,
            check=False,
        )
        if init.returncode != 0:
            return ValidationResult(
                case.case_id, CaseStatus.INVALID_HCL, _first_error(init.stderr or init.stdout)
            )

        validate = subprocess.run(
            [terraform, "validate", "-no-color", "-json"],
            cwd=workdir,
            capture_output=True,
            text=True,
            env=env,
            timeout=300,
            check=False,
        )
        if validate.returncode != 0:
            detail = _first_error(validate.stdout or validate.stderr)
            status = (
                CaseStatus.UNKNOWN_RESOURCE_TYPE
                if "Invalid resource type" in (validate.stdout + validate.stderr)
                else CaseStatus.INVALID_HCL
            )
            return ValidationResult(case.case_id, status, detail)

    return ValidationResult(case.case_id, CaseStatus.OK)


def _first_error(output: str) -> str:
    """Extracts a one-line summary from terraform output."""
    try:
        payload = json.loads(output)
        diagnostics = payload.get("diagnostics") or []
        if diagnostics:
            first = diagnostics[0]
            return f"{first.get('summary', '')}: {first.get('detail', '')}".strip()[:300]
    except json.JSONDecodeError:
        pass
    for line in output.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith(("-", "Initializing", "Finding", "Installing")):
            return stripped[:300]
    return output.strip()[:300] or "unspecified failure"


def validate_corpus(
    cases: list[Case], mode: Literal["structural", "terraform"] = "structural"
) -> list[ValidationResult]:
    """Validates every case, returning one result per case."""
    results: list[ValidationResult] = []
    # Populated once, then read concurrently. See evaluation/tfenv.py for why the
    # shared plugin cache is unusable here.
    provider_mirror = ensure_provider_mirror() if mode == "terraform" else None

    for case in cases:
        structural = _validate_structural(case)
        if mode == "structural" or not structural.admissible:
            results.append(structural)
            continue
        results.append(_validate_terraform(case, provider_mirror))
    return results


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _print_report(cases: list[Case], results: list[ValidationResult], mode: str) -> None:
    gap = load_catalogue_gap()
    by_status: dict[str, list[str]] = {}
    for result in results:
        by_status.setdefault(result.status.value, []).append(result.case_id)

    admissible = [r for r in results if r.admissible]
    internal = [c for c in cases if c.collection == "internal"]
    external = [c for c in cases if c.collection == "external"]
    admissible_ids = {r.case_id for r in admissible}

    print("=" * 74)
    print(f"IaCSecBench corpus report  (validation mode: {mode})")
    print("=" * 74)

    print("\nDeclared versus present")
    print("-" * 74)
    print(f"  internal catalogue entries in benchmark.json : {gap['internal_declared']}")
    print(f"  internal case directories on disk            : {gap['internal_on_disk']}")
    print(f"  internal entries with no directory           : {len(gap['internal_missing'])}")
    print(f"  external cases declared in manifests         : {gap['external_declared']}")
    print(f"  external .tf files on disk                   : {gap['external_on_disk']}")

    print("\nAdmissibility")
    print("-" * 74)
    print(
        f"  cases loaded      : {len(cases)}  (internal {len(internal)}, external {len(external)})"
    )
    print(f"  admissible        : {len(admissible)}")
    print(f"  inadmissible      : {len(results) - len(admissible)}")

    for status, ids in sorted(by_status.items()):
        if status == CaseStatus.OK.value:
            continue
        print(f"\n  {status}  ({len(ids)} cases)")
        detail_by_id = {r.case_id: r.detail for r in results if r.status.value == status}
        for case_id in ids[:8]:
            detail = detail_by_id.get(case_id, "")
            print(f"    {case_id:<28} {detail[:44]}")
        if len(ids) > 8:
            print(f"    ... and {len(ids) - 8} more")

    usable = [c for c in cases if c.case_id in admissible_ids]
    if usable:
        violations = sum(1 for c in usable if c.expected == "VIOLATION")
        print("\nUsable corpus composition")
        print("-" * 74)
        print(f"  admissible cases  : {len(usable)}")
        print(f"  vulnerable        : {violations}")
        print(f"  secure baseline   : {len(usable) - violations}")
        domains: dict[str, int] = {}
        for case in usable:
            domains[case.domain] = domains.get(case.domain, 0) + 1
        print(f"  domains           : {len(domains)}")

    print("\n" + "=" * 74)
    if len(admissible) < len(cases):
        print("The admissible count above is the corpus size that may be reported.")
    if mode == "structural":
        print("Structural mode cannot detect invalid resource types.")
        print("Re-run with --mode terraform for an authoritative verdict.")
    print("=" * 74)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="IaCSecBench corpus loader and validator")
    parser.add_argument(
        "--report", action="store_true", help="print the corpus admissibility report"
    )
    parser.add_argument(
        "--mode",
        choices=("structural", "terraform"),
        default="structural",
        help="structural is offline; terraform runs init+validate per case",
    )
    parser.add_argument("--no-external", action="store_true", help="internal corpus only")
    parser.add_argument("--json", type=Path, help="write the machine-readable report to this path")
    parser.add_argument(
        "--latex",
        action="store_true",
        help="write results/tables/corpus.tex for the manuscript",
    )
    parser.add_argument("--limit", type=int, help="validate at most N cases (for a quick check)")
    args = parser.parse_args(argv)

    try:
        from evaluation.normalize import ControlMap

        control_map = ControlMap.load()
    except Exception as exc:  # noqa: BLE001 - the report must still render
        print(
            f"warning: control map unavailable ({exc}); control resolution disabled",
            file=sys.stderr,
        )
        control_map = None

    cases = load_corpus(control_map, include_external=not args.no_external)
    if args.limit:
        cases = cases[: args.limit]
    results = validate_corpus(cases, mode=args.mode)

    if args.report or not (args.json or args.latex):
        _print_report(cases, results, args.mode)

    if args.latex:
        table_dir = ROOT / "results" / "tables"
        table_dir.mkdir(parents=True, exist_ok=True)
        # Exactly one trailing newline, matching evaluation/analyze.py. Whatever the
        # emitter ends with, the file on disk must be what pre-commit's
        # end-of-file-fixer would leave, or every regeneration shows up as a diff.
        (table_dir / "corpus.tex").write_text(
            emit_admissibility_table(cases, results, args.mode).rstrip("\n") + "\n",
            encoding="utf-8",
        )
        print(f"Wrote {(table_dir / 'corpus.tex').relative_to(ROOT)}")

    if args.json:
        payload = {
            "mode": args.mode,
            "catalogue_gap": load_catalogue_gap(),
            "cases": [c.to_dict() for c in cases],
            "validation": [r.to_dict() for r in results],
            "admissible_ids": sorted(r.case_id for r in results if r.admissible),
        }
        out_path = args.json if args.json.is_absolute() else (Path.cwd() / args.json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"\nWrote {_display_path(out_path)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
