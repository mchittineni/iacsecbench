"""Invariants the control map must satisfy for results to mean anything.

The control map mediates between the native rule identifiers a tool emits and the
canonical controls a benchmark case is authored against. Every defect in it moves
a measurement without looking like it moved anything: a mistyped identifier turns
a detection into a false negative, and an identifier no tool can emit turns an
uncovered control into an apparently covered one.

These tests check the properties that can be checked without running a scanner.
They are deliberately mechanical -- an assertion here is cheaper than re-reading
1,700 lines of JSON after every edit.
"""

# A test function's parameter deliberately shares the name of the fixture that
# supplies it -- that is how pytest resolves fixtures, so pylint's shadowing
# warning is inapplicable to every occurrence in this file.
# pylint: disable=redefined-outer-name

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from evaluation.normalize import PARSERS, ControlMap

ROOT = Path(__file__).resolve().parent.parent.parent
CONTROL_MAP = ROOT / "evaluation" / "control_map.json"
POLICY_DIR = ROOT / "security_framework" / "policies"
TFSEC_RAW = ROOT / "results" / "raw" / "tfsec"


@pytest.fixture(scope="module")
def control_map() -> ControlMap:
    return ControlMap.load(CONTROL_MAP)


def implemented_opa_rule_ids() -> set[str]:
    """The ``rule_id`` literals the Rego policy set can actually emit."""
    source = "".join(path.read_text(encoding="utf-8") for path in POLICY_DIR.glob("*.rego"))
    return set(re.findall(r'"rule_id":\s*"([a-z0-9_]+)"', source))


def observed_tfsec_avd_crosswalk() -> dict[str, set[str]]:
    """Maps each tfsec long identifier to the AVD numbers tfsec reported for it.

    tfsec emits both spellings in every result, so this correspondence is read off
    recorded output rather than asserted. It is the basis of the Trivy identifiers
    in the control map, because Trivy reports the same AVD numbers without the
    ``AVD-`` prefix.
    """
    crosswalk: dict[str, set[str]] = {}
    for path in sorted(TFSEC_RAW.glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        payload = record.get("payload", record)
        for result in (payload or {}).get("results") or []:
            long_id, rule_id = result.get("long_id"), result.get("rule_id")
            if long_id and rule_id:
                crosswalk.setdefault(long_id, set()).add(rule_id.removeprefix("AVD-"))
    return crosswalk


@pytest.mark.skipif(not TFSEC_RAW.is_dir(), reason="no recorded tfsec output to derive from")
def test_trivy_identifiers_agree_with_the_tfsec_crosswalk(control_map: ControlMap) -> None:
    """Every Trivy identifier must be one tfsec reported for the same control.

    Trivy inherited tfsec's rule set, so its identifiers are derivable rather than
    a matter of judgement. Deriving them removes the failure mode that matters
    here: an identifier chosen by looking at what Trivy emitted on a case would
    fit the map to the tool and manufacture a detection. This test re-runs the
    derivation and fails if the file has drifted from it in either direction --
    an invented identifier, or one dropped after tfsec stopped reporting it.
    """
    crosswalk = observed_tfsec_avd_crosswalk()
    invented: dict[str, list[str]] = {}
    for control_id, spec in control_map.controls.items():
        tools = spec.get("tools", {})
        derivable = {avd for lid in tools.get("tfsec", []) for avd in crosswalk.get(lid, set())}
        claimed = set(tools.get("trivy", []))
        extra = sorted(claimed - derivable)
        if extra:
            invented[control_id] = extra
    assert not invented, (
        "trivy identifiers not derivable from tfsec's recorded output "
        f"(each must be an AVD number tfsec reported for the same control): {invented}"
    )


def test_opa_identifiers_are_all_implemented(control_map: ControlMap) -> None:
    """No control may claim an OPA rule the policy set does not define.

    This is the direction of error that flatters the reference implementation:
    a phantom identifier cannot cause a false detection, because nothing emits
    it, but it inflates the count of controls the plan-level layer appears to
    cover. Seven such identifiers were removed from this file once; the test
    exists so they cannot drift back in unnoticed.
    """
    implemented = implemented_opa_rule_ids()
    assert implemented, "no rule_id literals found -- the policy set or this regex changed"

    phantom = {
        control_id: sorted(set(spec.get("tools", {}).get("opa") or []) - implemented)
        for control_id, spec in control_map.controls.items()
    }
    phantom = {cid: rules for cid, rules in phantom.items() if rules}
    assert not phantom, (
        "control map names OPA rules absent from security_framework/policies/*.rego: "
        f"{phantom}. Either implement the rule or drop the mapping -- do not leave a "
        "control looking covered when it is not."
    )


def test_every_tool_key_is_a_known_parser(control_map: ControlMap) -> None:
    """A tool key with no parser silently maps nothing.

    Findings are keyed by tool name, so an entry under a misspelled or removed
    tool is unreachable: the rules never match, and the affected controls score
    as undetected for a tool that was in fact never consulted.
    """
    known = set(PARSERS)
    unknown: dict[str, list[str]] = {}
    for control_id, spec in control_map.controls.items():
        extra = sorted(set(spec.get("tools", {})) - known)
        if extra:
            unknown[control_id] = extra
    assert not unknown, (
        f"control map references tools with no parser in evaluation/normalize.py: {unknown}. "
        f"Known tools: {sorted(known)}"
    )


def test_no_control_is_undetectable_by_every_tool(control_map: ControlMap) -> None:
    """A control no tool can report is not a control, it is a gap in the taxonomy.

    Such an entry scores every case citing it as a false negative for every tool
    at once, which reads as unanimous tool failure rather than as missing
    coverage. If a control genuinely has no detector yet, that belongs in the
    taxonomy documentation, not in the scoring map.
    """
    undetectable = sorted(
        control_id
        for control_id, spec in control_map.controls.items()
        if not any(spec.get("tools", {}).values())
    )
    assert not undetectable, (
        f"controls with no rule identifier for any tool: {undetectable}. "
        "Every case citing one scores as a miss for all tools simultaneously."
    )


def test_rule_identifiers_are_unique_within_a_tool(control_map: ControlMap) -> None:
    """The same identifier listed twice for one tool signals a copy-paste error."""
    duplicated: dict[str, dict[str, list[str]]] = {}
    for control_id, spec in control_map.controls.items():
        for tool, rules in spec.get("tools", {}).items():
            seen = {x for x in rules if rules.count(x) > 1}
            if seen:
                duplicated.setdefault(control_id, {})[tool] = sorted(seen)
    assert not duplicated, f"duplicate rule identifiers: {duplicated}"


def test_identifiers_carry_no_surrounding_whitespace() -> None:
    """Whitespace in an identifier makes it match nothing.

    ``controls_for`` strips before lookup, so a padded identifier still resolves
    at runtime and the defect stays invisible. It is caught here instead, where
    the fix is to correct the file rather than to rely on the reader.
    """
    payload = json.loads(CONTROL_MAP.read_text(encoding="utf-8"))
    padded: dict[str, list[str]] = {}
    for control_id, spec in payload["controls"].items():
        for tool, rules in spec.get("tools", {}).items():
            bad = [r for r in rules if r != r.strip() or not r]
            if bad:
                padded[f"{control_id}/{tool}"] = bad
    assert not padded, f"rule identifiers with stray whitespace or empty entries: {padded}"


def test_cis_citation_agrees_with_the_corpus_generator() -> None:
    """The map and the generator must cite the same control for the same ID.

    Ground truth is derived from the generator's per-control specification, while
    scoring and every human-readable label come from this map. If the two cite
    different CIS controls for one identifier, the corpus is testing one
    requirement and the results are described as another, and nothing in the
    pipeline would notice.

    This is the check that would have caught STO_UNENCRYPTED_BUCKET sooner. Its
    map text stated the CIS v1.4.0 2.1.1 requirement, which SSE-S3 satisfies, while its
    corpus labelled an AES256 bucket as violating -- a stricter,
    customer-managed-key requirement. Titles are deliberately not compared: the
    two files phrase controls neutrally and negatively by convention
    ("Key management rotation" against "Key management key lacks automatic
    rotation"), and 21 of 22 such differences are stylistic.
    """
    generator = (ROOT / "benchmark" / "generate_corpus.py").read_text(encoding="utf-8")
    cited = dict(
        re.findall(
            r'control_id="([A-Z0-9_]+)",\s*\n\s*domain="[^"]*",\s*\n\s*cis_control="([^"]*)"',
            generator,
        )
    )
    assert cited, "no ControlSpec entries parsed -- the generator's shape changed"

    control_map = ControlMap.load(CONTROL_MAP)
    conflicts = {}
    for control_id, generator_cis in cited.items():
        spec = control_map.controls.get(control_id)
        if spec is None:
            continue  # covered by the corpus loader, which rejects unknown controls
        map_cis = str(spec.get("cis_aws", ""))
        if map_cis != str(generator_cis):
            conflicts[control_id] = {"generator": generator_cis, "control_map": map_cis}
    assert not conflicts, (
        "generator and control map cite different CIS controls for the same "
        f"identifier: {conflicts}"
    )


def test_unverified_controls_are_reported_not_hidden(control_map: ControlMap) -> None:
    """The unverified set must stay introspectable.

    Results are qualified by how many entries remain unconfirmed against real
    tool output, so this list feeds a caveat printed alongside every run. A
    refactor that broke it would quietly drop the caveat, not the uncertainty.
    """
    unverified = control_map.unverified_controls
    assert isinstance(unverified, list)
    assert all(cid in control_map.controls for cid in unverified)
    for control_id in unverified:
        assert control_map.controls[control_id].get("verified") is not True


def test_every_control_has_a_case_exercising_it(control_map: ControlMap) -> None:
    """No control may sit in the map with nothing measuring it.

    Four controls previously had no case at all -- SRV_NO_API_AUTHORIZATION and the
    three K8S controls -- so every tool scored identically on them: not at all.
    A mapped control with no case is a claim the benchmark never tests, and it is
    invisible in the results because an absent case produces no row.
    """
    import benchmark.generate_corpus as generator

    specified = {spec.control_id for spec in generator.SPECS}
    orphaned = sorted(set(control_map.controls) - specified)
    assert not orphaned, f"controls with no case pair specified: {orphaned}"


def test_inapplicable_tools_carry_a_reason_and_no_identifiers(
    control_map: ControlMap,
) -> None:
    """A tool declared out of scope must not also claim rules for the control.

    Listing both would let the control be credited to a tool the same file says
    cannot see it, and `coverage()` would count it -- overstating that tool's
    breadth by exactly the controls it is documented not to read.
    """
    for control_id, spec in control_map.controls.items():
        inapplicable = spec.get("inapplicable_tools") or []
        if not inapplicable:
            continue
        assert spec.get("inapplicable_reason"), f"{control_id}: no reason recorded"
        for tool in inapplicable:
            claimed = spec.get("tools", {}).get(tool) or []
            assert not claimed, (
                f"{control_id}: {tool} is declared inapplicable but still claims {claimed}"
            )


def test_controls_verified_by_measurement_record_their_evidence(
    control_map: ControlMap,
) -> None:
    """The controls confirmed against real tool output must say what confirmed it.

    `verified: true` with no evidence is indistinguishable from an unreviewed
    default, which is how an unverified mapping becomes a published one. These six
    were flipped from false after their identifiers were observed firing, so each
    must carry the observation that justified the flip.
    """
    confirmed_by_measurement = [
        "SRV_NO_API_AUTHORIZATION",
        "K8S_PRIVILEGED_CONTAINER",
        "K8S_ROOT_CONTAINER",
        "K8S_NO_RESOURCE_LIMITS",
        "ENC_UNENCRYPTED_VOLUME",
        "NET_UNRESTRICTED_INGRESS",
    ]
    for control_id in confirmed_by_measurement:
        spec = control_map.controls[control_id]
        assert spec.get("verified") is True, f"{control_id} is no longer verified"
        assert spec.get("verification"), f"{control_id}: verified with no evidence recorded"


def test_controls_still_unverified_say_why(control_map: ControlMap) -> None:
    """An unverified control must record what was observed instead.

    Both survivors are genuine comparator gaps rather than mapping errors, and one
    of them -- SEC_HARDCODED_CREDENTIAL, which only the reference pipeline's Layer 1
    detects -- flatters the reference. An unexplained `verified: false` hides that.
    """
    for control_id in control_map.unverified_controls:
        assert control_map.controls[control_id].get("verification"), (
            f"{control_id}: unverified with no explanation of what was observed"
        )
