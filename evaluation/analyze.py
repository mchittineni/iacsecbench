"""IaCSecBench — analysis and LaTeX table generation.

Consumes the raw tool output written by :mod:`evaluation.run_baselines`, applies
the finding-normalization engine, and produces:

* ``results/evaluation.json`` — the complete machine-readable result set;
* ``results/tables/*.tex``    — LaTeX tables ready for \\input into the manuscript;
* a console summary.

Reporting guarantees
--------------------
Metrics that are not estimable from the available corpus are reported as such
rather than as zero. Specificity requires ground-truth-compliant cases; MCC
requires both classes. A corpus consisting only of vulnerable cases supports a
recall estimate and nothing else, and the output says so explicitly instead of
printing a specificity of 0.00% that a reader would mistake for a measurement.

Tools that were not installed are listed as ``not_run`` and omitted from every
table. They are never assigned an assumed detection rate.

Every proportion is accompanied by an exact Clopper-Pearson interval, and every
pairwise comparison against the reference tool uses the exact binomial McNemar
test with Holm-Bonferroni correction across the tool family.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evaluation.corpus import Case, load_corpus
from evaluation.normalize import MATCH_LEVELS, ControlMap, MatchLevel, score_case
from evaluation.stats import (
    ConfusionMatrix,
    exact_mcnemar,
    holm_bonferroni,
    minimum_detectable_discordance,
)
from evaluation.tables import (
    NOT_ESTIMABLE,
    TOOL_LABELS,
    emit_allpairs_table,
    emit_latency_table,
    emit_layer_table,
    emit_mcnemar_table,
    emit_performance_table,
    emit_rates_table,
    emit_strictness_table,
    latex_defects,
)

ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "results" / "raw"
MANIFEST = ROOT / "results" / "run_manifest.json"
OUT_JSON = ROOT / "results" / "evaluation.json"
TABLE_DIR = ROOT / "results" / "tables"
LEADERBOARD_CSV = ROOT / "leaderboard" / "results.csv"

REFERENCE_TOOL = "opa"


@dataclass
class ToolResult:
    """Aggregated result for one tool at one strictness level."""

    tool: str
    level: MatchLevel
    matrix: ConfusionMatrix
    outcomes: dict[str, str]
    latencies_ms: list[float]
    n_errors: int
    n_unmapped: int
    n_unmapped_on_missed: int = 0
    n_resource_applicable: int = 0

    @property
    def specificity_estimable(self) -> bool:
        return self.matrix.negatives > 0

    @property
    def mcc_estimable(self) -> bool:
        return self.matrix.positives > 0 and self.matrix.negatives > 0

    def latency_summary(self) -> dict[str, float | None]:
        if not self.latencies_ms:
            return {"mean_ms": None, "sd_ms": None, "n": 0}
        return {
            "mean_ms": statistics.fmean(self.latencies_ms),
            "sd_ms": statistics.stdev(self.latencies_ms) if len(self.latencies_ms) > 1 else 0.0,
            "n": len(self.latencies_ms),
        }

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "tool": self.tool,
            "level": self.level,
            "confusion_matrix": self.matrix.to_dict(),
            "latency": self.latency_summary(),
            "n_execution_errors": self.n_errors,
            "n_unmapped_findings": self.n_unmapped,
            "n_unmapped_findings_on_missed_cases": self.n_unmapped_on_missed,
            "specificity_estimable": self.specificity_estimable,
            "mcc_estimable": self.mcc_estimable,
        }
        if not self.specificity_estimable:
            payload["confusion_matrix"]["specificity"] = None
            payload["confusion_matrix"]["balanced_accuracy"] = None
        if not self.mcc_estimable:
            payload["confusion_matrix"]["mcc"] = None
        return payload


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #


def _load_raw(tool: str, case_id: str) -> Any | None:
    path = RAW_DIR / tool / f"{case_id.replace('/', '__')}.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def aggregate(
    cases: list[Case], manifest: dict[str, Any], control_map: ControlMap
) -> tuple[dict[str, dict[MatchLevel, ToolResult]], dict[str, str]]:
    """Builds per-tool, per-level results plus a per-tool status map."""
    runs_by_key: dict[tuple[str, str], dict[str, Any]] = {
        (run["tool"], run["case_id"]): run for run in manifest.get("runs", [])
    }
    tools = sorted({run["tool"] for run in manifest.get("runs", [])})

    status: dict[str, str] = {}
    results: dict[str, dict[MatchLevel, ToolResult]] = {}

    for tool in tools:
        tool_runs = [
            runs_by_key[(tool, c.case_id)] for c in cases if (tool, c.case_id) in runs_by_key
        ]
        if tool_runs and all(r["status"] == "not_installed" for r in tool_runs):
            status[tool] = "not_run"
            continue
        status[tool] = "run"

        latencies: list[float] = []
        n_errors = 0
        n_unmapped = 0
        # Unmapped findings only understate a tool where the tool *missed* the
        # case. On a case it already detected, or on a compliant case, an
        # unmapped rule changes nothing -- it is a detection of some other
        # control on incidental infrastructure. Counting the two situations
        # together turns a large, harmless number into an alarming one, so they
        # are counted apart.
        n_unmapped_on_missed = 0
        level_key = "all"
        resource_applicable: dict[str, int] = {"all": 0}
        per_level: dict[MatchLevel, dict[str, str]] = {lvl: {} for lvl in MATCH_LEVELS}
        counts: dict[MatchLevel, dict[str, int]] = {
            lvl: {"TP": 0, "FP": 0, "TN": 0, "FN": 0} for lvl in MATCH_LEVELS
        }

        for case in cases:
            run = runs_by_key.get((tool, case.case_id))
            if run is None:
                continue
            if run["status"] != "ok":
                n_errors += 1
                continue
            latencies.extend(run.get("latency_ms") or [])

            outcome = score_case(
                case_id=case.case_id,
                tool=tool,
                expected=case.expected,  # type: ignore[arg-type]
                expected_controls=case.canonical_controls,
                expected_resources=case.expected_resources or case.resource_types,
                payload=_load_raw(tool, case.case_id),
                control_map=control_map,
            )
            n_unmapped += len(outcome.unmapped_rules)
            if outcome.classification("control") == "FN" and outcome.unmapped_rules:
                n_unmapped_on_missed += len(outcome.unmapped_rules)
            if outcome.resource_matching_applicable:
                resource_applicable[level_key] += 1
            for level in MATCH_LEVELS:
                # A case that names no resource address cannot be scored under the
                # resource criterion. Counting it as a miss there made every tool
                # look worse under resource than under control purely because the
                # external cases declare no address, which is an artefact of the
                # corpus rather than a property of any tool.
                if level == "resource" and not outcome.resource_matching_applicable:
                    continue
                label = outcome.classification(level)
                counts[level][label] += 1
                per_level[level][case.case_id] = label

        results[tool] = {
            level: ToolResult(
                tool=tool,
                level=level,
                matrix=ConfusionMatrix(
                    tp=counts[level]["TP"],
                    fp=counts[level]["FP"],
                    tn=counts[level]["TN"],
                    fn=counts[level]["FN"],
                ),
                outcomes=per_level[level],
                latencies_ms=latencies,
                n_errors=n_errors,
                n_unmapped=n_unmapped,
                n_unmapped_on_missed=n_unmapped_on_missed,
                n_resource_applicable=resource_applicable["all"],
            )
            for level in MATCH_LEVELS
        }

        # Every case that produced usable output must land in exactly one cell of
        # every level's matrix. ConfusionMatrix.assert_total existed to check
        # precisely this and was never called, so the invariant was documented
        # but not enforced. A case counted twice, or dropped between the scoring
        # loop and the matrix, would otherwise surface only as an interval that
        # is narrower than the evidence supports -- the same failure mode as the
        # shared-directory defect disclosed in the manuscript, and equally
        # invisible in aggregate.
        n_scored = sum(
            1
            for case in cases
            if (run := runs_by_key.get((tool, case.case_id))) is not None and run["status"] == "ok"
        )
        for level in MATCH_LEVELS:
            expected_total = resource_applicable["all"] if level == "resource" else n_scored
            results[tool][level].matrix.assert_total(expected_total)

    return results, status


def pairwise_comparisons(
    results: dict[str, dict[MatchLevel, ToolResult]],
    reference: str,
    level: MatchLevel,
) -> dict[str, Any]:
    """Exact McNemar comparisons of the reference tool against every other tool.

    Discordant counts include both error types: a case where the reference is
    correct and the comparator wrong contributes to ``b`` whether the
    comparator's error was a missed violation or a spurious finding.

    The corpus size is deliberately not a parameter. Each comparison's paired
    difference interval is computed over the cases the two tools actually share,
    which is narrower than the corpus whenever either tool errored on a case.
    Passing a corpus-wide ``n`` would overstate the pairing.
    """
    if reference not in results:
        return {"error": f"reference tool {reference!r} produced no results"}

    ref_outcomes = results[reference][level].outcomes
    comparisons: dict[str, Any] = {}
    raw_p: dict[str, float] = {}

    for tool, levels in results.items():
        if tool == reference:
            continue
        shared, b, c = _discordant(ref_outcomes, levels[level].outcomes)
        if not shared:
            continue

        result = exact_mcnemar(b, c, reference=reference, comparator=tool, n_total=len(shared))
        comparisons[tool] = result.to_dict()
        comparisons[tool]["n_paired_cases"] = len(shared)
        # What this comparison could have detected, recorded alongside what it did
        # detect. A non-significant exact test on few discordant pairs does not
        # distinguish similar tools from an underpowered comparison, and the
        # distinction is computable from b + c without further measurement.
        comparisons[tool]["min_detectable_discordance"] = minimum_detectable_discordance(b + c)
        raw_p[tool] = result.p_exact

    if raw_p:
        adjusted = holm_bonferroni(raw_p)
        for tool, entry in adjusted.items():
            comparisons[tool]["holm"] = entry

    return comparisons


def _discordant(first: dict[str, str], second: dict[str, str]) -> tuple[list[str], int, int]:
    """Discordant counts over the cases two tools share.

    ``b`` counts cases the first tool classifies correctly and the second does not;
    ``c`` is the converse. Both error types count: a comparator that emits a
    spurious finding on a compliant case is as wrong as one that misses a
    violation, and restricting the count to missed violations understates
    disagreement.
    """
    shared = sorted(set(first) & set(second))
    b = c = 0
    for case_id in shared:
        first_ok = first[case_id] in ("TP", "TN")
        second_ok = second[case_id] in ("TP", "TN")
        if first_ok and not second_ok:
            b += 1
        elif second_ok and not first_ok:
            c += 1
    return shared, b, c


def all_pairwise_comparisons(
    results: dict[str, dict[MatchLevel, ToolResult]],
    status: dict[str, str],
    level: MatchLevel,
) -> list[dict[str, Any]]:
    """Every unordered pair of tools, not just each tool against the reference.

    Comparing only against the reference leaves the comparison a practitioner most
    wants unmade: two third-party scanners against each other. It also puts the
    tool this paper contributes at the centre of every test, which is a choice a
    reader is entitled to see the alternative to.

    Holm--Bonferroni is applied across the whole set of pairs. The family is
    therefore larger than in :func:`pairwise_comparisons` and the correction
    correspondingly stronger; that is the honest cost of asking more questions of
    the same corpus, not a reason to ask fewer.
    """
    tools = sorted(t for t in results if status.get(t) == "run")
    rows: list[dict[str, Any]] = []
    raw_p: dict[str, float] = {}

    for i, left in enumerate(tools):
        for right in tools[i + 1 :]:
            shared, b, c = _discordant(
                results[left][level].outcomes, results[right][level].outcomes
            )
            if not shared:
                continue
            result = exact_mcnemar(b, c, reference=left, comparator=right, n_total=len(shared))
            key = f"{left}|{right}"
            row = result.to_dict()
            row["pair"] = key
            row["left"] = left
            row["right"] = right
            row["n_paired_cases"] = len(shared)
            row["min_detectable_discordance"] = minimum_detectable_discordance(b + c)
            rows.append(row)
            raw_p[key] = result.p_exact

    if raw_p:
        adjusted = holm_bonferroni(raw_p)
        by_key = {r["pair"]: r for r in rows}
        for key, entry in adjusted.items():
            by_key[key]["holm"] = entry

    return rows


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="IaCSecBench analysis and table generation")
    parser.add_argument(
        "--level",
        choices=MATCH_LEVELS,
        default="control",
        help="matching strictness for the headline tables",
    )
    parser.add_argument(
        "--reference", default=REFERENCE_TOOL, help="tool to compare all others against"
    )
    parser.add_argument("--no-tables", action="store_true", help="skip LaTeX emission")
    args = parser.parse_args(argv)

    if not MANIFEST.is_file():
        print(f"No run manifest at {MANIFEST.relative_to(ROOT)}.")
        print("Run: python -m evaluation.run_baselines --all")
        return 2

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    control_map = ControlMap.load()
    scanned = set(manifest.get("scanned_case_ids") or [])

    all_cases = load_corpus(control_map)
    cases = [c for c in all_cases if c.case_id in scanned]
    if not cases:
        print("The manifest references no cases that are currently loadable.")
        return 2

    results, status = aggregate(cases, manifest, control_map)
    if not any(s == "run" for s in status.values()):
        print("No tool produced usable output; nothing to analyse.")
        return 2

    n_positives = sum(1 for c in cases if c.expected == "VIOLATION")
    n_negatives = len(cases) - n_positives
    comparisons = pairwise_comparisons(results, args.reference, args.level)
    all_pairs = all_pairwise_comparisons(results, status, args.level)

    # ---- console summary -------------------------------------------------- #
    print("=" * 78)
    print(f"IaCSecBench evaluation  (matching level: {args.level})")
    print("=" * 78)
    env = manifest.get("environment", {})
    print(f"\nEnvironment : {env.get('platform')}  |  commit {str(env.get('git_commit'))[:12]}")
    print(f"Corpus      : {len(cases)} cases  ({n_positives} vulnerable, {n_negatives} compliant)")
    print(f"Repeats     : {manifest.get('repeats')} executions per tool-case")

    # Taken from the control map that scored these findings, not from the
    # manifest's snapshot. The manifest records the map as it stood when the
    # scanners ran, but scoring re-reads the file, so a map corrected after the
    # run would otherwise be reported with its pre-correction defect count --
    # overstating the caveat and understating the audit that removed it.
    unverified = sorted(control_map.unverified_controls)
    recorded = manifest.get("control_map_unverified") or []
    if unverified:
        print(f"\nWARNING: {len(unverified)} control-map entries are unverified.")
        print("         Results are provisional until they are confirmed.")
    if sorted(recorded) != unverified:
        print(
            f"\nNote: the control map was corrected after this run "
            f"({len(recorded)} unverified at scan time, {len(unverified)} now). "
            "Scoring used the corrected map; latency and tool versions still "
            "come from the recorded run."
        )

    if n_negatives == 0:
        print("\nWARNING: the corpus contains no compliant baseline cases.")
        print("         Specificity, balanced accuracy and MCC are not estimable.")
        print("         False-positive behaviour cannot be characterised at all.")

    print(
        f"\n{'tool':<18} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4}  "
        f"{'recall':>8}  {'recall 95% CI':>20}  {'latency':>14}"
    )
    print("-" * 78)
    for tool in sorted(results):
        if status.get(tool) != "run":
            continue
        r = results[tool][args.level]
        m = r.matrix
        ci = m.recall_ci().as_pct()
        lat = r.latency_summary()
        lat_cell = f"{lat['mean_ms']:.1f}±{lat['sd_ms']:.1f}" if lat["mean_ms"] is not None else "-"
        print(
            f"{TOOL_LABELS.get(tool, (tool, ''))[0]:<18} {m.tp:>4} {m.fp:>4} {m.tn:>4} {m.fn:>4}  "
            f"{m.recall * 100:>7.2f}%  [{ci.lower:>6.2f}, {ci.upper:>6.2f}]  {lat_cell:>14}"
        )

    for tool, state in sorted(status.items()):
        if state == "not_run":
            print(f"{TOOL_LABELS.get(tool, (tool, ''))[0]:<18} not installed -- excluded")

    print("\nRecall by matching strictness")
    print("-" * 78)
    print(f"{'tool':<18} {'control':>9} {'resource':>10} {'any':>8}")
    for tool in sorted(results):
        if status.get(tool) != "run":
            continue
        row = results[tool]
        applicable = row["resource"].n_resource_applicable > 0
        control = f"{row['control'].matrix.recall * 100:>8.2f}%"
        resource = (
            f"{row['resource'].matrix.recall * 100:>9.2f}%"
            if applicable
            else f"{NOT_ESTIMABLE:>10}"
        )
        any_level = f"{row['any'].matrix.recall * 100:>7.2f}%"
        print(f"{TOOL_LABELS.get(tool, (tool, ''))[0]:<18} {control} {resource} {any_level}")

    total_unmapped = sum(
        levels[args.level].n_unmapped for t, levels in results.items() if status[t] == "run"
    )
    total_unmapped_on_missed = sum(
        levels[args.level].n_unmapped_on_missed
        for t, levels in results.items()
        if status[t] == "run"
    )
    if total_unmapped:
        print(f"\n{total_unmapped} findings carried rule identifiers absent from the control map.")
        if total_unmapped_on_missed:
            print(
                f"         {total_unmapped_on_missed} of them landed on cases the emitting "
                "tool missed, so those tools may be under-credited."
            )
        else:
            print(
                "         None landed on a case its tool missed, so no reported recall is "
                "under-credited by them."
            )
        print("Run `python -m evaluation.normalize --emit-unmapped` and extend it.")

    # ---- artefacts -------------------------------------------------------- #
    payload = {
        "environment": env,
        "corpus": {
            "n_cases": len(cases),
            "n_vulnerable": n_positives,
            "n_compliant": n_negatives,
            "case_ids": [c.case_id for c in cases],
        },
        "matching_level": args.level,
        "reference_tool": args.reference,
        "all_pairwise": all_pairs,
        "control_map_schema": manifest.get("control_map_schema"),
        "control_map_unverified": unverified,
        "tool_status": status,
        "results": {
            tool: {lvl: levels[lvl].to_dict() for lvl in MATCH_LEVELS}
            for tool, levels in results.items()
            if status[tool] == "run"
        },
        "pairwise_mcnemar": comparisons,
        "caveats": _caveats(
            n_negatives, unverified, total_unmapped, total_unmapped_on_missed, control_map
        ),
    }
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    # Trailing newline for the same reason the tables below carry one: without it
    # the end-of-file-fixer pre-commit hook appends one, every analysis run strips
    # it again, and the file reads as permanently modified.
    OUT_JSON.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"\nWrote {OUT_JSON.relative_to(ROOT)}")

    if not args.no_tables:
        TABLE_DIR.mkdir(parents=True, exist_ok=True)
        tables = {
            "performance.tex": emit_performance_table(
                results, status, args.level, len(cases), n_positives, n_negatives
            ),
            "rates.tex": emit_rates_table(results, status, args.level),
            "strictness.tex": emit_strictness_table(results, status),
            "latency.tex": emit_latency_table(results, status, manifest.get("repeats", 1)),
            "mcnemar.tex": emit_mcnemar_table(comparisons, args.reference),
            "allpairs.tex": emit_allpairs_table(all_pairs, args.level),
            "layers.tex": emit_layer_table(results, status, args.level, n_positives),
        }
        malformed = {n: p for n, c in tables.items() if (p := latex_defects(c))}
        if malformed:
            print("\nerror: generated tables are malformed and were not written.", file=sys.stderr)
            for name, problems in malformed.items():
                for problem in problems:
                    print(f"  {name}: {problem}", file=sys.stderr)
            print(
                "\nA malformed table breaks the manuscript build at a point far from "
                "its cause.\nFix the emitter in evaluation/analyze.py.",
                file=sys.stderr,
            )
            return 1
        for name, content in tables.items():
            # Exactly one trailing newline. Several emitters end their line list
            # with "" so that the table is followed by a blank line in the source,
            # which combined with a bare `content + "\n"' wrote a trailing blank
            # line. pre-commit's end-of-file-fixer then stripped it, so every
            # regeneration left eight tables dirty in git and the freshness checks
            # could not distinguish real drift from that churn.
            (TABLE_DIR / name).write_text(content.rstrip("\n") + "\n", encoding="utf-8")
        print(f"Wrote {len(tables)} LaTeX tables to {TABLE_DIR.relative_to(ROOT)}/")

        LEADERBOARD_CSV.parent.mkdir(parents=True, exist_ok=True)
        LEADERBOARD_CSV.write_text(
            emit_leaderboard_csv(results, status, args.level).rstrip("\n") + "\n",
            encoding="utf-8",
        )
        print(f"Wrote {LEADERBOARD_CSV.relative_to(ROOT)}")

    print("\nCaveats that must accompany these numbers:")
    for caveat in payload["caveats"]:
        print(f"  - {caveat}")
    return 0


def _csv_field(value: str) -> str:
    """Quotes a CSV field when it needs it (RFC 4180).

    Trivy's category is "HCL scanning, tfsec successor"; written bare, its comma
    split the row into one field too many and shifted every later column.
    """
    if any(ch in value for ch in ',"\n'):
        return '"' + value.replace('"', '""') + '"'
    return value


def emit_leaderboard_csv(
    results: dict[str, dict[str, ToolResult]],
    status: dict[str, str],
    level: MatchLevel,
) -> str:
    """Renders the public leaderboard from measured confusion matrices.

    ``leaderboard/results.csv`` was previously written by evaluation/score.py,
    which multiplies corpus counts by hardcoded per-tool rates and pins the
    reference implementation to a perfect score. Emitting the same path from the
    measured matrices is what stops the fabricated version from being the only
    one that exists -- a file no measuring stage writes will keep being
    regenerated by the stage that fabricates it.

    Only tools that actually executed appear. A tool that was absent or errored
    on every case is omitted rather than written with zeros, because a zero row
    and a missing row mean different things and a CSV cannot caveat itself.
    """
    header = (
        "tool_name,category,total_cases,tp,fp,tn,fn,"
        "accuracy_pct,precision_pct,recall_pct,f1_score_pct,fpr_pct,fnr_pct,"
        "recall_ci_low_pct,recall_ci_high_pct,latency_mean_ms,latency_sd_ms,"
        "latency_samples,matching_level"
    )
    lines = [header]
    ranked = sorted(
        (t for t in results if status[t] == "run"),
        key=lambda t: results[t][level].matrix.recall,
        reverse=True,
    )
    for tool in ranked:
        result = results[tool][level]
        m = result.matrix
        label, category = TOOL_LABELS.get(tool, (tool, ""))
        ci = m.recall_ci()
        latency = result.latency_summary()

        def num(value: float | None, digits: int = 2) -> str:
            return "" if value is None else f"{value:.{digits}f}"

        lines.append(
            ",".join(
                [
                    _csv_field(label),
                    _csv_field(category),
                    str(m.total),
                    str(m.tp),
                    str(m.fp),
                    str(m.tn),
                    str(m.fn),
                    num(m.accuracy * 100),
                    num(m.precision * 100),
                    num(m.recall * 100),
                    num(m.f1 * 100),
                    num((1 - m.specificity) * 100) if result.specificity_estimable else "",
                    num((1 - m.recall) * 100),
                    num(ci.as_pct().lower) if ci else "",
                    num(ci.as_pct().upper) if ci else "",
                    num(latency["mean_ms"], 1),
                    num(latency["sd_ms"], 1),
                    str(latency["n"]),
                    level,
                ]
            )
        )
    return "\n".join(lines)


def _scope_caveats(control_map: Any) -> list[str]:
    """Caveats for controls a tool cannot detect because it does not read the input.

    This is not the same failure as missing a misconfiguration, and the confusion
    matrix cannot tell them apart: both appear as a non-detection, and
    :func:`normalize.score_case` counts both as a false negative. The Kubernetes
    controls are the live case -- neither tfsec nor Trivy emits any finding on any
    ``kubernetes_*`` Terraform resource, so their zero on those cases measures
    scope, not accuracy. Stating it is the difference between a reader concluding
    "Trivy missed this" and "Trivy does not look at this".
    """
    by_tool: dict[str, list[str]] = {}
    for control_id, spec in control_map.controls.items():
        for tool in spec.get("inapplicable_tools") or []:
            by_tool.setdefault(tool, []).append(control_id)

    out = []
    for tool, controls in sorted(by_tool.items()):
        listed = ", ".join(sorted(controls))
        out.append(
            f"{tool} is out of scope for {len(controls)} controls ({listed}): it emits "
            "no finding on the resources they govern, so its non-detections there "
            "measure scope rather than recall and must not be read as missed "
            "detections."
        )
    return out


def _caveats(
    n_negatives: int,
    unverified: list[str],
    n_unmapped: int,
    n_unmapped_on_missed: int,
    control_map: Any | None = None,
) -> list[str]:
    caveats = []
    if control_map is not None:
        caveats.extend(_scope_caveats(control_map))
    if n_negatives == 0:
        caveats.append(
            "The corpus has no compliant baselines, so no false-positive rate, "
            "specificity, balanced accuracy or MCC can be reported."
        )
    if unverified:
        caveats.append(
            f"{len(unverified)} control-map entries are unverified against tool output; "
            "detection may be under-credited for affected controls."
        )
    if n_unmapped:
        # Whether unmapped findings understate anything is measurable, not
        # assumable. An unmapped rule matters only on a case the tool missed at
        # control level; anywhere else it is a detection of a different control on
        # incidental infrastructure, and excluding it is correct rather than
        # unfair. Asserting understatement without checking would overstate the
        # uncertainty as surely as ignoring it would understate it.
        if n_unmapped_on_missed:
            caveats.append(
                f"{n_unmapped} findings were unmappable and are excluded from "
                f"control-level scoring. {n_unmapped_on_missed} of them occurred on "
                "cases the emitting tool missed, so recall for those tools may be "
                "under-credited; extend the control map to resolve them."
            )
        else:
            caveats.append(
                f"{n_unmapped} findings were unmappable and are excluded from "
                "control-level scoring. None occurred on a case its tool missed, so "
                "no reported recall is under-credited by them: they are detections "
                "of controls other than the one under test, on infrastructure the "
                "case declares incidentally."
            )
    caveats.append(
        "Comparator tools ran with default rulesets; the plan-level policy set was "
        "authored with knowledge of the corpus. This asymmetry favours the reference."
    )
    return caveats


if __name__ == "__main__":
    raise SystemExit(main())
