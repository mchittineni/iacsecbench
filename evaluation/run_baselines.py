"""IaCSecBench — baseline scanner execution harness.

Executes each evaluated tool over each admissible benchmark case and writes the
raw, unmodified tool output to ``results/raw/<tool>/<case>.json``, alongside a
provenance manifest recording resolved tool versions, the git commit, and the
host platform.

Design commitments
------------------
*Nothing is synthesised.* A tool that is not installed is recorded with status
``not_installed`` and is excluded from the comparison. A tool that crashes on a
case is recorded with status ``error`` and its stderr retained. Neither is
converted into a detection outcome, because a missing measurement and a negative
measurement are not the same thing and must not share a representation.

*Latency is measured, not assumed.* Each tool is executed ``--repeats`` times per
case; the manifest records every wall-clock sample so that a mean and standard
deviation can be computed downstream. A single-run figure quoted to one decimal
place is not reportable on shared-tenancy CI hardware.

*Plan-level evaluation is real.* The OPA layer runs ``terraform init`` and
``terraform plan -out``, converts the plan with ``terraform show -json``, and
evaluates Rego against the resulting document. Provider credential validation is
disabled through an injected provider override so that planning requires no cloud
account, which is what makes the layer usable in CI.

Usage::

    python -m evaluation.run_baselines --list-tools
    python -m evaluation.run_baselines --tools checkov --repeats 3
    python -m evaluation.run_baselines --all --repeats 5
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from evaluation.tfenv import ensure_provider_mirror, init_args, terraform_env

ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "results" / "raw"
MANIFEST = ROOT / "results" / "run_manifest.json"
REGO_POLICY = ROOT / "security_framework" / "policies" / "cis_aws_benchmark.rego"

# Terraform provider configuration that permits `plan` without cloud credentials.
# Injected into a scratch copy of each case; never written into the corpus.
PROVIDER_OVERRIDE = """
# Injected by evaluation/run_baselines.py -- permits offline plan generation.
provider "aws" {
  region                      = "eu-west-2"
  access_key                  = "mock_access_key"
  secret_key                  = "mock_secret_key"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  skip_region_validation      = true
}
"""

__all__ = ["ToolSpec", "CaseRun", "run_tool_on_case", "discover_tools", "main"]


# --------------------------------------------------------------------------- #
# Tool specifications
# --------------------------------------------------------------------------- #


@dataclass
class ToolSpec:
    """Declares how one scanner is invoked and versioned."""

    name: str
    binary: str
    version_args: list[str]
    layer: str
    build_command: Callable[[Path], list[str]]
    # Exit codes that indicate a successful scan. Most scanners exit non-zero
    # when they find something, which is not an execution failure.
    ok_exit_codes: tuple[int, ...] = (0, 1)
    json_from_stdout: bool = True
    needs_plan: bool = False

    def resolve(self) -> str | None:
        return shutil.which(self.binary)

    def version(self) -> str | None:
        path = self.resolve()
        if path is None:
            return None
        try:
            proc = subprocess.run(
                [path, *self.version_args],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError):
            return "unknown"
        output = (proc.stdout or proc.stderr).strip()
        return output.splitlines()[0].strip() if output else "unknown"


# The Layer 1 repository-edge scanner is invoked in-process rather than as a
# subprocess, so it is declared separately from the external tool specs below.
LAYER1_TOOL = "iacsb_layer1"

TOOL_SPECS: dict[str, ToolSpec] = {
    "checkov": ToolSpec(
        name="checkov",
        binary="checkov",
        version_args=["--version"],
        layer="source",
        build_command=lambda d: [
            "checkov",
            "--directory",
            str(d),
            "--output",
            "json",
            "--quiet",
            "--compact",
            "--framework",
            "terraform",
        ],
    ),
    "tfsec": ToolSpec(
        name="tfsec",
        binary="tfsec",
        version_args=["--version"],
        layer="source",
        build_command=lambda d: ["tfsec", str(d), "--format", "json", "--no-colour"],
        # tfsec signals finding severity through its exit status, not just
        # success or failure: 0 with no findings, 1 with findings, and 2 on this
        # corpus for five cases that nonetheless wrote complete, parseable JSON
        # containing real findings. Because the exit-code gate below runs before
        # the JSON parse, omitting 2 discarded those five answers as errors and
        # silently reduced tfsec's denominator from 48 to 43. A tool that answers
        # correctly must not be scored as though it failed.
        ok_exit_codes=(0, 1, 2),
    ),
    # Trivy is the maintained successor to tfsec: Aqua folded tfsec's engine and
    # rule set into it, so the two share rule provenance and their identifiers are
    # the same AVD numbers under different spellings (tfsec `AVD-AWS-0086`, Trivy
    # `AWS-0086`). It is included because tfsec is no longer the current product
    # and a comparison that omitted its replacement would be measuring an
    # abandoned scanner. It is NOT an independent third opinion, and the analysis
    # must not treat it as one.
    "trivy": ToolSpec(
        name="trivy",
        binary="trivy",
        version_args=["--version"],
        layer="source",
        build_command=lambda d: [
            "trivy",
            "config",
            str(d),
            "--format",
            "json",
            "--quiet",
            # Without this Trivy pulls its checks bundle from a registry on first
            # use. A network fetch inside a timed measurement would be recorded as
            # scanner latency, and a fetch failure would be recorded as a scan
            # that found nothing -- indistinguishable from a clean case.
            "--skip-check-update",
        ],
        # `trivy config` exits 0 whether or not it finds anything unless --exit-code
        # is passed. 1 is accepted so that a future default change does not turn
        # every finding into a recorded execution error.
        ok_exit_codes=(0, 1),
    ),
    "opa": ToolSpec(
        name="opa",
        binary="opa",
        version_args=["version"],
        layer="plan",
        build_command=lambda plan: [
            "opa",
            "eval",
            "--format",
            "json",
            "--data",
            str(REGO_POLICY),
            "--input",
            str(plan),
            "data.aws.cis.benchmark.deny",
        ],
        ok_exit_codes=(0,),
        needs_plan=True,
    ),
}


def run_layer1_on_case(case_id: str, case_dir: Path, repeats: int) -> CaseRun:
    """Runs the repository-edge secret and personal-data scanner over one case.

    Included so that layer attribution (RQ4) is computed from measured detections
    rather than asserted. Findings are emitted in the structured shape the
    normalization engine expects, with the rule identifier carried through so the
    layer can be credited or not on the same basis as every other tool.
    """
    try:
        from security_framework.engine.engine import BenchmarkEngine
    except ImportError as exc:
        return CaseRun(case_id=case_id, tool=LAYER1_TOOL, status="error", stderr=str(exc))

    out_dir = RAW_DIR / LAYER1_TOOL
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{case_id.replace('/', '__')}.json"

    latencies: list[float] = []
    findings: list[dict[str, Any]] = []
    for _ in range(max(1, repeats)):
        started = time.perf_counter()
        engine = BenchmarkEngine(str(case_dir))
        raw = engine.scan_secret_patterns()
        latencies.append((time.perf_counter() - started) * 1000.0)
        findings = [
            {
                "rule_id": "layer1_secret_pattern",
                "resource": "",
                "severity": "CRITICAL",
                "msg": f"{item.get('rule', 'secret')} in {item.get('file', '')}",
                "file": item.get("file", ""),
                "line": item.get("line", 0),
            }
            for item in raw
        ]

    out_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    return CaseRun(
        case_id=case_id,
        tool=LAYER1_TOOL,
        status="ok",
        exit_code=0,
        latency_ms=latencies,
        raw_path=str(out_path.relative_to(ROOT)),
    )


# --------------------------------------------------------------------------- #
# Execution records
# --------------------------------------------------------------------------- #


@dataclass
class CaseRun:
    """Result of running one tool on one case."""

    case_id: str
    tool: str
    status: str  # ok | error | not_installed | plan_failed | timeout
    exit_code: int | None = None
    latency_ms: list[float] = field(default_factory=list)
    stderr: str = ""
    raw_path: str | None = None

    @property
    def mean_latency_ms(self) -> float | None:
        return sum(self.latency_ms) / len(self.latency_ms) if self.latency_ms else None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["mean_latency_ms"] = self.mean_latency_ms
        return payload


# --------------------------------------------------------------------------- #
# Plan generation
# --------------------------------------------------------------------------- #


def generate_plan_json(
    case_dir: Path, workdir: Path, provider_mirror: Path | None
) -> tuple[Path | None, str]:
    """Produces a ``tfplan.json`` for a case without contacting a cloud provider.

    Returns:
        A ``(path, error)`` pair. ``path`` is None when planning failed, in which
        case ``error`` carries a one-line diagnosis. A plan failure is reported
        as ``plan_failed`` rather than as an absence of findings.
    """
    terraform = shutil.which("terraform")
    if terraform is None:
        return None, "terraform not installed"

    for tf_file in sorted(case_dir.glob("*.tf")):
        shutil.copy2(tf_file, workdir / tf_file.name)
    (workdir / "zz_provider_override.tf").write_text(PROVIDER_OVERRIDE, encoding="utf-8")

    env = terraform_env()

    for args in (
        [terraform, *init_args(provider_mirror)],
        [terraform, "plan", "-out=tfplan.bin", "-no-color", "-input=false", "-refresh=false"],
    ):
        proc = subprocess.run(
            args, cwd=workdir, capture_output=True, text=True, env=env, timeout=900, check=False
        )
        if proc.returncode != 0:
            message = (proc.stderr or proc.stdout).strip().splitlines()
            return None, (message[0][:300] if message else f"{args[1]} failed")

    show = subprocess.run(
        [terraform, "show", "-json", "tfplan.bin"],
        cwd=workdir,
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
        check=False,
    )
    if show.returncode != 0:
        return None, "terraform show -json failed"

    plan_path = workdir / "tfplan.json"
    plan_path.write_text(show.stdout, encoding="utf-8")
    return plan_path, ""


# --------------------------------------------------------------------------- #
# Tool execution
# --------------------------------------------------------------------------- #


def run_tool_on_case(
    spec: ToolSpec,
    case_id: str,
    case_dir: Path,
    repeats: int,
    provider_mirror: Path | None,
    timeout_s: int = 600,
) -> CaseRun:
    """Runs one tool on one case ``repeats`` times, retaining the final output."""
    if spec.resolve() is None:
        return CaseRun(case_id=case_id, tool=spec.name, status="not_installed")

    safe_id = case_id.replace("/", "__")
    out_dir = RAW_DIR / spec.name
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{safe_id}.json"

    latencies: list[float] = []
    last_stdout = ""
    last_stderr = ""
    exit_code: int | None = None

    with tempfile.TemporaryDirectory(prefix=f"iacsb-run-{safe_id}-") as tmp:
        workdir = Path(tmp) / "case"
        workdir.mkdir()

        if spec.needs_plan:
            plan_path, error = generate_plan_json(case_dir, workdir, provider_mirror)
            if plan_path is None:
                return CaseRun(case_id=case_id, tool=spec.name, status="plan_failed", stderr=error)
            target = plan_path
        else:
            for tf_file in sorted(case_dir.glob("*.tf")):
                shutil.copy2(tf_file, workdir / tf_file.name)
            target = workdir

        command = spec.build_command(target)

        for _ in range(max(1, repeats)):
            started = time.perf_counter()
            try:
                proc = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=timeout_s,
                    check=False,
                    cwd=workdir,
                )
            except subprocess.TimeoutExpired:
                return CaseRun(
                    case_id=case_id,
                    tool=spec.name,
                    status="timeout",
                    stderr=f"exceeded {timeout_s}s",
                    latency_ms=latencies,
                )
            latencies.append((time.perf_counter() - started) * 1000.0)
            last_stdout, last_stderr = proc.stdout, proc.stderr
            exit_code = proc.returncode

    if exit_code not in spec.ok_exit_codes:
        return CaseRun(
            case_id=case_id,
            tool=spec.name,
            status="error",
            exit_code=exit_code,
            latency_ms=latencies,
            stderr=(last_stderr or last_stdout).strip()[:1000],
        )

    try:
        parsed = json.loads(last_stdout) if last_stdout.strip() else {}
    except json.JSONDecodeError:
        return CaseRun(
            case_id=case_id,
            tool=spec.name,
            status="error",
            exit_code=exit_code,
            latency_ms=latencies,
            stderr=f"output was not valid JSON: {last_stdout.strip()[:400]}",
        )

    out_path.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
    return CaseRun(
        case_id=case_id,
        tool=spec.name,
        status="ok",
        exit_code=exit_code,
        latency_ms=latencies,
        raw_path=str(out_path.relative_to(ROOT)),
    )


# --------------------------------------------------------------------------- #
# Provenance
# --------------------------------------------------------------------------- #


def discover_tools() -> dict[str, dict[str, Any]]:
    """Resolves availability and version for every declared tool."""
    discovered: dict[str, dict[str, Any]] = {}
    for name, spec in TOOL_SPECS.items():
        path = spec.resolve()
        discovered[name] = {
            "installed": path is not None,
            "path": path,
            "version": spec.version(),
            "layer": spec.layer,
        }
    for extra in ("terraform",):
        path = shutil.which(extra)
        version = None
        if path:
            proc = subprocess.run(
                [path, "version"], capture_output=True, text=True, timeout=60, check=False
            )
            version = (proc.stdout or "").strip().splitlines()[0] if proc.stdout else "unknown"
        discovered[extra] = {"installed": path is not None, "path": path, "version": version}
    return discovered


def _git_commit() -> str:
    git = shutil.which("git")
    if git is None:
        return "unknown"
    try:
        proc = subprocess.run(
            [git, "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return proc.stdout.strip() or "unknown"
    except OSError:
        return "unknown"


def _git_dirty_paths() -> list[str] | None:
    """Tracked paths that differ from HEAD, or None when git is unavailable.

    A commit alone does not identify the measured tree. The run reported in the
    manuscript recorded release 1.3.1, whose corpus had 44 internal cases, while
    52 were measured: the tree carried uncommitted changes and nothing said so.
    Recording the dirty paths makes that visible in the manifest itself.
    """
    git = shutil.which("git")
    if git is None:
        return None
    try:
        proc = subprocess.run(
            [git, "status", "--porcelain", "--untracked-files=no"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    return sorted(line[3:] for line in proc.stdout.splitlines() if line.strip())


def _environment() -> dict[str, Any]:
    dirty = _git_dirty_paths()
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
        "git_commit": _git_commit(),
        "git_dirty": None if dirty is None else bool(dirty),
        "git_dirty_paths": dirty,
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="IaCSecBench baseline execution harness")
    parser.add_argument(
        "--tools",
        nargs="+",
        choices=sorted(TOOL_SPECS) + [LAYER1_TOOL],
        help="tools to run",
    )
    parser.add_argument("--all", action="store_true", help="run every installed tool")
    parser.add_argument("--list-tools", action="store_true", help="report tool availability")
    parser.add_argument("--repeats", type=int, default=3, help="executions per case for latency")
    parser.add_argument("--no-external", action="store_true", help="internal corpus only")
    parser.add_argument(
        "--validate",
        choices=("structural", "terraform"),
        default="terraform",
        help="admissibility mode; only admissible cases are scanned",
    )
    parser.add_argument(
        "--allow-inadmissible",
        action="store_true",
        help="scan every loaded case regardless of admissibility (diagnostics only)",
    )
    parser.add_argument("--limit", type=int, help="scan at most N cases")
    args = parser.parse_args(argv)

    discovered = discover_tools()

    if args.list_tools:
        print(f"{'tool':<14} {'installed':<11} {'layer':<10} version")
        print("-" * 70)
        for name, info in discovered.items():
            flag = "yes" if info["installed"] else "NO"
            print(
                f"{name:<14} {flag:<11} {info.get('layer', '-'):<10} {info.get('version') or '-'}"
            )
        missing = [n for n, i in discovered.items() if not i["installed"]]
        if missing:
            print(f"\nNot installed: {', '.join(missing)}")
            print("These tools will be recorded as not_run and excluded from the comparison.")
            print("They will not be represented by assumed detection rates.")
        return 0

    from evaluation.corpus import load_corpus, validate_corpus
    from evaluation.normalize import ControlMap

    control_map = ControlMap.load()
    cases = load_corpus(control_map, include_external=not args.no_external)
    verdicts = {v.case_id: v for v in validate_corpus(cases, mode=args.validate)}

    if args.allow_inadmissible:
        selected = cases
    else:
        selected = [c for c in cases if verdicts[c.case_id].admissible]

    if args.limit:
        selected = selected[: args.limit]

    if not selected:
        print("No admissible cases to scan.", file=sys.stderr)
        print(
            "Run `python -m evaluation.corpus --report --mode terraform` to see why.",
            file=sys.stderr,
        )
        print("\nThe harness will not fabricate results for an empty corpus.", file=sys.stderr)
        return 2

    requested = args.tools or (sorted(TOOL_SPECS) + [LAYER1_TOOL] if args.all else None)
    if not requested:
        parser.error("specify --tools, --all, or --list-tools")

    runnable = [t for t in requested if t == LAYER1_TOOL or discovered[t]["installed"]]
    skipped = [t for t in requested if t != LAYER1_TOOL and not discovered[t]["installed"]]

    print(
        f"Scanning {len(selected)} admissible cases with {len(runnable)} tools "
        f"({args.repeats} repeats each)."
    )
    if skipped:
        print(f"Not installed, recorded as not_run: {', '.join(skipped)}")

    # Built once up front so that per-case planning never races on provider
    # installation. See evaluation/tfenv.py.
    provider_mirror = ensure_provider_mirror()
    if provider_mirror is None and any(
        TOOL_SPECS[t].needs_plan for t in runnable if t in TOOL_SPECS
    ):
        print("warning: no provider mirror; plan-level runs may fail or race.")

    runs: list[CaseRun] = []
    for tool in runnable:
        print(f"\n[{tool}]")
        for index, case in enumerate(selected, start=1):
            if tool == LAYER1_TOOL:
                run = run_layer1_on_case(case.case_id, case.path, args.repeats)
            else:
                run = run_tool_on_case(
                    TOOL_SPECS[tool], case.case_id, case.path, args.repeats, provider_mirror
                )
            runs.append(run)
            mean = run.mean_latency_ms
            latency = f"{mean:8.1f} ms" if mean is not None else "        -"
            print(f"  {index:3d}/{len(selected)}  {case.case_id:<34} {run.status:<13} {latency}")

    for tool in skipped:
        for case in selected:
            runs.append(CaseRun(case_id=case.case_id, tool=tool, status="not_installed"))

    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(
        json.dumps(
            {
                "environment": _environment(),
                "tools": discovered,
                "repeats": args.repeats,
                "validation_mode": args.validate,
                "allow_inadmissible": args.allow_inadmissible,
                "control_map_schema": control_map.schema_version,
                "control_map_unverified": control_map.unverified_controls,
                "n_cases_loaded": len(cases),
                "n_cases_scanned": len(selected),
                "scanned_case_ids": [c.case_id for c in selected],
                "runs": [r.to_dict() for r in runs],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    ok = sum(1 for r in runs if r.status == "ok")
    print(f"\nCompleted: {ok}/{len(runs)} tool-case executions succeeded.")
    by_status: dict[str, int] = {}
    for run in runs:
        by_status[run.status] = by_status.get(run.status, 0) + 1
    for status, count in sorted(by_status.items()):
        print(f"  {status:<16} {count}")
    print(f"\nRaw output: {RAW_DIR.relative_to(ROOT)}/")
    print(f"Manifest:   {MANIFEST.relative_to(ROOT)}")

    # Reconcile what discovery claimed against what actually executed. These two
    # can disagree: a tool present when discovery ran can be gone by the time its
    # stage is reached, in which case the manifest records "installed: true"
    # alongside a full sweep of not_installed runs. The manifest then reads as
    # though the tool participated when it contributed nothing, and a reader has
    # to cross-tabulate two sections to notice. Report it here instead.
    for tool in runnable:
        if tool == LAYER1_TOOL:
            continue
        observed = [r for r in runs if r.tool == tool]
        if observed and not any(r.status == "ok" for r in observed):
            statuses = sorted({r.status for r in observed})
            print(
                f"\nwarning: {tool} was discovered as installed "
                f"({discovered[tool]['version']}) but produced no successful "
                f"execution on any of {len(observed)} cases "
                f"(statuses: {', '.join(statuses)}).\n"
                f"         It contributes nothing to the comparison. Do not "
                f"report it as an evaluated tool.",
                file=sys.stderr,
            )

    print("\nNext: python -m evaluation.normalize --emit-unmapped")
    print("      python -m evaluation.analyze")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
