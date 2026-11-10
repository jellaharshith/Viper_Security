"""Offline workflow policy checks; never contact GitHub or execute workflow tools."""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
FILES = sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])


def load_workflow(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def triggers(workflow):
    # PyYAML's YAML 1.1 resolver reads the unquoted GitHub Actions key `on` as True.
    return workflow.get("on", workflow.get(True))


def uses_values(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "uses":
                yield value
            yield from uses_values(value)
    elif isinstance(node, list):
        for value in node:
            yield from uses_values(value)


@pytest.mark.parametrize("path", FILES, ids=lambda path: path.name)
def test_every_action_is_pinned_and_workflow_permissions_are_explicit(path):
    workflow = load_workflow(path)
    assert isinstance(workflow["permissions"], dict) and workflow["permissions"]
    for uses in uses_values(workflow):
        assert re.fullmatch(r"[^@\s]+@[0-9a-fA-F]{40}", uses), uses


@pytest.mark.parametrize("path", FILES, ids=lambda path: path.name)
def test_workflows_never_use_pull_request_target(path):
    assert "pull_request_target" not in triggers(load_workflow(path))


def test_weekly_kb_only_runs_on_schedule_or_explicit_dispatch():
    workflow = load_workflow(WORKFLOWS / "kb-weekly.yml")
    assert set(triggers(workflow)) == {"schedule", "workflow_dispatch"}


def test_required_status_check_job_ids_are_stable():
    ci = load_workflow(WORKFLOWS / "ci.yml")
    security = load_workflow(WORKFLOWS / "security.yml")
    assert "ci-pass" in ci["jobs"]
    assert {"secrets", "dependency-audit"} <= security["jobs"].keys()
    assert ci["jobs"]["ci-pass"].get("name", "ci-pass") == "ci-pass"
    for job in ("secrets", "dependency-audit"):
        assert security["jobs"][job].get("name", job) == job


@pytest.mark.parametrize("name,prefix", [("ci.yml", "ci-"), ("security.yml", "security-")])
def test_concurrency_cancels_only_pr_runs_and_isolates_every_non_pr_run(name, prefix):
    workflow = load_workflow(WORKFLOWS / name)
    concurrency = workflow["concurrency"]
    assert concurrency["cancel-in-progress"] == "${{ github.event_name == 'pull_request' }}"
    assert concurrency["group"] == (
        prefix + "${{ github.event_name }}-${{ github.event.pull_request.number || github.run_id }}"
    )
    assert triggers(workflow)["push"]["branches"] == ["main"]
    assert all(level == "read" for level in workflow["permissions"].values())


@pytest.mark.parametrize("windows,other,expected", [
    ("success", "success", 0), ("skipped", "success", 0),
    ("failure", "success", 1), ("cancelled", "success", 1),
    ("success", "failure", 1),
])
def test_ci_aggregator_propagates_windows_and_other_job_failures(windows, other, expected):
    workflow = load_workflow(WORKFLOWS / "ci.yml")
    assert workflow["jobs"]["test-windows"]["if"] == "github.event_name == 'push'"
    aggregator = workflow["jobs"]["ci-pass"]
    assert aggregator["if"] == "always()"
    assert set(aggregator["needs"]) == {"lint", "types", "test", "test-vmapi", "test-windows"}
    results = {job: {"result": windows if job == "test-windows" else other}
               for job in aggregator["needs"]}
    script = "\n".join(step["run"] for step in aggregator["steps"] if "run" in step)
    script = script.replace("${{ toJSON(needs) }}", json.dumps(results))
    script = script.replace("${{ join(needs.*.result, ' ') }}",
                            " ".join(value["result"] for value in results.values()))
    assert "${{" not in script, "unexpected expression in the aggregator; extend this offline harness"
    bash = shutil.which("bash")
    if bash is None:
        fallback = Path("C:/Program Files/Git/bin/bash.exe")
        bash = str(fallback) if fallback.is_file() else None
    if bash is None:
        pytest.skip("Bash unavailable for the offline aggregator check")
    result = subprocess.run(  # noqa: S603 -- parsed local workflow, echo/grep only; no workflow tools
        [bash, "-c", script], capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == expected, result.stdout + result.stderr
