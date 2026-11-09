import pytest

pytest.importorskip("fastapi")
# ruff: noqa: S101 -- pytest assertions

import os
import signal
import sys
import time
from unittest.mock import Mock

from fastapi.testclient import TestClient
from vmapi.app import create_app
from vmapi.jobs import Job, JobRegistry
from vmapi.toolrunner import build_command

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")
POSIX = pytest.mark.skipif(os.name != "posix", reason="Linux VM process groups required")
AUTH = {"Authorization": "Bearer test-only-token"}


@pytest.fixture(autouse=True)
def default_nuclei_templates(monkeypatch):
    monkeypatch.delenv("VIPER_EXEC_NUCLEI_TEMPLATES", raising=False)


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("VIPER_EXEC_API_TOKEN", "test-only-token")
    monkeypatch.setenv("VIPER_EXEC_EGRESS_ALLOWLIST", "scanme.nmap.org")
    with TestClient(create_app()) as value:
        yield value


def payload(**updates):
    value = {"job_id": "job-1", "tool": "nmap", "args": {"target": "scanme.nmap.org"},
             "target": "scanme.nmap.org"}
    value.update(updates)
    return value


@pytest.mark.parametrize("method,path", [
    ("get", "/health"), ("post", "/jobs"), ("get", "/jobs/x"),
    ("get", "/jobs/x/stream"), ("post", "/jobs/x/pause"), ("post", "/jobs/x/stop"),
    ("get", "/docs"), ("get", "/openapi.json"),
])
def test_every_route_requires_auth(client, method, path):
    assert client.request(method, path).status_code == 401
    assert client.request(method, path, headers={"Authorization": "Bearer bad"}).status_code == 401


def test_health(client, monkeypatch):
    assert client.get("/health", headers=AUTH).json() == {"status": "ok", "tools": ["nmap", "nuclei"]}
    monkeypatch.delenv("VIPER_EXEC_API_TOKEN")
    assert client.get("/health", headers=AUTH).status_code == 401


@pytest.mark.parametrize("updates", [
    {"tool": "sh"}, {"args": {"target": "scanme.nmap.org", "extra": "-oN"}},
    {"args": {"target": "scanme.nmap.org;id"}}, {"target": "example.com"},
    {"args": {"target": "example.com"}}, {"args": {}},
    {"args": {"target": "scanme.nmap.org", "ports": "80;id"}},
    {"args": {"target": "scanme.nmap.org", "flags": ["-oN", "/etc/out"]}},
    {"args": {"target": "scanme.nmap.org", "ports": "80,example.com"}},
    {"args": {"target": "scanme.nmap.org", "service_detection": "true"}},
    {"tool": "nuclei", "args": {"target": "scanme.nmap.org", "templates": "/etc/evil"}},
    {"tool": "nuclei", "args": {"target": "https://scanme.nmap.org@evil.test"}},
])
def test_rejects_unsafe_requests(client, updates):
    assert client.post("/jobs", headers=AUTH, json=payload(**updates)).status_code == 422


def test_allowlists_build_single_target():
    allowed = frozenset({"scanme.nmap.org"})
    assert build_command("nmap", {"target": "scanme.nmap.org", "ports": "80,443",
                                  "service_detection": True, "skip_discovery": True},
                         "scanme.nmap.org", allowed) == [
        "/usr/bin/nmap", "-sT", "-sV", "-Pn", "-p", "80,443", "scanme.nmap.org"]
    command = build_command("nuclei", {"target": "scanme.nmap.org"}, "scanme.nmap.org", allowed)
    assert command == [
        "/usr/bin/nuclei", "-jsonl", "-silent", "-nc", "-duc", "-no-interactsh",
        "-disable-redirects", "-t", "/opt/viper/nuclei-templates",
        "-tags", "tech,exposure,misconfig", "-etags", "dos,fuzz,intrusive,bruteforce,rce,sqli,xss",
        "-severity", "info,low,medium", "-rl", "1", "-c", "5", "-timeout", "10",
        "-retries", "0", "-u", "scanme.nmap.org",
    ]


def test_nuclei_templates_env_override(monkeypatch):
    monkeypatch.setenv("VIPER_EXEC_NUCLEI_TEMPLATES", "/srv/trusted-templates")
    command = build_command("nuclei", {"target": "scanme.nmap.org", "rate_limit": 10},
                            "scanme.nmap.org", frozenset({"scanme.nmap.org"}))
    assert command[command.index("-t") + 1] == "/srv/trusted-templates"
    assert command[command.index("-rl") + 1] == "10"


@pytest.mark.parametrize("directory", [
    "", "relative/templates", "-templates", "-/opt/templates", "C:/templates",
    "/opt/two templates", "/opt/templates\t", "/opt/templates\n", "/opt/templates\r",
    "/opt/templates\x1b", "/opt/templates\x7f", "/opt/templates\x85",
    "/opt/templates\u00a0", "/opt/templates\u200b",
])
def test_nuclei_bad_templates_env_refuses_job(client, monkeypatch, directory):
    monkeypatch.setenv("VIPER_EXEC_NUCLEI_TEMPLATES", directory)
    start = Mock()
    monkeypatch.setattr(client.app.state.jobs, "start", start)
    response = client.post("/jobs", headers=AUTH, json=payload(
        tool="nuclei", args={"target": "scanme.nmap.org"}))
    assert response.status_code == 422
    start.assert_not_called()


@pytest.mark.parametrize("key", ["templates", "tags", "severity", "t", "-passive"])
def test_nuclei_profile_args_rejected(client, monkeypatch, key):
    start = Mock()
    monkeypatch.setattr(client.app.state.jobs, "start", start)
    response = client.post("/jobs", headers=AUTH, json=payload(
        tool="nuclei", args={"target": "scanme.nmap.org", key: "untrusted"}))
    assert response.status_code == 422
    start.assert_not_called()


@pytest.mark.parametrize("target", [
    "https://scanme.nmap.org@evil.test", "scanme.nmap.org;id", "scanme.nmap.org evil.test",
    "scanme.nmap.org\n-templates", "-scanme.nmap.org", "scanme.nmap.org/24", "example.com",
])
def test_nuclei_target_smuggling_rejected(client, monkeypatch, target):
    start = Mock()
    monkeypatch.setattr(client.app.state.jobs, "start", start)
    response = client.post("/jobs", headers=AUTH, json=payload(
        tool="nuclei", target=target, args={"target": target}))
    assert response.status_code == 422
    start.assert_not_called()


@pytest.mark.parametrize("rate", [True, False, 0, 11, 1.0, "1", None])
def test_nuclei_rate_requires_bounded_integer(client, monkeypatch, rate):
    start = Mock()
    monkeypatch.setattr(client.app.state.jobs, "start", start)
    response = client.post("/jobs", headers=AUTH, json=payload(
        tool="nuclei", args={"target": "scanme.nmap.org", "rate_limit": rate}))
    assert response.status_code == 422
    start.assert_not_called()


def wait_terminal(client):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        response = client.get("/jobs/job-1", headers=AUTH)
        if response.json()["state"] in {"done", "failed", "killed"}:
            return response.json()
        time.sleep(0.01)
    pytest.fail("job did not reach terminal state")


@POSIX
def test_happy_job_and_sse(client, monkeypatch):
    monkeypatch.setattr("vmapi.app.build_command", lambda *args: [sys.executable, "-u", "-c",
                                                               "print('hello'); print('world')"])
    assert client.post("/jobs", headers=AUTH, json=payload()).json() == {
        "job_id": "job-1", "state": "running"}
    assert wait_terminal(client) == {"job_id": "job-1", "state": "done", "exit_code": 0}
    response = client.get("/jobs/job-1/stream", headers=AUTH)
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.text == "data: hello\n\ndata: world\n\n"
    assert client.post("/jobs", headers=AUTH, json=payload()).status_code == 409


@POSIX
def test_stop_kills_child_tree_and_paused_job(client, monkeypatch):
    script = ("import subprocess,sys,time; "
              "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)']); "
              "print(p.pid,flush=True); time.sleep(120)")
    monkeypatch.setattr("vmapi.app.build_command", lambda *args: [sys.executable, "-u", "-c", script])
    assert client.post("/jobs", headers=AUTH, json=payload()).status_code == 201
    job = client.app.state.jobs.get("job-1")
    with job.changed:
        assert job.changed.wait_for(lambda: bool(job.lines), timeout=5)
        child = int(job.lines[0])
    assert os.getpgid(child) == job.process.pid
    assert client.post("/jobs/job-1/pause", headers=AUTH).json() == {"state": "paused"}
    assert client.post("/jobs/job-1/stop", headers=AUTH).json() == {"state": "killed"}
    assert job.process.poll() == -signal.SIGKILL
    assert not JobRegistry.group_alive(job.process.pid)
    assert client.get("/jobs/job-1", headers=AUTH).json()["state"] == "killed"


def test_missing_jobs(client):
    assert client.get("/jobs/missing", headers=AUTH).status_code == 404


@POSIX
def test_failed_job(client, monkeypatch):
    monkeypatch.setattr("vmapi.app.build_command",
                        lambda *args: [sys.executable, "-c", "raise SystemExit(7)"])
    client.post("/jobs", headers=AUTH, json=payload())
    assert wait_terminal(client)["exit_code"] == 7


def test_no_scope_denies(client, monkeypatch):
    monkeypatch.delenv("VIPER_EXEC_EGRESS_ALLOWLIST")
    with TestClient(create_app()) as empty:
        assert empty.post("/jobs", headers=AUTH, json=payload()).status_code == 422


def test_stop_refuses_unverified_acknowledgement(client, monkeypatch):
    registry = client.app.state.jobs
    process = Mock(pid=123, returncode=None)
    registry.jobs["job-1"] = Job("job-1", process)
    monkeypatch.setattr(registry, "_kill", Mock(side_effect=RuntimeError("still alive")))
    response = client.post("/jobs/job-1/stop", headers=AUTH)
    assert response.status_code == 503
    assert registry.jobs["job-1"].state != "killed"
    # Keep fixture shutdown from retrying the deliberately failing fake.
    registry.jobs.clear()


def test_stop_is_idempotent_without_resignalling_reused_pid(client, monkeypatch):
    registry = client.app.state.jobs
    job = Job("job-1", Mock(pid=123), state="killed", termination_verified=True)
    registry.jobs["job-1"] = job
    kill = Mock(side_effect=AssertionError("must not signal a completed group"))
    monkeypatch.setattr(registry, "_kill", kill)
    assert client.post("/jobs/job-1/stop", headers=AUTH).json() == {"state": "killed"}
    kill.assert_not_called()


def test_stream_waits_for_output_capture_after_process_exit():
    job = Job("job-1", Mock(), state="done", output_done=True, lines=["last line"])
    assert list(JobRegistry.stream(job)) == ["data: last line\n\n"]
