"""`viper scope draft|approve`: a model-drafted scope is never trusted until a human approves it. Offline."""

import json

import pytest

from viper import cli
from viper.agents import runner
from viper.agents.audit import AuditLog
from viper.config import Settings

PROGRAM = "Acme bounty. In scope: app.acme.test and *.api.acme.test. Out of scope: admin.acme.test. No DoS."
REPLY = json.dumps({
    "evidence_ref": "https://acme.test/security/policy",
    "in_scope": ["app.acme.test", "*.api.acme.test"],
    "exclusions": ["admin.acme.test"],
    "forbidden_techniques": ["dos"],
    "ambiguities": ["Is mobile traffic in scope?"],
})


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("VIPER_AUDIT_DIR", str(tmp_path / "audit"))
    monkeypatch.setenv("VIPER_OLLAMA_MODEL", "fake")
    monkeypatch.setattr(runner, "llm_chat", lambda _settings: (lambda _messages: REPLY))
    text = tmp_path / "program.txt"
    text.write_text(PROGRAM, encoding="utf-8")
    return {"text": str(text), "out": str(tmp_path / "scopes"), "tmp": tmp_path}


def draft(env, project="acme"):
    return cli.main(["scope", "draft", "--text-file", env["text"], "--project", project,
                     "--program-url", "https://acme.test/bounty", "--out", env["out"]])


def test_draft_writes_a_draft_the_agent_cannot_load(env, capsys):
    assert draft(env) == 0
    path = env["tmp"] / "scopes" / "acme.draft.yaml"
    assert path.exists() and "DRAFT" in path.read_text(encoding="utf-8")
    with pytest.raises(Exception):  # noqa: B017 - any load failure proves the draft is inert
        runner.load_scope(path)
    out = capsys.readouterr().out
    assert "app.acme.test" in out and "Is mobile traffic in scope?" in out and "DRAFT" in out


def test_draft_refuses_to_overwrite_and_validates_the_project_id(env, capsys):
    assert draft(env) == 0
    capsys.readouterr()
    assert draft(env) == 1 and "scope error" in capsys.readouterr().out
    for bad in ("../x", "a b", ""):
        assert draft(env, bad) == 1


def test_draft_failure_is_class_only_and_writes_nothing(env, monkeypatch, capsys):
    monkeypatch.setattr(runner, "llm_chat", lambda _s: (lambda _m: "I cannot help with that."))
    assert draft(env) == 1
    assert "scope error" in capsys.readouterr().out
    assert not (env["tmp"] / "scopes" / "acme.draft.yaml").exists()


def approve(env, confirm=None, project="acme"):
    args = ["scope", "approve", "--draft", str(env["tmp"] / "scopes" / f"{project}.draft.yaml")]
    if confirm is not None:
        args += ["--confirm", confirm]
    return cli.main(args)


def test_approve_without_confirmation_changes_nothing(env, capsys):
    assert draft(env) == 0
    capsys.readouterr()
    assert approve(env) == 1
    out = capsys.readouterr().out
    assert "--confirm acme" in out and "app.acme.test" in out
    assert not (env["tmp"] / "scopes" / "acme.scope.yaml").exists()


def test_approve_with_the_wrong_confirmation_changes_nothing(env):
    assert draft(env) == 0
    assert approve(env, confirm="other") == 1
    assert not (env["tmp"] / "scopes" / "acme.scope.yaml").exists()


def test_approve_writes_a_loadable_scope_and_audits_it(env, capsys):
    assert draft(env) == 0
    assert approve(env, confirm="acme") == 0
    final = env["tmp"] / "scopes" / "acme.scope.yaml"
    scope = runner.load_scope(final)
    assert scope.project_id == "acme" and "app.acme.test" in scope.in_scope
    assert "admin.acme.test" in scope.exclusions
    events = AuditLog(Settings(_env_file=None, audit_dir=env["tmp"] / "audit"), "acme").events("scope")
    assert [e["event"] for e in events] == ["scope_approved"]
    assert events[0]["actor"] == "human" and events[0]["detail"]["scope_revision"] == scope.revision


def test_approve_never_overwrites_an_existing_scope(env):
    assert draft(env) == 0
    assert approve(env, confirm="acme") == 0
    first = (env["tmp"] / "scopes" / "acme.scope.yaml").read_text(encoding="utf-8")
    assert approve(env, confirm="acme") == 1
    assert (env["tmp"] / "scopes" / "acme.scope.yaml").read_text(encoding="utf-8") == first


def test_approve_rejects_a_file_that_is_not_a_draft(env, capsys):
    final = env["tmp"] / "scopes"
    final.mkdir(parents=True)
    (final / "x.draft.yaml").write_text("project_id: x\nin_scope: [a.test]\n", encoding="utf-8")
    assert cli.main(["scope", "approve", "--draft", str(final / "x.draft.yaml"), "--confirm", "x"]) == 1
    assert "scope error" in capsys.readouterr().out


def test_terminal_output_is_stripped_of_control_characters(env, monkeypatch, capsys):
    nasty = json.dumps({"evidence_ref": "https://acme.test/p", "in_scope": ["app.acme.test"],
                        "exclusions": [], "forbidden_techniques": [],
                        "ambiguities": ["ok" + chr(27) + "]52;c;AAAA" + chr(7) + chr(0x202E) + "tail"]})
    monkeypatch.setattr(runner, "llm_chat", lambda _s: (lambda _m: nasty))
    assert draft(env) == 0
    out = capsys.readouterr().out
    assert chr(27) not in out and chr(7) not in out and chr(0x202E) not in out


def test_a_failed_audit_append_leaves_no_usable_scope(env, monkeypatch, capsys):  # codex v1 #1
    from viper.agents.audit import AuditError

    assert draft(env) == 0

    def boom(self, **kwargs):
        raise AuditError("disk full")

    monkeypatch.setattr(AuditLog, "append", boom)
    assert approve(env, confirm="acme") == 1
    assert not (env["tmp"] / "scopes" / "acme.scope.yaml").exists()
    assert "scope error" in capsys.readouterr().out


def test_an_existing_scope_blocks_approval_before_anything_is_audited(env):
    assert draft(env) == 0
    (env["tmp"] / "scopes" / "acme.scope.yaml").write_text("planted", encoding="utf-8")
    assert approve(env, confirm="acme") == 1
    log = AuditLog(Settings(_env_file=None, audit_dir=env["tmp"] / "audit"), "acme")
    assert log.events("scope") == []
    assert (env["tmp"] / "scopes" / "acme.scope.yaml").read_text(encoding="utf-8") == "planted"
