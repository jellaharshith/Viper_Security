"""Offline RFC-3161 verification against a saved real token, never a TSA network call."""

import base64
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from viper.agents import anchor
from viper.agents.anchor import AnchorReceipt, make_tsa_verifier, verify_anchor, verify_tsa_token
from viper.agents.anchor_check import anchor_verdict

FIX = Path(__file__).parent / "fixtures" / "anchor"
DIGEST = "4c3da67688a064a39d3ce310a3d9d3ea0a54e1161b734e204d140766f9f7b6e2"
ROOT = FIX / "digicert-trusted-root-g4.pem"
TOKEN = (FIX / "digicert.tsr").read_bytes()


@pytest.fixture
def openssl_binary():
    binary = shutil.which("openssl")
    if binary is None:
        fallback = Path("C:/Program Files/Git/usr/bin/openssl.exe")
        binary = str(fallback) if fallback.is_file() else None
    if binary is None:
        pytest.skip("OpenSSL is unavailable for real offline fixture verification")
    return binary


def test_real_tsa_fixture_and_unrelated_trust_root(openssl_binary):
    assert verify_tsa_token(TOKEN, DIGEST, ca_file=ROOT, openssl=openssl_binary)
    assert not verify_tsa_token(TOKEN, DIGEST, ca_file=FIX / "unrelated-root-isrg-x1.pem",
                                openssl=openssl_binary)


@pytest.mark.parametrize("token,digest", [(TOKEN, "a" * 64), (TOKEN[:100], DIGEST),
                                         (b"garbage", DIGEST)])
def test_wrong_imprint_and_malformed_tokens_fail(token, digest, openssl_binary):
    assert not verify_tsa_token(token, digest, ca_file=ROOT, openssl=openssl_binary)


def test_fixed_argv_private_tempfile_minimal_environment_and_cleanup():
    calls = []
    paths = []

    def run(argv, **kwargs):
        calls.append(argv)
        assert isinstance(argv, list) and kwargs["shell"] is False
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert 0 < kwargs["timeout"] <= 20
        assert kwargs["env"]["LC_ALL"] == "C"
        assert Path(kwargs["env"]["OPENSSL_CONF"]).read_bytes() == b""
        assert "HTTP_PROXY" not in kwargs["env"] and "VIPER_EXEC_API_TOKEN" not in kwargs["env"]
        path = Path(argv[argv.index("-in") + 1])
        paths.append(path)
        assert path.read_bytes() == TOKEN
        if os.name == "posix":
            assert path.stat().st_mode & 0o077 == 0
            assert path.parent.stat().st_mode & 0o077 == 0
        output = (b"Time stamp: Nov  9 04:24:53 2026 GMT\n" if "-reply" in argv else b"Verification: OK\n")
        os.write(kwargs["stdout"], output)
        return subprocess.CompletedProcess(argv, 0)

    assert verify_tsa_token(TOKEN, DIGEST, ca_file=ROOT, runner=run)
    assert len(calls) == 2
    verify = calls[1]
    assert verify[1:3] == ["ts", "-verify"]
    assert verify[verify.index("-digest") + 1] == DIGEST
    assert "-sha256" in verify
    assert verify[verify.index("-attime") + 1] == "1794198293"
    assert verify[verify.index("-CAfile") + 1] == str(ROOT)
    assert all(not path.exists() and not path.parent.exists() for path in paths)


@pytest.mark.parametrize("head", ["", "a" * 63, "A" * 64, "g" * 64,
                                 "a" * 64 + "\n", "a" * 64 + ";id", None, 123])
def test_hostile_heads_never_launch_a_process(head):
    def run(*args, **kwargs):
        pytest.fail("invalid head must be rejected before invoking OpenSSL")

    assert not verify_tsa_token(TOKEN, head, runner=run)


@pytest.mark.parametrize("token", [b"", b"x" * (256 * 1024 + 1), "not bytes", None])
def test_invalid_or_oversized_tokens_never_launch_a_process(token):
    def run(*args, **kwargs):
        pytest.fail("invalid token must not reach OpenSSL")

    assert not verify_tsa_token(token, DIGEST, runner=run)


@pytest.mark.parametrize("error", [FileNotFoundError(), subprocess.TimeoutExpired("openssl", 1),
                                  RuntimeError("secret must not leak")])
def test_process_errors_fail_closed_and_remove_temporary_files(error):
    paths = []

    def run(argv, **kwargs):
        paths.append(Path(argv[argv.index("-in") + 1]))
        raise error

    assert not verify_tsa_token(TOKEN, DIGEST, ca_file=ROOT, runner=run)
    assert paths and all(not path.exists() and not path.parent.exists() for path in paths)


@pytest.mark.parametrize("output,code", [(b"Verification: OK\n", 1), (b"Verification: FAILED\n", 0),
                                        (b"Verification: OK injected\n", 0)])
def test_both_success_exit_status_and_exact_success_text_are_required(output, code):
    def run(argv, **kwargs):
        os.write(kwargs["stdout"], b"Time stamp: Nov  9 04:24:53 2026 GMT\n" if "-reply" in argv else output)
        return subprocess.CompletedProcess(argv, 0 if "-reply" in argv else code)

    assert not verify_tsa_token(TOKEN, DIGEST, ca_file=ROOT, runner=run)


def test_output_capture_is_bounded_and_bad_timestamp_does_not_verify():
    def run(argv, **kwargs):
        try:
            for _ in range(100):
                os.write(kwargs["stdout"], b"x" * 8192)
        except OSError:
            pass  # bounded reader closes the pipe on overflow
        return subprocess.CompletedProcess(argv, 0)

    assert not verify_tsa_token(TOKEN, DIGEST, ca_file=ROOT, runner=run)


@pytest.mark.parametrize("stamp", [b"garbage\n", b"Time stamp: Feb 31 04:24:53 2026 GMT\n",
                                   b"Time stamp: Nov  9 04:24:53 2026 GMT\n" * 2])
def test_missing_invalid_or_ambiguous_stamp_stops_before_verification(stamp):
    def run(argv, **kwargs):
        assert "-reply" in argv, "invalid timestamp must not reach verification"
        os.write(kwargs["stdout"], stamp)
        return subprocess.CompletedProcess(argv, 0)

    assert not verify_tsa_token(TOKEN, DIGEST, ca_file=ROOT, runner=run)


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf")])
def test_invalid_timeouts_are_rejected_without_a_process(timeout):
    def run(*args, **kwargs):
        pytest.fail("invalid timeout reached OpenSSL")

    assert not verify_tsa_token(TOKEN, DIGEST, timeout=timeout, runner=run)


def test_default_ca_and_provider_factory_and_verified_verdict(monkeypatch):
    calls = []

    def verify(token, head, **kwargs):
        calls.append((token, head, kwargs))
        return True

    monkeypatch.setattr(anchor, "verify_tsa_token", verify)
    verifier = make_tsa_verifier(ROOT)
    assert verifier("tsa", DIGEST, TOKEN)
    assert calls == [(TOKEN, DIGEST, {"ca_file": ROOT})]
    assert not verifier("rekor", DIGEST, TOKEN)
    assert not verifier("mock", DIGEST, TOKEN)
    receipt = AnchorReceipt(provider="tsa", head_hash=DIGEST, token=base64.b64encode(TOKEN).decode())
    assert anchor_verdict(receipt, in_chain=True,
                          token_ok=verify_anchor(receipt, DIGEST, verifier=verifier)) == ("VERIFIED", False)


def test_default_trust_store_is_certifi(monkeypatch):
    monkeypatch.setattr(anchor.certifi, "where", lambda: str(ROOT))

    def run(argv, **kwargs):
        if "-verify" in argv:
            assert argv[argv.index("-CAfile") + 1] == str(ROOT)
        os.write(kwargs["stdout"], b"Time stamp: Nov  9 04:24:53 2026 GMT\n" if "-reply" in argv
                 else b"Verification: OK\n")
        return subprocess.CompletedProcess(argv, 0)

    assert verify_tsa_token(TOKEN, DIGEST, runner=run)
