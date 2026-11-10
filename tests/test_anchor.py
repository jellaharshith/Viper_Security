"""All network boundaries are injected; tests use no external services."""

import base64

import httpx
import pytest

from viper.agents.anchor import (
    AnchorError,
    AnchorReceipt,
    anchor_head,
    submit_rekor,
    submit_tsa,
    verify_anchor,
)

HEAD = "a" * 64


def test_default_mock_receipt_roundtrip_is_not_external_proof() -> None:
    receipt = anchor_head(HEAD)
    assert receipt.provider == "mock"
    assert receipt.head_hash == HEAD
    assert verify_anchor(receipt, HEAD)
    assert not verify_anchor(receipt, "b" * 64)
    assert not receipt.externally_verified
    assert AnchorReceipt.model_validate_json(receipt.model_dump_json()) == receipt


@pytest.mark.parametrize("head", ["", "abc", "g" * 64, "A" * 64])
def test_invalid_head_denied(head: str) -> None:
    with pytest.raises(AnchorError):
        anchor_head(head)


@pytest.mark.parametrize("provider", ["tsa", "rekor"])
def test_external_submission_requires_opt_in_and_retains_opaque_token(provider: str) -> None:
    def submit(head: str) -> bytes:
        assert head == HEAD
        return b"external-token"

    with pytest.raises(AnchorError, match="opt-in"):
        anchor_head(HEAD, provider=provider, submit=submit)
    receipt = anchor_head(HEAD, provider=provider, allow_network=True, submit=submit)
    assert base64.b64decode(receipt.token) == b"external-token"
    assert not verify_anchor(receipt, HEAD)  # opaque bytes are not a verified signature
    assert verify_anchor(receipt, HEAD, verifier=lambda p, h, t: (
        p == provider and h == HEAD and t == b"external-token"
    ))
    assert not receipt.externally_verified


def test_submission_errors_fail_closed_and_do_not_expose_provider_secrets() -> None:
    def broken(head: str) -> bytes:
        raise RuntimeError("secret=hidden")

    with pytest.raises(AnchorError, match="submission failed") as exc:
        anchor_head(HEAD, provider="tsa", allow_network=True, submit=broken)
    assert "hidden" not in str(exc.value)
    with pytest.raises(AnchorError):
        anchor_head(HEAD, provider="tsa", allow_network=True)
    with pytest.raises(AnchorError):
        anchor_head(HEAD, provider="unknown")


def test_mock_tampering_and_verifier_failure_are_rejected() -> None:
    receipt = anchor_head(HEAD).model_copy(update={"token": "!!!!"})
    assert not verify_anchor(receipt, HEAD)

    def broken(provider: str, head: str, token: bytes) -> bool:
        raise ValueError("bad signature")

    external = anchor_head(HEAD, provider="rekor", allow_network=True, submit=lambda h: b"x")
    assert not verify_anchor(external, HEAD, verifier=broken)


def test_tsa_posts_rfc3161_sha256_request_offline() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        assert request.headers["content-type"] == "application/timestamp-query"
        assert request.content == (
            bytes.fromhex("30390201013031300d060960864801650304020105000420")
            + bytes.fromhex(HEAD) + bytes.fromhex("0101ff")
        )
        return httpx.Response(200, content=b"DER-receipt",
                              headers={"content-type": "application/timestamp-reply"})

    transport = httpx.MockTransport(handle)
    with pytest.raises(AnchorError, match="opt-in"):
        submit_tsa(HEAD, endpoint="https://tsa.example/", transport=transport)
    assert submit_tsa(HEAD, endpoint="https://tsa.example/", allow_network=True,
                      transport=transport) == b"DER-receipt"


def test_rekor_only_posts_signed_entry_binding_requested_head() -> None:
    import json

    entry = {"apiVersion": "0.0.1", "kind": "hashedrekord", "spec": {
        "data": {"hash": {"algorithm": "sha256", "value": HEAD}},
        "signature": {"content": "c2ln", "publicKey": {"content": "a2V5"}},
    }}

    def handle(request: httpx.Request) -> httpx.Response:
        assert json.loads(request.content) == entry
        assert request.url.path == "/api/v1/log/entries"
        return httpx.Response(201, content=b'{"entry":"receipt"}')

    transport = httpx.MockTransport(handle)
    assert submit_rekor(HEAD, entry=entry, endpoint="https://rekor.example/api/v1/log/entries",
                        allow_network=True, transport=transport) == b'{"entry":"receipt"}'
    with pytest.raises(AnchorError, match="binding"):
        submit_rekor("b" * 64, entry=entry, endpoint="https://rekor.example/api/v1/log/entries",
                     allow_network=True, transport=transport)


@pytest.mark.parametrize("endpoint", ["ftp://tsa.example/", "https://user:pass@tsa.example/",
                                     "https://tsa.example/#fragment"])
def test_external_adapter_rejects_unsafe_endpoint(endpoint: str) -> None:
    with pytest.raises(AnchorError):
        submit_tsa(HEAD, endpoint=endpoint, allow_network=True)


@pytest.mark.parametrize("status", [302, 500])
def test_tsa_does_not_follow_redirects_or_accept_error_response(status: int) -> None:
    transport = httpx.MockTransport(lambda r: httpx.Response(
        status, headers={"location": "https://other.example/"}, content=b"error"))
    with pytest.raises(AnchorError):
        submit_tsa(HEAD, endpoint="https://tsa.example/", allow_network=True, transport=transport)


def _adapter(provider, endpoint, transport, *, allow_network=True):
    if provider == "tsa":
        return submit_tsa(HEAD, endpoint=endpoint, transport=transport, allow_network=allow_network)
    entry = {"apiVersion": "0.0.1", "kind": "hashedrekord", "spec": {
        "data": {"hash": {"algorithm": "sha256", "value": HEAD}},
        "signature": {"content": "c2ln", "publicKey": {"content": "a2V5"}},
    }}
    return submit_rekor(HEAD, entry=entry, endpoint=endpoint, transport=transport,
                        allow_network=allow_network)


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_tsa_accepts_both_schemes_without_proxy_or_redirects(scheme, monkeypatch):
    client = httpx.Client

    def guarded_client(**kwargs):
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        assert kwargs["timeout"] == 10
        return client(**kwargs)

    monkeypatch.setattr("viper.agents.anchor.httpx.Client", guarded_client)

    def handle(request):
        assert request.url.scheme == scheme
        assert request.content == (
            bytes.fromhex("30390201013031300d060960864801650304020105000420")
            + bytes.fromhex(HEAD) + bytes.fromhex("0101ff")
        )
        return httpx.Response(200, content=b"opaque-signed-token")

    assert submit_tsa(HEAD, endpoint=f"{scheme}://tsa.example/", allow_network=True,
                      transport=httpx.MockTransport(handle)) == b"opaque-signed-token"


@pytest.mark.parametrize("provider", ["tsa", "rekor"])
@pytest.mark.parametrize("scheme", ["http", "https"])
@pytest.mark.parametrize("part", ["user:pass@provider.example/", "provider.example/#fragment"])
def test_both_adapters_reject_credentials_and_fragments_before_sending(provider, scheme, part):
    def handle(request):
        pytest.fail("unsafe endpoint must be refused before transport")

    with pytest.raises(AnchorError):
        _adapter(provider, f"{scheme}://{part}", httpx.MockTransport(handle))


def test_rekor_stays_https_only():
    def handle(request):
        pytest.fail("plain HTTP Rekor request must never be sent")

    with pytest.raises(AnchorError):
        _adapter("rekor", "http://rekor.example/api/v1/log/entries", httpx.MockTransport(handle))


@pytest.mark.parametrize("provider,scheme", [("tsa", "http"), ("tsa", "https"), ("rekor", "https")])
def test_opt_in_and_redirect_rejection_remain_provider_independent(provider, scheme):
    calls = []

    def handle(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://elsewhere.example/"}, content=b"redirect")

    transport = httpx.MockTransport(handle)
    endpoint = f"{scheme}://provider.example/"
    with pytest.raises(AnchorError, match="opt-in"):
        _adapter(provider, endpoint, transport, allow_network=False)
    assert calls == []
    with pytest.raises(AnchorError):
        _adapter(provider, endpoint, transport)
    assert calls == [endpoint]


@pytest.mark.parametrize("provider,scheme", [("tsa", "http"), ("rekor", "https")])
def test_response_size_limit_is_retained(provider, scheme):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b"x" * (4 * 1024 * 1024 + 1)))
    with pytest.raises(AnchorError, match="size limit"):
        _adapter(provider, f"{scheme}://provider.example/", transport)
