"""Mock-first audit-head anchoring with explicit external adapters.

No implicit network calls are made. Explicit submit_tsa/submit_rekor adapters
require network opt-in; use functools.partial to bind them as submit callbacks.
Receipt bytes are retained, never treated as verified proof. Rekor requires the
caller to supply a signed hashedrekord entry; the server validates its signature.

verify_anchor requires an injected offline verifier for external receipts: TSA
verification must check status, message imprint, signature and trusted chain;
Rekor verification must check digest binding, signature, log identity and
inclusion proof against a trusted checkpoint. Mock receipts prove no timestamp.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict

Submit = Callable[[str], bytes]
Verifier = Callable[[str, str, bytes], bool]
Provider = Literal["mock", "tsa", "rekor"]


class AnchorError(RuntimeError):
    """An anchor could not be obtained safely."""


class AnchorReceipt(BaseModel):
    """Serializable opaque receipt; external trust is evaluated on verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    provider: Provider
    head_hash: str
    token: str  # base64, retains binary TSA tokens without lossy conversions
    externally_verified: Literal[False] = False


def _post(
    head: str, endpoint: str, allow_network: bool, transport: httpx.BaseTransport | None,
    *, content: bytes | None = None, json: dict[str, Any] | None = None,
    content_type: str = "application/json",
) -> bytes:
    if not allow_network:
        raise AnchorError("External anchoring requires explicit network opt-in")
    if not _valid_head(head):
        raise AnchorError("Invalid SHA-256 audit head")
    try:
        url = httpx.URL(endpoint)
        if url.scheme != "https" or not url.host or url.userinfo or url.fragment:
            raise AnchorError("Anchor endpoint must be HTTPS without credentials or fragments")
        with httpx.Client(transport=transport, timeout=10, follow_redirects=False, trust_env=False) as client:
            with client.stream("POST", url, content=content, json=json,
                               headers={"Content-Type": content_type}) as response:
                if response.status_code not in {200, 201}:
                    raise AnchorError("Anchor provider rejected submission")
                chunks = bytearray()
                for chunk in response.iter_bytes():
                    chunks.extend(chunk)
                    if len(chunks) > 4 * 1024 * 1024:
                        raise AnchorError("Anchor response exceeds size limit")
                if not chunks:
                    raise AnchorError("Empty anchor response")
                return bytes(chunks)
    except (httpx.HTTPError, ValueError):
        raise AnchorError("Anchor submission failed") from None


def submit_tsa(
    head_hash: str, *, endpoint: str, allow_network: bool = False,
    transport: httpx.BaseTransport | None = None,
) -> bytes:
    """Request an RFC-3161 SHA-256 timestamp, retaining the opaque DER reply.

    certReq=True; no nonce (the verifier must authenticate the signed imprint,
    timestamp and trusted certificate chain). HTTP success is not TSA success.
    """
    if not _valid_head(head_hash):
        raise AnchorError("Invalid SHA-256 audit head")
    request = (bytes.fromhex("30390201013031300d060960864801650304020105000420")
               + bytes.fromhex(head_hash) + bytes.fromhex("0101ff"))
    return _post(head_hash, endpoint, allow_network, transport, content=request,
                 content_type="application/timestamp-query")


def submit_rekor(
    head_hash: str, *, entry: dict[str, Any], endpoint: str, allow_network: bool = False,
    transport: httpx.BaseTransport | None = None,
) -> bytes:
    """Submit a caller-signed hashedrekord; retain entry/proof response bytes.

    Use the full HTTPS /api/v1/log/entries endpoint. The signer must sign the
    artifact whose SHA-256 digest is the audit head; never send audit payloads.
    """
    try:
        spec = entry["spec"]
        binding = spec["data"]["hash"]
        signature = spec["signature"]
        valid = (entry["kind"] == "hashedrekord" and entry["apiVersion"] == "0.0.1"
                 and binding == {"algorithm": "sha256", "value": head_hash}
                 and bool(signature["content"]) and bool(signature["publicKey"]["content"]))
    except (KeyError, TypeError):
        valid = False
    if not valid:
        raise AnchorError("Invalid signed Rekor entry binding")
    return _post(head_hash, endpoint, allow_network, transport, json=entry)


def _valid_head(head: str) -> bool:
    return bool(re.fullmatch(r"[a-f0-9]{64}", head))


def anchor_head(
    head_hash: str, *, provider: str = "mock", allow_network: bool = False,
    submit: Submit | None = None,
) -> AnchorReceipt:
    """Anchor one SHA-256 head; external submission needs explicit opt-in.

    Persist the returned receipt using model_dump_json alongside the project log.
    Failure does not change the audit log or return a mock success fallback.
    """
    if not _valid_head(head_hash):
        raise AnchorError("Invalid SHA-256 audit head")
    if provider == "mock":
        token = ("viper-mock-anchor-v1:" + head_hash).encode("ascii")
    elif provider in {"tsa", "rekor"}:
        if not allow_network:
            raise AnchorError("External anchoring requires explicit network opt-in")
        if submit is None:
            raise AnchorError("External anchoring requires a configured protocol adapter")
        try:
            token = submit(head_hash)
        except Exception:
            raise AnchorError("Anchor submission failed") from None
        if not isinstance(token, bytes) or not token or len(token) > 4 * 1024 * 1024:
            raise AnchorError("Invalid anchor response")
    else:
        raise AnchorError("Unknown anchor provider")
    return AnchorReceipt(provider=provider, head_hash=head_hash,  # type: ignore[arg-type]
                         token=base64.b64encode(token).decode("ascii"))


def verify_anchor(receipt: AnchorReceipt, head_hash: str, *, verifier: Verifier | None = None) -> bool:
    """Verify head binding offline; external tokens need a trusted verifier.

    A True mock result checks consistency only, never external authenticity.
    Do not use a receipt's stored fields as a substitute for cryptographic checks.
    """
    if not _valid_head(head_hash) or receipt.head_hash != head_hash:
        return False
    try:
        token = base64.b64decode(receipt.token, validate=True)
        if receipt.provider == "mock":
            return token == ("viper-mock-anchor-v1:" + head_hash).encode("ascii")
        return verifier is not None and verifier(receipt.provider, head_hash, token) is True
    except (ValueError, binascii.Error):
        return False
    except Exception:
        return False  # trust or decoding failures cannot turn into verification success
