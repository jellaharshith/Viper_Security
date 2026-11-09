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
import math
import os
import re
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import certifi
import httpx
from pydantic import BaseModel, ConfigDict

Submit = Callable[[str], bytes]
Verifier = Callable[[str, str, bytes], bool]
Provider = Literal["mock", "tsa", "rekor"]
ProcessRunner = Callable[..., subprocess.CompletedProcess[Any]]
_MAX_TSA_TOKEN = 256 * 1024
_MAX_OPENSSL_OUTPUT = 64 * 1024


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
    content_type: str = "application/json", allow_http: bool = False,
) -> bytes:
    if not allow_network:
        raise AnchorError("External anchoring requires explicit network opt-in")
    if not _valid_head(head):
        raise AnchorError("Invalid SHA-256 audit head")
    try:
        url = httpx.URL(endpoint)
        schemes = {"http", "https"} if allow_http else {"https"}
        if url.scheme not in schemes or not url.host or url.userinfo or url.fragment:
            raise AnchorError("Anchor endpoint uses a forbidden scheme, credentials or fragment")
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
    HTTP or HTTPS is accepted because the payload contains only a SHA-256 digest,
    not audit contents or credentials, and the signed token is self-authenticating
    only after offline verification against the chosen trust store. An attacker
    on an HTTP path can deny service but cannot forge a token that passes that
    verification. Callers must verify the returned opaque reply; transport is
    never proof. The offline verifier does not check CRL/OCSP revocation.
    """
    if not _valid_head(head_hash):
        raise AnchorError("Invalid SHA-256 audit head")
    request = (bytes.fromhex("30390201013031300d060960864801650304020105000420")
               + bytes.fromhex(head_hash) + bytes.fromhex("0101ff"))
    return _post(head_hash, endpoint, allow_network, transport, content=request,
                 content_type="application/timestamp-query", allow_http=True)


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


def _openssl_output(argv: list[str], timeout: float, runner: ProcessRunner, config: Path) -> str | None:
    """Drain a pipe with bounded memory; overflow closes it instead of buffering unlimited output."""
    read_fd, write_fd = os.pipe()
    output = bytearray()
    failed = threading.Event()

    def drain() -> None:
        try:
            while chunk := os.read(read_fd, 4096):
                if len(output) + len(chunk) > _MAX_OPENSSL_OUTPUT:
                    failed.set()
                    return
                output.extend(chunk)
        except OSError:
            failed.set()
        finally:
            os.close(read_fd)

    thread = threading.Thread(target=drain, daemon=True)
    thread.start()
    env = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C", "OPENSSL_CONF": str(config)}
    if os.name == "nt" and "SYSTEMROOT" in os.environ:
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    result = None
    try:
        result = runner(argv, shell=False, stdin=subprocess.DEVNULL, stdout=write_fd,
                        stderr=subprocess.STDOUT, env=env, timeout=timeout, check=False)
    except Exception:
        failed.set()
    finally:
        os.close(write_fd)
        thread.join(timeout=timeout)
    if thread.is_alive() or failed.is_set() or result is None or result.returncode != 0:
        return None
    return output.decode("utf-8", errors="replace")


def _stamp_epoch(reply: str) -> int:
    """Parse OpenSSL's C-locale genTime display without changing Python's global locale."""
    stamps = re.findall(
        r"^Time stamp:[ \t]+([A-Z][a-z]{2})[ \t]+([0-9]{1,2})[ \t]+"
        r"([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)?[ \t]+([0-9]{4})[ \t]+GMT\r?$",
        reply, re.MULTILINE,
    )
    if len(stamps) != 1:
        raise ValueError("missing or ambiguous TSA timestamp")
    month, day, hour, minute, second, year = stamps[0]
    months = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
    return int(datetime(int(year), months.index(month) + 1, int(day), int(hour), int(minute),
                        int(second), tzinfo=UTC).timestamp())


def verify_tsa_token(
    token: bytes, head_hash: str, *, ca_file: Path | None = None, openssl: str = "openssl",
    timeout: float = 20.0, runner: ProcessRunner = subprocess.run,
) -> bool:
    """Verify an RFC-3161 reply's SHA-256 imprint, signature and CA chain offline.

    Trust defaults to certifi. Chain validation uses the token's signed timestamp
    (`-attime`), not today's date. Revocation (CRL/OCSP) is NOT checked. A trusted
    TSA/root and truthful TSA time remain trust assumptions; this does not prove
    audit-log completeness. No network, shell, user OpenSSL config or proxy env
    is used. Token and captured output are bounded; errors always return False.
    """
    try:
        if (not isinstance(token, bytes) or not 0 < len(token) <= _MAX_TSA_TOKEN
                or not isinstance(head_hash, str) or not _valid_head(head_hash)
                or not isinstance(openssl, str) or not openssl
                or not math.isfinite(timeout) or timeout <= 0):
            return False
        ca = Path(certifi.where()) if ca_file is None else Path(ca_file)
        deadline = time.monotonic() + timeout
        with tempfile.TemporaryDirectory(prefix="viper-tsa-") as directory:
            path = Path(directory) / "reply.tsr"
            config = Path(directory) / "openssl.cnf"
            # Portable empty config instead of user/global engines and providers.
            config.touch(mode=0o600, exist_ok=False)
            with path.open("xb") as handle:
                os.chmod(path, 0o600)
                handle.write(token)
            reply = _openssl_output([openssl, "ts", "-reply", "-in", str(path), "-text"],
                                    max(0.001, deadline - time.monotonic()), runner, config)
            if reply is None:
                return False
            epoch = _stamp_epoch(reply)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            verified = _openssl_output(
                [openssl, "ts", "-verify", "-in", str(path), "-digest", head_hash,
                 "-sha256", "-CAfile", str(ca), "-attime", str(epoch)], remaining, runner, config,
            )
            return (verified is not None
                    and re.search(r"^Verification: OK\r?$", verified, re.MULTILINE) is not None)
    except Exception:
        return False


def make_tsa_verifier(ca_file: Path | None = None) -> Verifier:
    """Bind local TSA trust for verify_anchor; other providers are deliberately unsupported."""
    def verifier(provider: str, head_hash: str, token: bytes) -> bool:
        return provider == "tsa" and verify_tsa_token(token, head_hash, ca_file=ca_file)

    return verifier
