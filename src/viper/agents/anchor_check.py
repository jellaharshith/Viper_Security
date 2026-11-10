"""How `viper audit verify` judges one stored anchor receipt (M7)."""

from __future__ import annotations

import base64
import binascii

from viper.agents.anchor import AnchorReceipt


def anchor_verdict(receipt: AnchorReceipt, *, in_chain: bool, token_ok: bool) -> tuple[str, bool]:
    """Return ``(label, counts_as_failure)`` for one anchor receipt.

    in_chain: the receipt's head hash is a record in the verified local chain.
    token_ok: ``verify_anchor`` accepted the token. For ``mock`` that only means the token is
              self-consistent; for ``tsa``/``rekor`` it is False unless a trusted verifier
              vouched for it. The caller supplies its explicit trust configuration.
    """
    if not in_chain:
        return "MISMATCH", True  # the anchored head is not in this log: rewritten or wrong file
    try:  # a token that is not even valid base64 is a broken proof, not merely an absent verifier
        base64.b64decode(receipt.token, validate=True)
    except (binascii.Error, ValueError):
        return "MALFORMED", True
    if receipt.provider == "mock":
        # A mock token only proves self-consistency. A mismatch means someone edited it.
        return ("CONSISTENT_ONLY", False) if token_ok else ("TAMPERED", True)
    if token_ok:
        return "VERIFIED", False  # a trusted verifier vouched for the external receipt
    # External receipt without accepted proof: preserve the selected honest UNVERIFIED policy.
    return "UNVERIFIED", False
