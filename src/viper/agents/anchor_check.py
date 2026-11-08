"""How `viper audit verify` judges one stored anchor receipt (M7)."""

from __future__ import annotations

from viper.agents.anchor import AnchorReceipt


def anchor_verdict(receipt: AnchorReceipt, *, in_chain: bool, token_ok: bool) -> tuple[str, bool]:
    """Return ``(label, counts_as_failure)`` for one anchor receipt.

    in_chain: the receipt's head hash is a record in the verified local chain.
    token_ok: ``verify_anchor`` accepted the token. For ``mock`` that only means the token is
              self-consistent; for ``tsa``/``rekor`` it is False unless a trusted verifier
              vouched for it (none is wired yet, so external receipts arrive as False).
    """
    if not in_chain:
        return "MISMATCH", True  # the anchored head is not in this log: rewritten or wrong file
    # TODO(human): decide how much trust each remaining case earns and whether it fails verify.
    # Cases left to decide: mock+token_ok, external+token_ok, external+not token_ok, mock+not token_ok.
    return "UNVERIFIED", False
