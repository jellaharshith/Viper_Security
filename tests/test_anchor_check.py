"""anchor_verdict policy: honest labels, and only real integrity problems fail verify."""

import pytest

from viper.agents.anchor import AnchorReceipt
from viper.agents.anchor_check import anchor_verdict

HEAD = "a" * 64


def receipt(provider: str) -> AnchorReceipt:
    return AnchorReceipt(provider=provider, head_hash=HEAD, token="eA==")  # noqa: S106 - dummy b64


@pytest.mark.parametrize(("provider", "in_chain", "token_ok", "label", "fails"), [
    ("mock", True, True, "CONSISTENT_ONLY", False),   # self-consistent, not external proof
    ("mock", True, False, "TAMPERED", True),          # a mock token that mismatches its own head
    ("tsa", True, True, "VERIFIED", False),           # a trusted verifier vouched for it
    ("rekor", True, True, "VERIFIED", False),
    ("tsa", True, False, "UNVERIFIED", False),        # honest receipt, no verifier wired: not a failure
    ("rekor", True, False, "UNVERIFIED", False),
    ("mock", False, True, "MISMATCH", True),          # anchored head absent from the chain
    ("tsa", False, True, "MISMATCH", True),
    ("tsa", False, False, "MISMATCH", True),
])
def test_verdict_table(provider, in_chain, token_ok, label, fails):
    assert anchor_verdict(receipt(provider), in_chain=in_chain, token_ok=token_ok) == (label, fails)
