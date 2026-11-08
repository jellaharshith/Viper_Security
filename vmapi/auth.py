"""Fail-closed bearer authentication; credentials never enter responses or logs."""

import hmac
import os


def authorized(header: str | None) -> bool:
    token = os.environ.get("VIPER_EXEC_API_TOKEN", "")
    if not token or not header:
        return False
    scheme, separator, supplied = header.partition(" ")
    return bool(separator and scheme.lower() == "bearer" and
                hmac.compare_digest(supplied.encode(), token.encode()))
