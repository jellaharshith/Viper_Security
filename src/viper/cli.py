"""Minimal command-line entry point (health check only for M0)."""

from __future__ import annotations

import argparse
import json
import logging
import sys

from viper import __version__
from viper.config import get_settings
from viper.logging_setup import configure_logging

log = logging.getLogger("viper.cli")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="viper")
    parser.add_argument("--health", action="store_true", help="print redacted config and exit")
    args = parser.parse_args(argv)

    settings = get_settings()
    configure_logging(settings.log_level)

    if args.health:
        log.info("health check", extra={"version": __version__})
        print(json.dumps({"status": "OK", "version": __version__, "config": settings.redacted()}, indent=2))
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
