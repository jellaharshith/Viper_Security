"""Viper: human-controlled AI copilot for authorized penetration testing."""

from importlib.metadata import PackageNotFoundError, version

try:  # single source of truth: pyproject.toml, via the installed package metadata
    __version__ = version("viper")
except PackageNotFoundError:  # running from a bare checkout without installing
    __version__ = "0.0.0+unknown"
