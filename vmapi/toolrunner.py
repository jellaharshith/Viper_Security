"""The only translation from untrusted job arguments to an executable argv."""

import ipaddress
import json
import os
import posixpath
import re
import subprocess
import sys
import unicodedata

TOOLS = ("nmap", "nuclei", "otp_2fa_probe", "upload_bypass_probe", "injection_probe",
         "secret_scan", "graphql_introspect", "zap_baseline")
ARGUMENT_ALLOWLIST = {
    "nmap": frozenset({"target", "ports", "service_detection", "skip_discovery"}),
    "nuclei": frozenset({"target", "rate_limit"}),
    "otp_2fa_probe": frozenset({"target", "endpoint_path", "mode", "max_attempts", "delay_ms"}),
    "upload_bypass_probe": frozenset({"target", "endpoint_path", "variant"}),
    "injection_probe": frozenset({"target", "endpoint_path", "param_name", "technique"}),
    "secret_scan": frozenset({"target", "path"}),
    "graphql_introspect": frozenset({"target", "path"}),
    "zap_baseline": frozenset({"target", "max_duration_minutes"}),
}

# v1.2 web-app probes: each selects ONE of a small, fixed, pre-reviewed probe via an enum field.
# No raw payload, file content, username, password or OTP code ever reaches this layer.
_OTP_MODES = frozenset({"enumerate_codes", "rate_limit_probe"})
_UPLOAD_VARIANTS = frozenset({"disallowed_extension_render", "content_detector_marker"})
_INJECTION_TECHNIQUES = frozenset({
    "sqli_boolean", "sqli_time", "xss_reflected_marker",
    "command_injection_marker", "url_injection_redirect",
})
_PARAM_NAME = re.compile(r"[A-Za-z0-9_\[\]]{1,64}")
_ENDPOINT_PATH = re.compile(r"/[\x21-\x7e]{0,255}")  # leading slash, printable ASCII, no control/space
_SECRET_SCAN_PATH = re.compile(r"/[A-Za-z0-9/_.-]{1,200}\.js")
_GRAPHQL_PATH = re.compile(r"/[A-Za-z0-9/_.-]{1,200}")
_PROBES_DIR = "/opt/viper/probes"


def valid_target(value: str) -> bool:
    if not isinstance(value, str) or len(value) > 253:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(re.fullmatch(
            r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
            r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*", value))


def build_command(tool: str, args: dict, target: str, allowed_targets: frozenset[str]) -> list[str]:
    """Accept exact hosts only, never URLs, networks, files, flags or multiple targets."""
    if tool not in ARGUMENT_ALLOWLIST or set(args) - ARGUMENT_ALLOWLIST[tool]:
        raise ValueError("tool or argument not allowlisted")
    if not valid_target(target) or target not in allowed_targets or args.get("target") != target:
        raise ValueError("target not allowlisted or mismatched")
    if tool in ("otp_2fa_probe", "upload_bypass_probe", "injection_probe",
                "secret_scan", "graphql_introspect", "zap_baseline"):
        return _build_probe_command(tool, args, target)
    if tool == "nmap":
        command = ["/usr/bin/nmap", "-sT"]
        for key, flag in (("service_detection", "-sV"), ("skip_discovery", "-Pn")):
            if key in args:
                if type(args[key]) is not bool:
                    raise ValueError("boolean argument required")
                if args[key]:
                    command.append(flag)
        if "ports" in args:
            ports = args["ports"]
            if not isinstance(ports, str) or not re.fullmatch(r"[0-9]{1,5}(?:,[0-9]{1,5}){0,31}", ports):
                raise ValueError("ports must be at most 32 explicit TCP ports")
            if any(not 1 <= int(port) <= 65535 for port in ports.split(",")):
                raise ValueError("invalid port")
            command.extend(["-p", ports])
        command.append(target)
        return command
    rate = args.get("rate_limit", 1)
    if type(rate) is not int or not 1 <= rate <= 10:
        raise ValueError("rate_limit must be an integer from 1 to 10")
    templates = os.environ.get("VIPER_EXEC_NUCLEI_TEMPLATES", "/opt/viper/nuclei-templates")
    if (not posixpath.isabs(templates) or templates.startswith("-")
            or any(char.isspace() or unicodedata.category(char).startswith("C")
                   for char in templates)):
        raise ValueError(
            "VIPER_EXEC_NUCLEI_TEMPLATES must be an absolute path without whitespace or controls")
    return ["/usr/bin/nuclei", "-jsonl", "-silent", "-nc", "-duc", "-no-interactsh",
            "-disable-redirects", "-t", templates, "-tags", "tech,misconfig",
            "-etags", "dos,fuzz,intrusive,bruteforce,rce,sqli,xss", "-severity", "info,low,medium",
            "-pt", "http", "-rl", str(rate), "-c", "5", "-timeout", "10", "-retries", "0", "-u", target]


def _require_endpoint_path(args: dict) -> str:
    path = args.get("endpoint_path")
    if not isinstance(path, str) or not _ENDPOINT_PATH.fullmatch(path):
        raise ValueError("endpoint_path must be a leading-slash, printable-ASCII, bounded path")
    return path


def _build_probe_command(tool: str, args: dict, target: str) -> list[str]:
    """Dispatch a v1.2 web-app probe as a VM-local Python subprocess (never a shell string).

    Mirrors nmap/nuclei's invariant: argv is constructed exclusively here from validated,
    allowlisted fields; the probe script itself resolves any test-account session from VM-local
    environment, never from these args.
    """
    if tool in ("otp_2fa_probe", "upload_bypass_probe", "injection_probe"):
        _require_endpoint_path(args)
    if tool == "otp_2fa_probe":
        if args.get("mode") not in _OTP_MODES:
            raise ValueError("mode must be one of the fixed, reviewed set")
        max_attempts = args.get("max_attempts")
        if type(max_attempts) is not int or not 1 <= max_attempts <= 50:
            raise ValueError("max_attempts must be a bounded integer from 1 to 50")
        if "delay_ms" in args:
            delay_ms = args["delay_ms"]
            if type(delay_ms) is not int or not 100 <= delay_ms <= 5000:
                raise ValueError("delay_ms must be a bounded integer from 100 to 5000")
    elif tool == "upload_bypass_probe":
        if args.get("variant") not in _UPLOAD_VARIANTS:
            raise ValueError("variant must be one of the fixed, reviewed set")
    elif tool == "injection_probe":
        if args.get("technique") not in _INJECTION_TECHNIQUES:
            raise ValueError("technique must be one of the fixed, reviewed set")
        param_name = args.get("param_name")
        if not isinstance(param_name, str) or not _PARAM_NAME.fullmatch(param_name):
            raise ValueError("param_name must be a short [A-Za-z0-9_\\[\\]] identifier")
    elif tool == "secret_scan":
        path = args.get("path")
        if not isinstance(path, str) or not _SECRET_SCAN_PATH.fullmatch(path):
            raise ValueError("path must match the bounded JS-file path schema")
    elif tool == "graphql_introspect":
        path = args.get("path", "/graphql")
        if not isinstance(path, str) or not _GRAPHQL_PATH.fullmatch(path):
            raise ValueError("path must match the bounded GraphQL path schema")
        args = {**args, "path": path}
    elif tool == "zap_baseline":
        minutes = args.get("max_duration_minutes", 5)
        if type(minutes) is not int or not 1 <= minutes <= 15:
            raise ValueError("max_duration_minutes must be a bounded integer from 1 to 15")
        args = {**args, "max_duration_minutes": minutes}
    else:
        raise ValueError("probe tool not allowlisted")
    payload = json.dumps({**args, "target": target}, sort_keys=True)
    return [sys.executable, f"{_PROBES_DIR}/{tool}.py", "--args-json", payload]


# The ONLY names ever copied from this process's own environment into a spawned probe's.
# Deliberately narrow: never the bearer token or anything else, no matter what else is set.
_PROBE_ENV_PASSTHROUGH = ("VIPER_EXEC_ALSCO_TEST_SESSION_FILE", "VIPER_EXEC_ALSCO_ACCEPT_EXPIRED_CERT")


def spawn(command: list[str]) -> subprocess.Popen:
    # start_new_session invokes setsid(2) in the child, safely even from API threads.
    # Never use preexec_fn=os.setsid: Python warns it can deadlock in threaded servers.
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": os.path.expanduser("~")}
    for name in _PROBE_ENV_PASSTHROUGH:
        value = os.environ.get(name)
        if value is not None:
            env[name] = value
    return subprocess.Popen(  # noqa: S603 -- argv constructed exclusively by build_command
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True, cwd="/", env=env,
    )
