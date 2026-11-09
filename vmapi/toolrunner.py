"""The only translation from untrusted job arguments to an executable argv."""

import ipaddress
import os
import posixpath
import re
import subprocess
import unicodedata

TOOLS = ("nmap", "nuclei")
ARGUMENT_ALLOWLIST = {
    "nmap": frozenset({"target", "ports", "service_detection", "skip_discovery"}),
    "nuclei": frozenset({"target", "rate_limit"}),
}


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
            "-disable-redirects", "-t", templates, "-tags", "tech,exposure,misconfig",
            "-etags", "dos,fuzz,intrusive,bruteforce,rce,sqli,xss", "-severity", "info,low,medium",
            "-rl", str(rate), "-c", "5", "-timeout", "10", "-retries", "0", "-u", target]


def spawn(command: list[str]) -> subprocess.Popen:
    # start_new_session invokes setsid(2) in the child, safely even from API threads.
    # Never use preexec_fn=os.setsid: Python warns it can deadlock in threaded servers.
    return subprocess.Popen(  # noqa: S603 -- argv constructed exclusively by build_command
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True, cwd="/",
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": os.path.expanduser("~")},
    )
