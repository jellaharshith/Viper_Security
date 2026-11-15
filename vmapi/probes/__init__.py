"""v1.2 web-app probes: small, reviewed scripts run as VM-local subprocesses by ``toolrunner.py``.

Each script implements exactly one fixed, pre-reviewed detection probe per enum value it accepts —
never a model- or caller-supplied payload. Any authenticated test-account session is resolved here,
from VM-local environment/files, never from argv (so a credential never crosses the wire from the
orchestrator, and never lands in the audit log, which records ``Action.args``).
"""
