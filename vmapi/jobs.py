"""Single-worker, in-memory registry with bounded capture and process-group control."""

import os
import signal
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from subprocess import Popen

from vmapi.toolrunner import spawn

TERMINAL = {"done", "failed", "killed"}
MAX_OUTPUT = 1024 * 1024


@dataclass
class Job:
    job_id: str
    process: Popen[bytes]
    state: str = "running"
    exit_code: int | None = None
    lines: list[str] = field(default_factory=list)
    changed: threading.Condition = field(default_factory=threading.Condition)
    control: threading.Lock = field(default_factory=threading.Lock)
    output_done: bool = False
    termination_verified: bool = False


class JobRegistry:
    def __init__(self):
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()

    def get(self, job_id: str) -> Job:
        with self.lock:
            return self.jobs[job_id]

    def start(self, job_id: str, command: list[str]) -> Job:
        if os.name != "posix":
            raise RuntimeError("execution requires a Linux VM")
        with self.lock:
            if job_id in self.jobs:
                raise ValueError("job_id already exists")
            if len(self.jobs) >= 128:
                raise RuntimeError("registry full; restart only after all jobs are stopped")
            process = spawn(command)
            job = Job(job_id, process)
            self.jobs[job_id] = job
        threading.Thread(target=self._capture, args=(job,), daemon=True).start()
        threading.Thread(target=self._watch, args=(job,), daemon=True).start()
        return job

    @staticmethod
    def group_alive(pgid: int) -> bool:
        # Linux zombies have exited and cannot execute; init must reap orphaned zombies.
        # Inspect membership rather than merely the leader, which may already have exited.
        if Path("/proc").is_dir():
            for entry in Path("/proc").iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
                    if int(fields[2]) == pgid and fields[0] not in {"Z", "X"}:
                        return True
                except (FileNotFoundError, ProcessLookupError):
                    continue
            return False
        try:
            os.killpg(pgid, 0)
            return True
        except ProcessLookupError:
            return False

    @classmethod
    def _kill(cls, job: Job):
        try:
            os.killpg(job.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        job.process.wait(timeout=5)
        deadline = time.monotonic() + 5
        while cls.group_alive(job.process.pid):
            if time.monotonic() >= deadline:
                raise RuntimeError("process group termination not verified")
            time.sleep(0.01)
        job.termination_verified = True

    def _capture(self, job: Job):
        total = 0
        try:
            with job.process.stdout as output:
                while raw := output.readline(65536):
                    total += len(raw)
                    if total > MAX_OUTPUT:
                        try:
                            self.stop(job)
                        except ValueError:
                            pass  # Watcher already verified that the process group exited.
                        break
                    # Escape CR and NUL to prevent SSE field injection.
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    line = line.replace("\r", "\\r").replace("\x00", "\\0")
                    with job.changed:
                        job.lines.append(line)
                        job.changed.notify_all()
        finally:
            with job.changed:
                job.output_done = True
                job.changed.notify_all()

    def _watch(self, job: Job):
        try:
            job.process.wait(timeout=300)
            with job.control:
                if self.group_alive(job.process.pid):
                    self._kill(job)
                job.termination_verified = True
                with job.changed:
                    job.exit_code = job.process.returncode
                    if job.state not in TERMINAL:
                        job.state = "done" if job.exit_code == 0 else "failed"
                    job.changed.notify_all()
        except Exception:
            # Timeout, wait or verification failure must never imply success.
            try:
                self.stop(job)
            except Exception:
                with job.changed:
                    job.state = "failed"
                    job.changed.notify_all()

    def pause(self, job: Job):
        with job.control, job.changed:
            if job.state != "running" or job.process.poll() is not None:
                raise ValueError("job is not running")
            os.killpg(job.process.pid, signal.SIGSTOP)
            job.state = "paused"
            job.changed.notify_all()

    def stop(self, job: Job):
        with job.control:
            if job.state == "killed" and job.termination_verified:
                return
            if job.state in TERMINAL and job.termination_verified:
                raise ValueError("job already finished")
            self._kill(job)
            with job.changed:
                job.exit_code = job.process.returncode
                job.state = "killed"
                job.changed.notify_all()

    @staticmethod
    def stream(job: Job):
        index = 0
        while True:
            with job.changed:
                if index < len(job.lines):
                    line = job.lines[index]
                    index += 1
                elif job.state in TERMINAL and job.output_done:
                    return
                else:
                    job.changed.wait(timeout=1)
                    if index < len(job.lines) or (job.state in TERMINAL and job.output_done):
                        continue
                    line = None
            if line is None:
                yield ": keepalive\n\n"
                continue
            yield f"data: {line}\n\n"

    def close(self):
        with self.lock:
            jobs = list(self.jobs.values())
        failures = []
        for job in jobs:
            if not job.termination_verified:
                try:
                    self.stop(job)
                except Exception as exc:
                    failures.append(exc)
        if failures:
            raise RuntimeError("shutdown could not verify all process groups terminated") from failures[0]
