"""Which knowledge-base collection is live. Promotion and rollback are one atomic file swap."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path


@dataclass
class KBRegistry:
    path: Path
    active: str | None = None
    previous: str | None = None
    history: list[dict[str, str]] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> KBRegistry:
        if not path.exists():
            return cls(path)
        raw = json.loads(path.read_text(encoding="utf-8"))
        return cls(path, raw.get("active"), raw.get("previous"), raw.get("history", []))

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps({"active": self.active, "previous": self.previous, "history": self.history}, indent=1),
            encoding="utf-8",
            newline="\n",
        )
        os.replace(tmp, self.path)  # atomic: readers see the old or the new file, never half

    def _log(self, event: str, collection: str | None) -> None:
        self.history.append(
            {"at": datetime.now(UTC).isoformat(timespec="seconds"), "event": event,
             "collection": collection or ""}
        )

    def bootstrap(self, collection: str) -> None:
        """Adopt an existing collection as active (first run, before any update)."""
        if self.active is None:
            self.active = collection
            self._log("bootstrap", collection)
            self._save()

    def promote(self, collection: str) -> None:
        if collection == self.active:
            raise ValueError("collection is already active")
        self.previous, self.active = self.active, collection
        self._log("promote", collection)
        self._save()

    def rollback(self) -> str:
        if not self.previous:
            raise ValueError("no previous collection to roll back to")
        self.active, self.previous = self.previous, self.active
        self._log("rollback", self.active)
        self._save()
        return self.active or ""


def resolve_collection(registry_path: Path, fallback: str) -> str:
    """Live collection name: the registry's choice, else the configured default."""
    return KBRegistry.load(registry_path).active or fallback
