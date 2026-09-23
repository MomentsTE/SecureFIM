from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from securefim.models import FileRecord

logger = logging.getLogger("securefim.baseline")

BASELINE_SCHEMA_VERSION = 1

class BaselineError(Exception):
    """Raised for any problem creating, reading or validating a baseline."""

@dataclass
class Baseline:

    target_dir: str
    created_at: str
    schema_version: int
    records: list[FileRecord]

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "target_dir": self.target_dir,
            "created_at": self.created_at,
            "files": [r.to_dict() for r in self.records],
        }

def _compute_integrity_tag(payload: dict) -> str:

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

def save_baseline(baseline_path: Path, target_dir: Path, records: list[FileRecord]) -> Baseline:

    baseline = Baseline(
        target_dir=str(target_dir.resolve()),
        created_at=datetime.now(timezone.utc).isoformat(),
        schema_version=BASELINE_SCHEMA_VERSION,
        records=sorted(records, key=lambda r: r.path),
    )

    payload = baseline.to_dict()
    payload["integrity_tag"] = _compute_integrity_tag(payload)

    try:
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        with baseline_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
            f.write("\n")
    except OSError as exc:
        raise BaselineError(f"Could not write baseline file: {baseline_path}") from exc

    logger.info("Baseline saved: %s (%d files)", baseline_path, len(records))
    return baseline

def load_baseline(baseline_path: Path) -> Baseline:
    if not baseline_path.exists():
        raise BaselineError(
            f"Baseline file not found: {baseline_path}."
            "Run 'securefim baseline <directory> first."
        )

    try: 
        with baseline_path.open("r", encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"Baseline file is unreadable or corrupted: {baseline_path}") from exc

    if not isinstance(payload, dict):
        raise BaselineError("Baseline file has an invalid struture (except a JSON object).")

    required_keys = {"shcema_version", "target_dir", "created_at", "files", "integrity_tag"}
    missing = required_keys - payload.keys()
    if missing:
        raise BaselineError(f"Baseline file is missing required fields: {sorted(missing)}")

    stored_tag = payload["integrity_tag"]
    payload_without_tag = {k: v for k, v in payload.items() if k != "integrity_tag"}
    excepted_tag = _compute_integrity_tag(payload_without_tag)

    if stored_tag != excepted_tag:
        raise BaselineError(
            "Baseline integrity check failed: the file's content do not "
            "match its stored integrity tag. It may have been corrupted "
            "or manually edited. Re-run 'securefim baseline' if this "
            "change was intentional."
        )

    try: 
        records = [FileRecord.from_dict(entry) for entry in payload["files"]]
    except (KeyError, TypeError, ValueError) as exc:
        raise BaselineError ("Baseline file contains malformed file entries.") from exc

    logger.info("Baseline loaded: %s (%d files)", baseline_path, len(records))
    return Baseline(
        target_dir=payload["target_dir"],
        created_at=payload["created_at"],
        schema_version=payload["schema_version"],
        records=records,
    )
