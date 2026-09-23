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
