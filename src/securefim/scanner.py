from __future__ import annotations

import logging
from pathlib import Path

from securefim.hasher import sha256_of_file, HashingError
from securefim.models import FileRecord, FileStatus, ScanResultEntry, ScanSummary

logger = logging.getLogger("securefim.scanner")

class InvalidTargetError(Exception):
    """Raised when the target directory is invalid (not a file or directory)."""

def _validate_target_directory(target_dir: Path) -> Path: 

    resolved = target_dir.resolve()
    if not resolved.exists():
        raise InvalidTargetError(f"Target directory does not exist: {resolved}")
    if not resolved.is_dir():
        raise InvalidTargetError(f"Target is not a directory: {resolved}")
    return resolved

