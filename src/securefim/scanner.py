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

def discover_files(
        target_dir: Path,
        include_hidden: bool = True,
        follow_symlinks: bool = False,
        ) -> list[Path]:

    resolved_root = _validate_target_directory(target_dir)
    discovered: list[Path] = []

    for entry in resolved_root.rglob("*"):
        if not include_hidden and any(part.startswith(".") for part in entry.relative_to(resolved_root).parts):
            continue

        if entry.is_symlink() and not follow_symlinks:
            logger.info("Skipping symlink (not followed): %s", entry.name)
            continue

        if entry.is_file():
            try: 
                resolved_entry = entry.resolve()
                resolved_entry.relative_to(resolved_root)  # Ensure it's within the target directory
            except (ValueError, OSError):
                logger.warning("Skipping file outside target directory: %s", entry.name)
                continue
            discovered.append(entry)

    return sorted(discovered)

