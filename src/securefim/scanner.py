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


def build_file_records(target_dir: Path, files: list[Path]) -> tuple[list[FileRecord], list[str]]:
    """
    Hash a list of files and turn them into FileRecord objects.
 
    Returns a tuple of (records, unreadable_relative_paths) so callers
    can report on files that exist but could not be hashed, rather than
    silently dropping them.
    """
    resolved_root = target_dir.resolve()
    records: list[FileRecord] = []
    unreadable: list[str] = []
 
    for file_path in files:
        rel_path = file_path.resolve().relative_to(resolved_root).as_posix()
        try:
            digest = sha256_of_file(file_path)
            size = file_path.stat().st_size
        except (HashingError, OSError):
            unreadable.append(rel_path)
            continue
        records.append(FileRecord(path=rel_path, sha256=digest, size=size))
 
    return records, unreadable
 
 
def compare_to_baseline(
    baseline_records: list[FileRecord],
    current_records: list[FileRecord],
    unreadable_paths: list[str],
) -> tuple[list[ScanResultEntry], ScanSummary]:
    """
    Compare a baseline snapshot against a current snapshot.
 
    This is pure logic with no file I/O, which makes it straightforward
    to unit test: feed it two lists of FileRecord and check the output.
    """
    baseline_by_path = {r.path: r for r in baseline_records}
    current_by_path = {r.path: r for r in current_records}
 
    all_paths = set(baseline_by_path) | set(current_by_path) | set(unreadable_paths)
    entries: list[ScanResultEntry] = []
    summary = ScanSummary()
 
    for path in sorted(all_paths):
        baseline_record = baseline_by_path.get(path)
        current_record = current_by_path.get(path)
 
        if path in unreadable_paths:
            status = FileStatus.UNREADABLE
            summary.unreadable += 1
        elif baseline_record is None and current_record is not None:
            status = FileStatus.NEW
            summary.new += 1
        elif baseline_record is not None and current_record is None:
            status = FileStatus.DELETED
            summary.deleted += 1
        elif baseline_record.sha256 != current_record.sha256:
            status = FileStatus.MODIFIED
            summary.modified += 1
        else:
            status = FileStatus.UNCHANGED
            summary.unchanged += 1
 
        entries.append(
            ScanResultEntry(
                path=path,
                status=status,
                baseline_hash=baseline_record.sha256 if baseline_record else None,
                current_hash=current_record.sha256 if current_record else None,
            )
        )
        summary.total += 1
        
    return entries, summary