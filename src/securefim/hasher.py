from __future__ import annotations

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger("securefim.hasher")

# Read files in fixed-size chunks rather than loading them entirely into
# memory. This keeps memory usage bounded even for very large files.

_CHUNK_SIZE = 65536  # 64 KiB

class HashingError(Exception):
    """Raised when a file cannot be hashed or is unreadable."""

def sha256_of_file(file_path: Path) -> str:
    """
    Compute the SHA-256 hex digest of a file's contents.
 
    Args:
        file_path: Path to the file to hash.
 
    Returns:
        A lowercase hex string representing the SHA-256 digest.
 
    Raises:
        HashingError: if the file cannot be opened or read (permission
            denied, deleted mid-read, or any other I/O failure).
    """
    digest = hashlib.sha256()
    try:
        with file_path.open("rb") as f:
            while chunk := f.read(_CHUNK_SIZE):
                digest.update(chunk)
    except (OSError, PermissionError) as exc:
        logger.warning("Failed to hash file: %s (%s)", file_path.name, type(exc).__name__)
        raise HashingError(f"Could not read file for hashing: {file_path.name}") from exc

    return digest.hexdigest()