from __future__ import annotations

from dataclasses import dataclass, asdict
from enum import Enum

class FileStatus(str, Enum):
    NEW = "NEW"
    DELETED = "DELETED"
    MODIFIED = "MODIFIED"
    UNCHANGED = "UNCHANGED"
    UNREADABLE = "UNREADABLE"

@dataclass(frozen=True)
class FileRecord:
    path: str
    sha256: str
    size: int

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(data: dict) -> FileRecord:
        return FileRecord(
            path=str(data["path"]),
            sha256=str(data["sha256"]),
            size=int(data["size"])
        )

@dataclass(frozen=True)
class ScanResultEntry:
    path: str
    status: FileStatus
    baseline_hash: str | None = None
    current_hash: str | None = None

@dataclass
class ScanSummary:

    total: int = 0
    unchanged: int = 0
    deleted: int = 0
    modified: int = 0
    unreadable: int = 0
    new: int = 0

    @property
    def changed(self) -> bool:
        return (self.modified + self.new + self.deleted +self.unreadable ) > 0