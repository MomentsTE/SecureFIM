from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from securefim.baseline import Baseline, BaselineError, load_baseline, save_baseline
from securefim.models import FileStatus, ScanResultEntry, ScanSummary
from securefim.scanner import InvalidTargetError, build_file_records, compare_to_baseline, discover_files

EXIT_OK = 0
EXIT_CHANGES_DETECTED = 1
EXIT_USAGE_ERROR = 2

DIVIDER = "─" * 55

_STATUS_LABELS = {
    FileStatus.NEW: "NEW",
    FileStatus.DELETED: "DELETED",
    FileStatus.MODIFIED: "MODIFIED",
    FileStatus.UNCHANGED: "UNCHANGED",
    FileStatus.UNREADABLE: "UNREADABLE",
}

def _configure_logging(log_path: Path, verbose: bool) -> None:

    log_path.parent.mkdir(parents=True, exist_ok=True)

    handlers: list[logging.Handler] = [logging.FileHandler(log_path, encoding="utf-8")]
    if verbose: 
        handlers.append(logging.StreamHandler(sys.stderr))

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", 
        handlers=handlers,
    )

def _print_header(title: str, target: Path) -> None:

    print("SECUREFIM")
    print(DIVIDER)
    print(title)
    print(f"Target: {target}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

def _print_results(entries: list[ScanResultEntry]) -> None: 
    print("RESULTS")
    print(DIVIDER)
    if not entries:
        print("(no files found)")
    for entry in entries:
        label = _STATUS_LABELS[entry.status]
        print(f"[{label:<10}] {entry.path}")
    print()


def _print_summary(summary: ScanSummary) -> None:
    print("SUMMARY")
    print(DIVIDER)
    print(f"Files scanned: {summary.total}")
    print(f"Unchangred:     {summary.unchanged}")
    print(f"Modified:      {summary.modified}")
    print(f"New:           {summary.new}")
    print(f"Deleted:       {summary.deleted}")
    if summary.unreadable:
        print(f"Unreadable:    {summary.unreadable}")
    print()

    if summary.has_changes:
        print("⚠ Integrity changes detected.")
    else:
        print("✔ No integrity changes detected.")

def cmd_baseline(args: argparse.Namespace) -> int:
    target_dir = Path(args.directory)
    baseline_path = Path(args.baseline_file)
    logger = logging.getLogger("securefim.cli")

    try:
        files = discover_files(target_dir, include_hidden=not args.exclude_hidden)
        records, unreadable = build_file_records(target_dir, files)
        save_baseline(baseline_path, target_dir, records)
    except InvalidTargetError as exc:
        logger.error("Failed to save baseline: %s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR
    except BaselineError as exc:
        logger.error("Failed to save baseline: %s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    print("SECUREFIM")
    print(DIVIDER)
    print("Baseline Created")
    print(f"Target:   {target_dir.resolve()}")
    print(f"Baseline:  {baseline_path.resolve()}")
    print()
    print(f"Files recorded:  {len(records)}")
    if unreadable:
        print(f"Files skipped (unreadable): {len(unreadable)}")
        for path in unreadable:
            print(f"  - {path}")
    print()
    print("✔ Baseline saved successfully.")
    return EXIT_OK

def cmd_scan(args: argparse.Namespace) -> int:
    target_dir = Path(args.directory)
    baseline_path = Path(args.baseline_file)
    logger = logging.getLogger("securefim.cli")

    try:
        baseline: Baseline = load_baseline(baseline_path)
        files = discover_files(target_dir, include_hidden=not args.exclude_hidden)
        current_records, unreadable = build_file_records(target_dir, files)
    except (InvalidTargetError, BaselineError) as exc:
        logger.error("Scan failed: %s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR
    
    entries, summary = compare_to_baseline(baseline.records, current_records, unreadable)

    _print_header("Integrity Scan", target_dir.resolve())
    _print_results(entries)
    _print_summary(summary)

    logger.info(
        "Scan complete: total=%d uchanged=%d modified=%d new=%d deleted=%d unreadable=%d",
        summary.total, summary.unchanged, summary.modified, summary.new, 
        summary.deleted, summary.unreadable
    )

    return EXIT_CHANGES_DETECTED if summary.has_changed else EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    baseline_path = Path(args.baseline_file)
    logger = logging.getLogger("securefim.cli")

    try:
        baseline = load_baseline(baseline_path)
    except BaselineError as exc:
        logger.error("Status check failed: %s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    print("SECUREFIM")
    print(DIVIDER)
    print("Baseline Status")
    print(DIVIDER)
    print(f"Target directory: {baseline.target_dir}")
    print(f"Created at:       {baseline.created_at}")
    print(f"Schema version:   {baseline.schema_version}")
    print(f"Files tracked:    {len(baseline.records)}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securefim",
        description="SecureFIM - a File Integrity Monitoring tool.\n"
                     "Detects new, deleted, and modified files using SHA-256 hashing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--log-file", default="logs/securefim.log",
        help="Path to the log file (default: logs/securefim.log)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Also print log messages to the console",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    common_baseline_arg = {
        "flags": ("-b", "--baseline-file"),
        "kwargs": dict(default=".securefim_baseline.json",
                        help="Path to the baseline file (default: .securefim_baseline.json)"),
    }

    p_baseline = subparsers.add_parser("baseline", help="Create a new baseline for a directory")
    p_baseline.add_argument("directory", help="Directory to baseline")
    p_baseline.add_argument(*common_baseline_arg["flags"], **common_baseline_arg["kwargs"])
    p_baseline.add_argument("--exclude-hidden", action="store_true", help="Skip hidden files/directories")
    p_baseline.set_defaults(func=cmd_baseline)

    p_scan = subparsers.add_parser("scan", help="Scan a directory against its baseline")
    p_scan.add_argument("directory", help="Directory to scan")
    p_scan.add_argument(*common_baseline_arg["flags"], **common_baseline_arg["kwargs"])
    p_scan.add_argument("--exclude-hidden", action="store_true", help="Skip hidden files/directories")
    p_scan.set_defaults(func=cmd_scan)

    p_status = subparsers.add_parser("status", help="Show metadata about an existing baseline")
    p_status.add_argument(*common_baseline_arg["flags"], **common_baseline_arg["kwargs"])
    p_status.set_defaults(func=cmd_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    _configure_logging(Path(args.log_file), args.verbose)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
