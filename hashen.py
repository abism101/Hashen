#!/usr/bin/env python3

"""
Hashen
------
Lightweight file hashing and integrity utility.

Features:
- Hash single files
- Hash directories
- SHA-256 / SHA-512 / SHA-1 / MD5
- Create integrity manifests
- Verify manifests
- Detect modified files
- Detect new files
- Detect deleted files
- JSON export

Standard-library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path


VERSION = "1.0.0"

BANNER = r"""
╭──────────────────────────────────────╮
│                HASHEN                │
│      File Integrity & Hash Tool      │
╰──────────────────────────────────────╯
"""


# ─────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────

@dataclass
class FileRecord:
    path: str
    size: int
    hash: str
    algorithm: str


@dataclass
class Manifest:
    version: str
    algorithm: str
    root: str
    created_at: str
    files: list[FileRecord]


# ─────────────────────────────────────────────
# HASHING
# ─────────────────────────────────────────────

SUPPORTED_ALGORITHMS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


def get_hasher(
    algorithm: str,
):
    """Return the requested hashlib constructor."""

    algorithm = algorithm.lower()

    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"unsupported algorithm: {algorithm}"
        )

    return SUPPORTED_ALGORITHMS[algorithm]


def hash_file(
    path: Path,
    algorithm: str,
    chunk_size: int = 1024 * 1024,
) -> str:
    """Calculate the hash of a file."""

    hasher = get_hasher(algorithm)()

    with path.open(
        "rb"
    ) as file:

        while True:

            chunk = file.read(
                chunk_size
            )

            if not chunk:
                break

            hasher.update(chunk)

    return hasher.hexdigest()


# ─────────────────────────────────────────────
# FILE DISCOVERY
# ─────────────────────────────────────────────

def iter_files(
    path: Path,
):
    """Yield files recursively."""

    if path.is_file():
        yield path
        return

    if path.is_dir():

        for item in sorted(
            path.rglob("*")
        ):

            if item.is_file():
                yield item


# ─────────────────────────────────────────────
# MANIFEST CREATION
# ─────────────────────────────────────────────

def build_manifest(
    root: Path,
    algorithm: str,
) -> Manifest:

    files: list[FileRecord] = []

    base = (
        root.parent
        if root.is_file()
        else root
    )

    for path in iter_files(root):

        relative = (
            path.relative_to(base)
            .as_posix()
        )

        record = FileRecord(
            path=relative,
            size=path.stat().st_size,
            hash=hash_file(
                path,
                algorithm,
            ),
            algorithm=algorithm,
        )

        files.append(record)

    return Manifest(
        version=VERSION,
        algorithm=algorithm,
        root=str(root),
        created_at=time.strftime(
            "%Y-%m-%dT%H:%M:%S%z"
        ),
        files=files,
    )


def save_manifest(
    manifest: Manifest,
    output: Path,
) -> None:

    data = asdict(manifest)

    output.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


# ─────────────────────────────────────────────
# MANIFEST LOADING
# ─────────────────────────────────────────────

def load_manifest(
    path: Path,
) -> Manifest:

    data = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    files = [
        FileRecord(**entry)
        for entry in data.get(
            "files",
            [],
        )
    ]

    return Manifest(
        version=data.get(
            "version",
            "unknown",
        ),
        algorithm=data.get(
            "algorithm",
            "sha256",
        ),
        root=data.get(
            "root",
            ".",
        ),
        created_at=data.get(
            "created_at",
            "",
        ),
        files=files,
    )


# ─────────────────────────────────────────────
# VERIFICATION
# ─────────────────────────────────────────────

@dataclass
class VerificationResult:
    checked: int = 0
    unchanged: int = 0
    modified: list[str] | None = None
    new: list[str] | None = None
    deleted: list[str] | None = None

    def __post_init__(self):
        if self.modified is None:
            self.modified = []

        if self.new is None:
            self.new = []

        if self.deleted is None:
            self.deleted = []


def verify_manifest(
    manifest: Manifest,
    root: Path | None = None,
) -> VerificationResult:

    result = VerificationResult()

    base = (
        root
        if root is not None
        else Path(manifest.root)
    )

    expected = {
        record.path: record
        for record in manifest.files
    }

    seen: set[str] = set()

    for record in manifest.files:

        current = base / record.path

        if not current.exists():

            result.deleted.append(
                record.path
            )

            continue

        if not current.is_file():

            result.deleted.append(
                record.path
            )

            continue

        seen.add(
            record.path
        )

        result.checked += 1

        try:

            current_size = (
                current.stat().st_size
            )

            current_hash = hash_file(
                current,
                manifest.algorithm,
            )

        except OSError:

            result.modified.append(
                record.path
            )

            continue

        if (
            current_size == record.size
            and current_hash == record.hash
        ):

            result.unchanged += 1

        else:

            result.modified.append(
                record.path
            )

    current_files = set()

    for path in iter_files(base):

        relative = (
            path.relative_to(base)
            .as_posix()
        )

        current_files.add(
            relative
        )

    for path in sorted(
        current_files - expected.keys()
    ):

        result.new.append(path)

    return result


# ─────────────────────────────────────────────
# DISPLAY
# ─────────────────────────────────────────────

def print_value(
    label: str,
    value: str,
) -> None:

    print(
        f"  {label:<14} {value}"
    )


def print_file_hash(
    path: Path,
    algorithm: str,
) -> None:

    digest = hash_file(
        path,
        algorithm,
    )

    print(
        "\n FILE"
    )

    print(
        " ─────────────────────────────────────"
    )

    print_value(
        "Name",
        path.name,
    )

    print_value(
        "Size",
        format_size(
            path.stat().st_size
        ),
    )

    print_value(
        "Algorithm",
        algorithm.upper(),
    )

    print_value(
        "Hash",
        digest,
    )


def print_manifest_summary(
    manifest: Manifest,
) -> None:

    print(
        "\n MANIFEST"
    )

    print(
        " ─────────────────────────────────────"
    )

    print_value(
        "Root",
        manifest.root,
    )

    print_value(
        "Algorithm",
        manifest.algorithm.upper(),
    )

    print_value(
        "Files",
        str(len(manifest.files)),
    )

    print_value(
        "Created",
        manifest.created_at,
    )


def print_verification(
    result: VerificationResult,
) -> None:

    print(
        "\n INTEGRITY"
    )

    print(
        " ─────────────────────────────────────"
    )

    print_value(
        "Checked",
        str(result.checked),
    )

    print_value(
        "Unchanged",
        str(result.unchanged),
    )

    print_value(
        "Modified",
        str(len(result.modified)),
    )

    print_value(
        "New",
        str(len(result.new)),
    )

    print_value(
        "Deleted",
        str(len(result.deleted)),
    )

    for path in result.modified:
        print(
            f"  [MODIFIED] {path}"
        )

    for path in result.new:
        print(
            f"  [NEW]      {path}"
        )

    for path in result.deleted:
        print(
            f"  [DELETED]  {path}"
        )

    if (
        not result.modified
        and not result.new
        and not result.deleted
    ):

        print(
            "\n  ✓ Integrity verified"
        )

    else:

        print(
            "\n  ! Integrity changes detected"
        )


def format_size(
    size: int,
) -> str:

    units = (
        "B",
        "KB",
        "MB",
        "GB",
        "TB",
    )

    value = float(size)

    for unit in units:

        if value < 1024 or unit == units[-1]:

            if unit == "B":
                return f"{int(value)} {unit}"

            return f"{value:.2f} {unit}"

        value /= 1024

    return f"{size} B"


# ─────────────────────────────────────────────
# JSON EXPORT
# ─────────────────────────────────────────────

def export_json(
    path: Path,
    data,
) -> None:

    path.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        prog="Hashen",
        description=(
            "File hashing and integrity "
            "verification utility."
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # hash
    hash_parser = subparsers.add_parser(
        "hash",
        help="Calculate a file hash.",
    )

    hash_parser.add_argument(
        "path",
        help="File to hash.",
    )

    hash_parser.add_argument(
        "-a",
        "--algorithm",
        default="sha256",
        choices=SUPPORTED_ALGORITHMS,
        help="Hash algorithm.",
    )

    # create
    create_parser = subparsers.add_parser(
        "create",
        help="Create an integrity manifest.",
    )

    create_parser.add_argument(
        "path",
        help="File or directory.",
    )

    create_parser.add_argument(
        "-o",
        "--output",
        default="manifest.json",
        help="Output manifest.",
    )

    create_parser.add_argument(
        "-a",
        "--algorithm",
        default="sha256",
        choices=SUPPORTED_ALGORITHMS,
        help="Hash algorithm.",
    )

    # verify
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify an integrity manifest.",
    )

    verify_parser.add_argument(
        "manifest",
        help="Manifest JSON file.",
    )

    verify_parser.add_argument(
        "-r",
        "--root",
        help="Root directory to verify.",
    )

    verify_parser.add_argument(
        "--json",
        metavar="FILE",
        help="Export verification report.",
    )

    # version
    parser.add_argument(
        "--version",
        action="version",
        version=f"Hashen {VERSION}",
    )

    return parser


# ─────────────────────────────────────────────
# COMMANDS
# ─────────────────────────────────────────────

def command_hash(
    args: argparse.Namespace,
) -> int:

    path = Path(args.path)

    if not path.exists():
        print(
            f"Error: file not found: {path}",
            file=sys.stderr,
        )
        return 1

    if not path.is_file():
        print(
            "Error: hash command requires a file.",
            file=sys.stderr,
        )
        return 1

    print_file_hash(
        path,
        args.algorithm,
    )

    return 0


def command_create(
    args: argparse.Namespace,
) -> int:

    root = Path(args.path)

    if not root.exists():
        print(
            f"Error: path not found: {root}",
            file=sys.stderr,
        )
        return 1

    print(
        f"Hashing {root}..."
    )

    started = time.perf_counter()

    manifest = build_manifest(
        root,
        args.algorithm,
    )

    output = Path(
        args.output
    )

    save_manifest(
        manifest,
        output,
    )

    elapsed = (
        time.perf_counter()
        - started
    )

    print_manifest_summary(
        manifest
    )

    print(
        "\n  ✓ Manifest created:"
        f" {output}"
    )

    print(
        f"  ✓ Completed in {elapsed:.2f}s"
    )

    return 0


def command_verify(
    args: argparse.Namespace,
) -> int:

    manifest_path = Path(
        args.manifest
    )

    if not manifest_path.exists():
        print(
            f"Error: manifest not found: "
            f"{manifest_path}",
            file=sys.stderr,
        )
        return 1

    try:

        manifest = load_manifest(
            manifest_path
        )

    except (
        OSError,
        json.JSONDecodeError,
        TypeError,
        KeyError,
    ) as exc:

        print(
            f"Error loading manifest: {exc}",
            file=sys.stderr,
        )
        return 1

    root = (
        Path(args.root)
        if args.root
        else None
    )

    result = verify_manifest(
        manifest,
        root,
    )

    print_manifest_summary(
        manifest
    )

    print_verification(
        result
    )

    if args.json:

        data = asdict(
            result
        )

        export_json(
            Path(args.json),
            data,
        )

        print(
            f"\n  JSON → {args.json}"
        )

    return (
        0
        if (
            not result.modified
            and not result.new
            and not result.deleted
        )
        else 2
    )


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main() -> int:

    parser = build_parser()

    args = parser.parse_args()

    print(
        BANNER
    )

    try:

        if args.command == "hash":
            return command_hash(args)

        if args.command == "create":
            return command_create(args)

        if args.command == "verify":
            return command_verify(args)

        parser.print_help()
        return 0

    except KeyboardInterrupt:

        print(
            "\n\nCancelled."
        )

        return 130

    except Exception as exc:

        print(
            f"\nError: {exc}",
            file=sys.stderr,
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
