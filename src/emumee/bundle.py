"""Collect explicitly supplied host files into a bounded guest-only package."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .safeio import read_regular_file


MAX_BUNDLE_FILES = 2048
MAX_BUNDLE_FILE_BYTES = 32 * 1024 * 1024
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_BUNDLE_PATH_CHARS = 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _regular(path: Path) -> None:
    details = path.lstat()
    if (not path.is_file() or path.is_symlink() or
            getattr(details, "st_file_attributes", 0) & _REPARSE_POINT or
            details.st_nlink != 1):
        raise ValueError(f"Bundle input is a link or not a regular single-linked file: {path}")


def _directory(path: Path) -> None:
    details = path.lstat()
    if (not path.is_dir() or path.is_symlink() or
            getattr(details, "st_file_attributes", 0) & _REPARSE_POINT):
        raise ValueError(f"Bundle directory is a link or not a directory: {path}")


def _relative(parts: tuple[str, ...]) -> str:
    if (not parts or len(parts) > 32 or any(not part or part in {".", ".."}
                                         or ":" in part or "\\" in part for part in parts)):
        raise ValueError("Bundle relative path is unsafe")
    relative = "/".join(parts)
    if len(relative) > MAX_BUNDLE_PATH_CHARS:
        raise ValueError("Bundle relative path exceeds limit")
    return relative


def normalize_relative(value: str) -> str:
    """Canonical package path accepted from the launch option or request."""
    if not isinstance(value, str) or not value or value.startswith(("/", "\\")):
        raise ValueError("Bundle path must be relative")
    return _relative(tuple(value.replace("\\", "/").split("/")))


def collect_bundle(directories: list[Path], files: list[tuple[Path, str]]) -> dict[str, bytes]:
    """Read each selected file once; never follow nested links or junctions."""
    selected: dict[str, bytes] = {}
    names: set[str] = set()
    total = 0

    def add(path: Path, parts: tuple[str, ...]) -> None:
        nonlocal total
        relative = _relative(parts)
        folded = relative.casefold()
        if folded in names:
            raise ValueError(f"Duplicate guest bundle path: {relative}")
        if len(selected) >= MAX_BUNDLE_FILES:
            raise ValueError(f"Bundle exceeds {MAX_BUNDLE_FILES} files")
        _regular(path)
        raw = read_regular_file(path, MAX_BUNDLE_FILE_BYTES)
        if raw is None:
            raise ValueError(f"Bundle file is unsafe or exceeds 32 MiB: {path}")
        total += len(raw)
        if total > MAX_BUNDLE_BYTES:
            raise ValueError("Bundle exceeds 64 MiB of file data")
        names.add(folded)
        selected[relative] = raw

    for root in directories:
        _directory(root)
        pending: list[tuple[Path, tuple[str, ...]]] = [(root, ())]
        while pending:
            current, prefix = pending.pop()
            _directory(current)
            with os.scandir(current) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    details = entry.stat(follow_symlinks=False)
                    if entry.is_symlink() or getattr(details, "st_file_attributes", 0) & _REPARSE_POINT:
                        raise ValueError(f"Bundle contains a link or junction: {path}")
                    parts = (*prefix, entry.name)
                    _relative(parts)
                    if entry.is_dir(follow_symlinks=False):
                        pending.append((path, parts))
                    elif entry.is_file(follow_symlinks=False):
                        add(path, parts)
                    else:
                        raise ValueError(f"Bundle contains an unsupported file type: {path}")
    for path, relative in files:
        add(path, tuple(normalize_relative(relative).split("/")))
    return selected
