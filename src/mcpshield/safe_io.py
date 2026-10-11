"""Bounded, no-follow reads for local scanner inputs."""

import os
from pathlib import Path
import stat


def read_limited_text(
    path: Path, max_bytes: int, *, decode_errors: str = "replace"
) -> str | None:
    """Read a regular file without following symlinks or exceeding ``max_bytes``.

    Returns ``None`` when the file is too large. The open file descriptor is
    checked after opening to reduce path replacement and symlink race exposure.
    """
    path_stat = os.stat(path, follow_symlinks=False)
    if stat.S_ISLNK(path_stat.st_mode):
        raise OSError(f"Refusing to read symbolic link: {path}")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags | no_follow)
    try:
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise OSError(f"Not a regular file: {path}")
        if (opened_stat.st_dev, opened_stat.st_ino) != (
            path_stat.st_dev,
            path_stat.st_ino,
        ):
            raise OSError(f"File changed while opening: {path}")
        if opened_stat.st_size > max_bytes:
            return None

        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > max_bytes:
            return None
        return content.decode("utf-8", errors=decode_errors)
    finally:
        os.close(descriptor)
