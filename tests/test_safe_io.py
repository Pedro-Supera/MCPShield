from pathlib import Path

import pytest

from mcpshield.safe_io import read_limited_text


def test_reads_regular_file_within_byte_limit(tmp_path: Path):
    source = tmp_path / "source.txt"
    source.write_text("safe", encoding="utf-8")

    assert read_limited_text(source, 4) == "safe"


def test_returns_none_when_content_exceeds_byte_limit(tmp_path: Path):
    source = tmp_path / "source.txt"
    source.write_text("too large", encoding="utf-8")

    assert read_limited_text(source, 4) is None


def test_refuses_symbolic_link(tmp_path: Path):
    target = tmp_path / "target.txt"
    target.write_text("safe", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    with pytest.raises(OSError, match="symbolic link"):
        read_limited_text(link, 100)


def test_refuses_non_regular_file(tmp_path: Path):
    with pytest.raises(OSError, match="Not a regular file"):
        read_limited_text(tmp_path, 100)


def test_rejects_file_replaced_between_stat_and_open(tmp_path: Path, monkeypatch):
    import os

    import mcpshield.safe_io as safe_io

    source = tmp_path / "source.txt"
    source.write_text("original", encoding="utf-8")
    replacement = tmp_path / "replacement.txt"
    replacement.write_text("replacement", encoding="utf-8")
    real_open = os.open

    def open_replacement(path, flags):
        return real_open(replacement, flags)

    monkeypatch.setattr(safe_io.os, "open", open_replacement)

    with pytest.raises(OSError, match="File changed while opening"):
        read_limited_text(source, 100)
