"""The two scripts the pipeline runs on its own behalf (D-086, D-088):
each refusal path is a test, because a script that ships without one
fails in the pipeline on the path a test would have exercised.
"""

import importlib.util
import stat
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_the_scanner_archive_with_the_wrong_hash_is_refused_and_removed(tmp_path: Path) -> None:
    sonar = load("sonar_scan")
    archive = tmp_path / sonar.ARCHIVE
    archive.write_bytes(b"not the vendor's archive")
    with pytest.raises(SystemExit) as refused:
        sonar.fetch(tmp_path)
    assert "does not match the pinned" in str(refused.value)
    assert not archive.exists(), "a wrong archive is not left for the next run to trust"


def test_unpacking_restores_the_modes_the_archive_recorded(tmp_path: Path) -> None:
    sonar = load("sonar_scan")
    archive = tmp_path / "scanner.zip"
    with zipfile.ZipFile(archive, "w") as z:
        helper = zipfile.ZipInfo("jre/lib/jspawnhelper")
        helper.external_attr = (0o755 << 16)
        z.writestr(helper, "#!/bin/sh\n")
        plain = zipfile.ZipInfo("conf/settings.txt")
        plain.external_attr = (0o644 << 16)
        z.writestr(plain, "x=1\n")
    sonar.unpack(archive, tmp_path)
    assert (tmp_path / "jre/lib/jspawnhelper").stat().st_mode & stat.S_IXUSR
    assert not (tmp_path / "conf/settings.txt").stat().st_mode & stat.S_IXUSR


def test_an_archive_member_that_escapes_the_directory_is_refused(tmp_path: Path) -> None:
    sonar = load("sonar_scan")
    archive = tmp_path / "scanner.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("../escaped.txt", "outside\n")
    with pytest.raises(SystemExit) as refused:
        sonar.unpack(archive, tmp_path / "into")
    assert "escapes the directory" in str(refused.value)
    assert not (tmp_path / "escaped.txt").exists()


def test_the_override_rewrites_only_the_pinned_block() -> None:
    compile_scan = load("compile_scan")
    tree = (
        "pyjwt==2.13.0 \\\n"
        "    --hash=sha256:aaaa \\\n"
        "    --hash=sha256:bbbb\n"
        "    # via\n"
        "    #   semgrep\n"
        "ruff==0.16.10 \\\n"
        "    --hash=sha256:cccc\n"
    )
    out = compile_scan.override(tree, "pyjwt", "2.15.1", ["dddd", "eeee"])
    assert "pyjwt==2.15.1 \\" in out and "sha256:dddd" in out and "sha256:eeee" in out
    assert "sha256:aaaa" not in out
    assert "ruff==0.16.10 \\\n    --hash=sha256:cccc\n" in out, "the next block is untouched"
    assert "    # via\n    #   semgrep\n" in out, "the via comment survives"
    with pytest.raises(SystemExit):
        compile_scan.override(tree, "absent", "1.0", ["ffff"])
