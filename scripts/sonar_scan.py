#!/usr/bin/env python3
"""Run SonarCloud's scanner from a checksum-pinned download.

    python3 scripts/sonar_scan.py            # analyze, needs SONAR_TOKEN
    python3 scripts/sonar_scan.py --version  # fetch, verify, print the version

The vendor's GitHub action fetches the scanner and then verifies it by
importing the vendor's signing key from public keyservers at run time,
and fails when they do not answer, which stopped this pipeline three
times in one afternoon (D-088). This fetches the same archive and
verifies it against the SHA-256 the vendor publishes, pinned here the
way every other downloaded tool in this repository is pinned. Nothing
else is contacted before the scan runs.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

VERSION = "8.1.0.6389"
ARCHIVE = f"sonar-scanner-cli-{VERSION}-linux-x64.zip"
URL = f"https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/{ARCHIVE}"
SHA256 = "bb8f709f9cb73352f8d1260a3b3c506c0f41146754bc630762c126d795499d0b"
ROOT = Path(__file__).resolve().parent.parent


def fetch(into: Path) -> Path:
    parts = urllib.parse.urlsplit(URL)
    if (parts.scheme, parts.netloc) != ("https", "binaries.sonarsource.com"):
        raise SystemExit(f"refusing to read {URL}")
    archive = into / ARCHIVE
    if not archive.exists():
        with urllib.request.urlopen(URL, timeout=120) as r:  # noqa: S310  # scheme and host checked above
            archive.write_bytes(r.read())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != SHA256:
        archive.unlink()
        raise SystemExit(f"{ARCHIVE}: sha256 {digest} does not match the pinned {SHA256}")
    return archive


def unpack(archive: Path, into: Path) -> Path:
    home = into / f"sonar-scanner-{VERSION}-linux-x64"
    if not home.exists():
        with zipfile.ZipFile(archive) as z:
            for member in z.infolist():
                target = (into / member.filename).resolve()
                if not str(target).startswith(str(into.resolve())):
                    raise SystemExit(f"{ARCHIVE}: member {member.filename} escapes the directory")
            z.extractall(into)
        # Zip extraction drops the execute bits.
        for name in ("bin/sonar-scanner", "jre/bin/java"):
            path = home / name
            path.chmod(path.stat().st_mode | 0o111)
    return home


def main(argv: list[str]) -> int:
    cache = Path(os.environ.get("RUNNER_TEMP") or (ROOT / ".tools")) / "sonar-scanner"
    cache.mkdir(parents=True, exist_ok=True)
    home = unpack(fetch(cache), cache)
    command = [str(home / "bin" / "sonar-scanner")]
    if "--version" in argv:
        command.append("--version")
    elif not os.environ.get("SONAR_TOKEN"):
        raise SystemExit("SONAR_TOKEN is not set; nothing to analyze with")
    return subprocess.run(command, cwd=ROOT, check=False, timeout=1800).returncode  # noqa: S603


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
