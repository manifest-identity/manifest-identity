"""Fuzz the credential report parser.

The parser's contract is that any input is either parsed or refused
with a ValueError-derived error naming what was wrong. That named
refusal is the expected path and is swallowed here; anything else that
escapes, an IndexError from a short row, a KeyError from a missing
column, a UnicodeError past the decoder, is a crash worth a fix.
"""

import sys

import atheris

with atheris.instrument_imports():
    from manifest_identity.ingest.credential_report import parse_credential_report


def test_one_input(data: bytes) -> None:
    try:
        parse_credential_report(data)
    except ValueError:
        pass


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
