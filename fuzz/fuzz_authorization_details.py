"""Fuzz the authorization details parser.

Same contract as the credential report: any input is parsed or refused
with a ValueError-derived error naming the problem. The refusal is
swallowed; an unexpected exception type is the finding. This parser
walks nested JSON and URL-decodes policy documents, which is exactly
the shape of code where an input nobody imagined finds a path.
"""

import sys

import atheris

with atheris.instrument_imports():
    from manifest_identity.ingest.authorization_details import parse_authorization_details


def test_one_input(data: bytes) -> None:
    try:
        parse_authorization_details(data)
    except ValueError:
        pass


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
