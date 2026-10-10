"""Builders for synthetic credential reports used across the ingest tests.

Synthetic by construction: account numbers and names are generated, and
no value is ever credential-shaped.
"""

HEADER = (
    "user,arn,user_creation_time,password_enabled,password_last_used,"
    "password_last_changed,password_next_rotation,mfa_active,"
    "access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
    "access_key_1_last_used_region,access_key_1_last_used_service,"
    "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,"
    "access_key_2_last_used_region,access_key_2_last_used_service,"
    "cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated"
)

ACCOUNT = "123456789012"


def user_row(
    name: str,
    account: str = ACCOUNT,
    created: str = "2025-01-01T00:00:00+00:00",
    password_enabled: str = "TRUE",  # noqa: S107  (the report column name; the value is a boolean, not a credential)
    mfa: str = "FALSE",
    key1_active: str = "FALSE",
    key1_rotated: str = "N/A",
    key1_used: str = "N/A",
) -> str:
    return (
        f"{name},arn:aws:iam::{account}:user/{name},{created},"
        f"{password_enabled},no_information,{created},N/A,{mfa},"
        f"{key1_active},{key1_rotated},{key1_used},N/A,N/A,"
        f"FALSE,N/A,N/A,N/A,N/A,FALSE,N/A,FALSE,N/A"
    )


def root_row(account: str = ACCOUNT) -> str:
    return (
        f"<root_account>,arn:aws:iam::{account}:root,"
        f"2020-06-01T00:00:00+00:00,not_supported,2026-01-05T12:00:00+00:00,"
        f"not_supported,not_supported,TRUE,FALSE,N/A,N/A,N/A,N/A,"
        f"FALSE,N/A,N/A,N/A,N/A,FALSE,N/A,FALSE,N/A"
    )


def report(*rows: str) -> bytes:
    return ("\n".join([HEADER, *rows]) + "\n").encode()
