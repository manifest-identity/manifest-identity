"""Spreadsheet formula injection, neutralized at every exit that writes CSV.

A cell that begins with an operator executes as a formula in the reader's
spreadsheet with the reader's permissions, and imported files control
names and tags, so every value an export writes passes through one gate.
It lives in core because exports on more than one floor write CSV: the
risk report and the campaign evidence above, and the observed-grant
export the authorized side offers for its round trip.
"""

# A cell beginning with one of these executes as a formula in common
# spreadsheets; a leading tab or carriage return smuggles the same.
FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: object) -> str:
    text = "" if value is None else str(value)
    if text.startswith(FORMULA_LEADERS):
        return "'" + text
    return text
