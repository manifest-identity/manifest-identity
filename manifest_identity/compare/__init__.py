"""compare: the difference between what is held and what was
authorized.

This part stores nothing. It reads observe and authorize at request
time and returns findings, each carrying when each side was last
heard from, because a stale side makes a delta lie and the lie is
always in the reassuring direction (threat 15).
"""
