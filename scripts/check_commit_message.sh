#!/usr/bin/env bash
# The writing rules apply to commit messages, which the file gates
# never read: a message is public prose the moment it is pushed.
# Checks the message file given as the first argument. If a local
# pattern file exists at ~/.config/claude-guards/private-frames.txt
# (one extended regex per line), those patterns are enforced too; the
# file is optional and never part of any repository.
set -euo pipefail

message_file="$1"
# Comment lines are the commit template's, not the message's.
message="$(grep -v '^#' "$message_file" || true)"

fail=0
refuse() {
  echo "commit message check: $1" >&2
  fail=1
}

# The subject leads with the identifier, because a narrow panel
# truncates around thirty characters and the identifying part must
# survive. A decision identifier, a subphase number from the plan, or
# a capitalised area: D-017, 1.5, CI, README.
#
# This ran nowhere for a long time. The scorer reads the last thirty
# subjects after the fact, so a new subject form went unnoticed until
# it had been used five times (D-030). A rule checked only in arrears
# is a rule people learn by being told off.
subject="$(printf '%s' "$message" | grep -v '^[[:space:]]*$' | head -1)"
if [ -n "$subject" ] \
   && ! printf '%s' "$subject" | grep -qE '^(Merge |Revert )' \
   && ! printf '%s' "$subject" | grep -qE '^(D-[0-9]+|[0-9]+\.[0-9]+[a-z]?|[A-Z][A-Z0-9-]{1,30}): '; then
  refuse "a subject that does not lead with an identifier, such as D-017, 1.5, or CI"
fi

if printf '%s' "$message" | grep -qP '\x{2014}|\x{2013}'; then
  refuse "an em or en dash; write the sentence without it"
fi
if printf '%s' "$message" | grep -qP '\x{2192}|\x{21d2}|\x{2190}|\x{2794}'; then
  refuse "an arrow; say what happened in words"
fi
if printf '%s' "$message" | grep -qP '\x{201c}|\x{201d}|\x{2018}|\x{2019}'; then
  refuse "a smart quote; use straight quotes"
fi
if printf '%s' "$message" | grep -qiE '\b(hiring|recruiter|interview|portfolio)\b|\bresumes?\b.*\b(work|career|job)\b|\bjob search\b'; then
  refuse "audience or situation language; write from the frame of the work"
fi
if printf '%s' "$message" | grep -qiE '\b(employer|employment)\b|\bits author\b'; then
  refuse "a reference to the author's situation; describe the work instead"
fi

private_patterns="$HOME/.config/claude-guards/private-frames.txt"
if [ -f "$private_patterns" ]; then
  while IFS= read -r pattern; do
    [ -z "$pattern" ] && continue
    if printf '%s' "$message" | grep -qiE "$pattern"; then
      refuse "a pattern from the local pattern file"
    fi
  done < "$private_patterns"
fi

exit "$fail"
