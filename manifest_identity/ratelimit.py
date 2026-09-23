"""Sign-in rate limiting, written here on purpose (see D-027).

Failures are counted per key over a sliding window; success clears the
username key so a legitimate user who finally types the right password
is not served a stale lockout. Only failures count, and there is no
account lockout: a lockout hands an attacker a denial of service
against any username they can spell.

State is in process memory. That is a stated limitation, not an
oversight: this application deploys as one process in version one, and
a restart clearing the counters is acceptable for a control whose job
is slowing online guessing, not surviving forensics.
"""

import threading
import time


class LoginRateLimiter:
    def __init__(self, max_failures: int = 5, window_seconds: int = 300) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> list[float]:
        kept = [t for t in self._failures.get(key, []) if now - t < self.window_seconds]
        if kept:
            self._failures[key] = kept
        else:
            self._failures.pop(key, None)
        return kept

    def allowed(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            # Distributed probing grows the key map without bound if only
            # touched keys prune; sweep everything once the map is large.
            if len(self._failures) > 1024:
                # The copy is required: pruning pops emptied keys, and
                # a dict cannot change size under its own iteration.
                for stale in list(self._failures):
                    self._prune(stale, now)
            return len(self._prune(key, now)) < self.max_failures

    def record_failure(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._prune(key, now)
            self._failures.setdefault(key, []).append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._failures.clear()


# One limiter per process, shared by the login route.
LOGIN_LIMITER = LoginRateLimiter()

# The write throttle (D-041): imports and campaign creation do real
# work per request (parsing, assessment of the whole account), so an
# authenticated session gets a generous but bounded budget. The same
# sliding-window mechanism; here every request counts, not only
# failures, and the ceiling is far above any human pace.
WRITE_LIMITER = LoginRateLimiter(max_failures=30, window_seconds=60)
