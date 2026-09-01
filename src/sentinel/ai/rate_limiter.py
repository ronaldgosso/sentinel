import random
import time
from typing import Any


class RateLimiter:
    """Token/interval-based rate limiter with exponential backoff and Retry-After support."""

    def __init__(
        self,
        requests_per_second: float | None = 1.0,
        max_retries: int = 3,
        initial_backoff: float = 1.0,
        max_backoff: float = 60.0,
    ) -> None:
        """Initialize rate limiter.

        :param requests_per_second: Max requests per second. If None or <= 0, rate limiting is disabled.
        :param max_retries: Maximum retry attempts on 429 / transient errors.
        :param initial_backoff: Initial backoff delay in seconds.
        :param max_backoff: Maximum backoff delay in seconds.
        """
        self.requests_per_second = requests_per_second
        self.min_interval = (
            1.0 / requests_per_second if requests_per_second and requests_per_second > 0 else 0.0
        )
        self.max_retries = max_retries
        self.initial_backoff = initial_backoff
        self.max_backoff = max_backoff
        self.last_request_time = 0.0

    @property
    def is_enabled(self) -> bool:
        """Return True if active client-side rate limiting is enabled."""
        return self.min_interval > 0

    def acquire(self) -> float:
        """Wait if necessary to comply with the rate limit interval.

        Returns the duration waited in seconds.
        """
        if not self.is_enabled:
            return 0.0

        now = time.time()
        elapsed = now - self.last_request_time
        wait_time = self.min_interval - elapsed

        if wait_time > 0:
            time.sleep(wait_time)
            self.last_request_time = time.time()
            return wait_time

        self.last_request_time = now
        return 0.0

    def get_backoff_delay(self, attempt: int, retry_after: Any = None) -> float:
        """Calculate backoff delay given the retry attempt and optional Retry-After header.

        :param attempt: Zero-based retry attempt number (0, 1, 2, ...).
        :param retry_after: Value from HTTP Retry-After header (seconds or string).
        :return: Seconds to wait before retrying.
        """
        if retry_after is not None:
            try:
                val = float(retry_after)
                if val > 0:
                    return min(val, self.max_backoff)
            except (ValueError, TypeError):
                pass

        # Exponential backoff with jitter: initial_backoff * 2^attempt + jitter
        backoff = self.initial_backoff * (2**attempt)
        jitter = random.uniform(0.1, 0.5)
        delay = min(backoff + jitter, self.max_backoff)
        return float(delay)
