"""
CyberGuard AI - Ingestion Rate Limiter & Alert Storm Shield
Implements token-bucket rate limiting per IP and user-agent to defend against alert flooding,
DoS attacks, and rogue agent traversal attempts.
"""

import time
from typing import Dict, Tuple

class TokenBucketRateLimiter:
    def __init__(self, capacity: int = 120, refill_rate_per_sec: float = 2.0):
        self.capacity = capacity
        self.refill_rate = refill_rate_per_sec
        # key -> (tokens, last_refill_timestamp)
        self.buckets: Dict[str, Tuple[float, float]] = {}

    def is_allowed(self, identifier: str, tokens_requested: int = 1) -> bool:
        """
        Determines whether the client request is permitted under rate constraints.
        Returns True if permitted, False if rate limited.
        """
        now = time.time()
        tokens, last_refill = self.buckets.get(identifier, (self.capacity, now))

        # Refill tokens based on elapsed duration
        elapsed = now - last_refill
        refilled_tokens = min(float(self.capacity), tokens + (elapsed * self.refill_rate))

        if refilled_tokens >= tokens_requested:
            self.buckets[identifier] = (refilled_tokens - tokens_requested, now)
            return True
        else:
            self.buckets[identifier] = (refilled_tokens, now)
            return False

    def get_remaining_tokens(self, identifier: str) -> int:
        now = time.time()
        tokens, last_refill = self.buckets.get(identifier, (self.capacity, now))
        elapsed = now - last_refill
        return int(min(float(self.capacity), tokens + (elapsed * self.refill_rate)))

GLOBAL_RATE_LIMITER = TokenBucketRateLimiter(capacity=100, refill_rate_per_sec=5.0)

