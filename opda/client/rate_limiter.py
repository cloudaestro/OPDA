"""
Rate limiting utilities for Okta API client.

Implements exponential backoff, circuit breaker patterns, and
configurable retry logic to handle API rate limits gracefully.
"""

import asyncio
import time
from datetime import datetime, timedelta
from typing import Any, Callable, TypeVar

import structlog
from tenacity import (
    AsyncRetrying,
    RetryCallState,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

T = TypeVar("T")

logger = structlog.get_logger(__name__)


class RateLimitExceeded(Exception):
    """Raised when API rate limit is exceeded."""
    
    def __init__(
        self,
        message: str,
        retry_after: int | None = None,
        reset_time: datetime | None = None,
    ) -> None:
        super().__init__(message)
        self.retry_after = retry_after
        self.reset_time = reset_time


class CircuitBreakerOpen(Exception):
    """Raised when circuit breaker is open."""
    
    def __init__(self, message: str, reset_time: datetime) -> None:
        super().__init__(message)
        self.reset_time = reset_time


class OktaRateLimiter:
    """
    Production-grade rate limiter for Okta API with circuit breaker.
    
    Features:
    - Exponential backoff with jitter
    - Circuit breaker pattern for fast failure
    - Request rate tracking and throttling
    - Configurable retry policies
    """
    
    def __init__(
        self,
        max_retries: int = 5,
        backoff_factor: float = 2.0,
        max_requests_per_minute: int = 60,
        circuit_breaker_threshold: int = 5,
        circuit_breaker_timeout: int = 300,
    ) -> None:
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.max_requests_per_minute = max_requests_per_minute
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self.circuit_breaker_timeout = circuit_breaker_timeout
        
        # Request tracking
        self._request_times: list[float] = []
        self._lock = asyncio.Lock()
        
        # Circuit breaker state
        self._failure_count = 0
        self._circuit_open_time: datetime | None = None
        self._is_circuit_open = False
        
        # Statistics
        self._total_requests = 0
        self._total_retries = 0
        self._total_rate_limit_hits = 0

    async def execute_with_retry(
        self,
        func: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """
        Execute a function with rate limiting and retry logic.
        
        Args:
            func: Function to execute
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function
            
        Returns:
            Function result
            
        Raises:
            RateLimitExceeded: If rate limit cannot be handled
            CircuitBreakerOpen: If circuit breaker is open
        """
        await self._check_circuit_breaker()
        await self._enforce_rate_limit()
        
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(self.max_retries + 1),
            wait=wait_exponential(
                multiplier=self.backoff_factor,
                min=1,
                max=60,
            ),
            retry=retry_if_exception_type(RateLimitExceeded),
            before_sleep=self._log_retry_attempt,
        ):
            with attempt:
                try:
                    self._total_requests += 1
                    result = await self._execute_function(func, *args, **kwargs)
                    
                    # Reset failure count on success
                    self._failure_count = 0
                    
                    return result
                    
                except RateLimitExceeded as e:
                    self._total_rate_limit_hits += 1
                    self._total_retries += 1
                    
                    logger.warning(
                        "Rate limit exceeded, retrying",
                        retry_after=e.retry_after,
                        attempt=attempt.retry_state.attempt_number,
                    )
                    
                    # Wait for the retry-after period if provided
                    if e.retry_after:
                        await asyncio.sleep(e.retry_after)
                    
                    raise
                    
                except Exception as e:
                    self._failure_count += 1
                    
                    # Open circuit breaker if too many failures
                    if self._failure_count >= self.circuit_breaker_threshold:
                        self._open_circuit_breaker()
                    
                    logger.error(
                        "Request failed",
                        error=str(e),
                        failure_count=self._failure_count,
                        attempt=attempt.retry_state.attempt_number,
                    )
                    raise

    async def _execute_function(
        self, func: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Any:
        """Execute function handling both sync and async functions."""
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        else:
            return func(*args, **kwargs)

    async def _check_circuit_breaker(self) -> None:
        """Check if circuit breaker is open and handle state transitions."""
        if not self._is_circuit_open:
            return
            
        if self._circuit_open_time is None:
            return
            
        # Check if circuit breaker timeout has passed
        if datetime.utcnow() - self._circuit_open_time > timedelta(
            seconds=self.circuit_breaker_timeout
        ):
            self._close_circuit_breaker()
            logger.info("Circuit breaker closed, attempting to resume requests")
        else:
            reset_time = self._circuit_open_time + timedelta(
                seconds=self.circuit_breaker_timeout
            )
            raise CircuitBreakerOpen(
                "Circuit breaker is open due to excessive failures",
                reset_time=reset_time,
            )

    async def _enforce_rate_limit(self) -> None:
        """Enforce request rate limiting."""
        async with self._lock:
            now = time.time()
            
            # Remove requests older than 1 minute
            self._request_times = [
                req_time for req_time in self._request_times
                if now - req_time < 60
            ]
            
            # Check if we've hit the rate limit
            if len(self._request_times) >= self.max_requests_per_minute:
                oldest_request = min(self._request_times)
                wait_time = 60 - (now - oldest_request)
                
                if wait_time > 0:
                    logger.warning(
                        "Rate limit approaching, throttling requests",
                        wait_time=wait_time,
                        current_requests=len(self._request_times),
                    )
                    await asyncio.sleep(wait_time)
            
            # Record this request
            self._request_times.append(now)

    def _open_circuit_breaker(self) -> None:
        """Open the circuit breaker."""
        self._is_circuit_open = True
        self._circuit_open_time = datetime.utcnow()
        
        logger.error(
            "Circuit breaker opened due to excessive failures",
            failure_count=self._failure_count,
            timeout_seconds=self.circuit_breaker_timeout,
        )

    def _close_circuit_breaker(self) -> None:
        """Close the circuit breaker and reset failure count."""
        self._is_circuit_open = False
        self._circuit_open_time = None
        self._failure_count = 0

    async def _log_retry_attempt(self, retry_state: RetryCallState) -> None:
        """Log retry attempts for debugging."""
        logger.warning(
            "Retrying failed request",
            attempt=retry_state.attempt_number,
            next_action=retry_state.next_action,
            outcome=str(retry_state.outcome) if retry_state.outcome else None,
        )

    def get_statistics(self) -> dict[str, Any]:
        """Get rate limiter usage statistics."""
        return {
            "total_requests": self._total_requests,
            "total_retries": self._total_retries,
            "total_rate_limit_hits": self._total_rate_limit_hits,
            "current_requests_per_minute": len(self._request_times),
            "circuit_breaker_open": self._is_circuit_open,
            "failure_count": self._failure_count,
            "circuit_open_time": self._circuit_open_time.isoformat()
            if self._circuit_open_time
            else None,
        }

    def reset_statistics(self) -> None:
        """Reset all statistics and state."""
        self._total_requests = 0
        self._total_retries = 0
        self._total_rate_limit_hits = 0
        self._request_times.clear()
        self._failure_count = 0
        self._close_circuit_breaker()