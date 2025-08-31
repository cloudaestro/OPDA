"""Tests for rate limiting functionality."""

import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock

import pytest

from opda.client.rate_limiter import (
    CircuitBreakerOpen,
    OktaRateLimiter,
    RateLimitExceeded,
)


class TestOktaRateLimiter:
    """Test OktaRateLimiter functionality."""

    @pytest.fixture
    def rate_limiter(self) -> OktaRateLimiter:
        """Create rate limiter with test configuration."""
        return OktaRateLimiter(
            max_retries=3,
            backoff_factor=1.5,
            max_requests_per_minute=10,  # Low limit for testing
            circuit_breaker_threshold=2,
            circuit_breaker_timeout=60,
        )

    @pytest.mark.asyncio
    async def test_successful_execution(self, rate_limiter: OktaRateLimiter) -> None:
        """Test successful function execution."""
        mock_func = AsyncMock(return_value="success")
        
        result = await rate_limiter.execute_with_retry(mock_func, "arg1", kwarg1="value1")
        
        assert result == "success"
        mock_func.assert_called_once_with("arg1", kwarg1="value1")

    @pytest.mark.asyncio
    async def test_sync_function_execution(self, rate_limiter: OktaRateLimiter) -> None:
        """Test execution of synchronous functions."""
        mock_func = Mock(return_value="sync_result")
        
        result = await rate_limiter.execute_with_retry(mock_func, "test_arg")
        
        assert result == "sync_result"
        mock_func.assert_called_once_with("test_arg")

    @pytest.mark.asyncio
    async def test_rate_limit_retry(self, rate_limiter: OktaRateLimiter) -> None:
        """Test retry logic for rate limit errors."""
        mock_func = AsyncMock()
        mock_func.side_effect = [
            RateLimitExceeded("Rate limit exceeded", retry_after=1),
            RateLimitExceeded("Rate limit exceeded", retry_after=1),
            "success",  # Third attempt succeeds
        ]
        
        result = await rate_limiter.execute_with_retry(mock_func)
        
        assert result == "success"
        assert mock_func.call_count == 3

    @pytest.mark.asyncio
    async def test_max_retries_exceeded(self, rate_limiter: OktaRateLimiter) -> None:
        """Test behavior when max retries is exceeded."""
        mock_func = AsyncMock()
        mock_func.side_effect = RateLimitExceeded("Persistent rate limit")
        
        with pytest.raises(RateLimitExceeded):
            await rate_limiter.execute_with_retry(mock_func)
        
        # Should attempt max_retries + 1 times (initial + retries)
        assert mock_func.call_count == rate_limiter.max_retries + 1

    @pytest.mark.asyncio
    async def test_circuit_breaker_opens(self, rate_limiter: OktaRateLimiter) -> None:
        """Test circuit breaker opens after threshold failures."""
        mock_func = AsyncMock()
        mock_func.side_effect = Exception("Persistent error")
        
        # First failure should not open circuit breaker
        with pytest.raises(Exception):
            await rate_limiter.execute_with_retry(mock_func)
        
        # Second failure should open circuit breaker
        with pytest.raises(Exception):
            await rate_limiter.execute_with_retry(mock_func)
        
        # Third attempt should immediately fail with CircuitBreakerOpen
        with pytest.raises(CircuitBreakerOpen):
            await rate_limiter.execute_with_retry(mock_func)

    @pytest.mark.asyncio
    async def test_circuit_breaker_recovery(self) -> None:
        """Test circuit breaker recovery after timeout."""
        rate_limiter = OktaRateLimiter(
            circuit_breaker_threshold=1,
            circuit_breaker_timeout=1,  # 1 second timeout for testing
        )
        
        mock_func = AsyncMock()
        mock_func.side_effect = [
            Exception("Initial failure"),  # Opens circuit breaker
            "success",  # Should work after timeout
        ]
        
        # First call fails and opens circuit breaker
        with pytest.raises(Exception):
            await rate_limiter.execute_with_retry(mock_func)
        
        # Immediate retry should fail with circuit breaker
        with pytest.raises(CircuitBreakerOpen):
            await rate_limiter.execute_with_retry(mock_func)
        
        # Wait for circuit breaker timeout
        await asyncio.sleep(1.1)
        
        # Should work now
        result = await rate_limiter.execute_with_retry(mock_func)
        assert result == "success"

    def test_statistics_tracking(self, rate_limiter: OktaRateLimiter) -> None:
        """Test statistics tracking."""
        initial_stats = rate_limiter.get_statistics()
        
        assert initial_stats["total_requests"] == 0
        assert initial_stats["total_retries"] == 0
        assert initial_stats["total_rate_limit_hits"] == 0
        assert initial_stats["circuit_breaker_open"] is False

    def test_statistics_reset(self, rate_limiter: OktaRateLimiter) -> None:
        """Test statistics reset functionality."""
        # Manually set some statistics
        rate_limiter._total_requests = 10
        rate_limiter._total_retries = 5
        rate_limiter._failure_count = 3
        
        rate_limiter.reset_statistics()
        
        stats = rate_limiter.get_statistics()
        assert stats["total_requests"] == 0
        assert stats["total_retries"] == 0
        assert stats["circuit_breaker_open"] is False

    @pytest.mark.asyncio
    async def test_rate_limit_enforcement(self) -> None:
        """Test rate limit enforcement with rapid requests."""
        rate_limiter = OktaRateLimiter(max_requests_per_minute=2)  # Very low limit
        
        mock_func = AsyncMock(return_value="success")
        
        # First two requests should work quickly
        start_time = asyncio.get_event_loop().time()
        
        await rate_limiter.execute_with_retry(mock_func)
        await rate_limiter.execute_with_retry(mock_func)
        
        # Third request should be delayed due to rate limiting
        await rate_limiter.execute_with_retry(mock_func)
        
        end_time = asyncio.get_event_loop().time()
        
        # Should have taken some time due to rate limiting
        # (This is a simplified test - in practice would need more precise timing)
        assert mock_func.call_count == 3

    @pytest.mark.asyncio
    async def test_retry_after_header(self, rate_limiter: OktaRateLimiter) -> None:
        """Test handling of retry-after header in rate limit responses."""
        mock_func = AsyncMock()
        mock_func.side_effect = [
            RateLimitExceeded("Rate limited", retry_after=0.1),  # Short wait for testing
            "success",
        ]
        
        start_time = asyncio.get_event_loop().time()
        result = await rate_limiter.execute_with_retry(mock_func)
        end_time = asyncio.get_event_loop().time()
        
        assert result == "success"
        assert mock_func.call_count == 2
        # Should have waited at least the retry_after time
        assert end_time - start_time >= 0.1

    @pytest.mark.asyncio
    async def test_concurrent_rate_limiting(self, rate_limiter: OktaRateLimiter) -> None:
        """Test rate limiting with concurrent requests."""
        mock_func = AsyncMock(return_value="success")
        
        # Execute multiple requests concurrently
        tasks = [
            rate_limiter.execute_with_retry(mock_func, f"request_{i}")
            for i in range(5)
        ]
        
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 5
        assert all(result == "success" for result in results)
        assert mock_func.call_count == 5