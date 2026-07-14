"""Rate limiting, adaptive throttling and error handling."""

import asyncio
import logging
import random
import time
from collections import deque
from typing import Dict, Optional

import aiohttp


class RateLimiter:
    def __init__(self, requests_per_second: float, burst_size: int = 100):
        self.rate = requests_per_second
        self.burst_size = burst_size
        self.tokens = burst_size
        self.last_update = time.time()
        self.lock = asyncio.Lock()
        self.request_history = deque(maxlen=10000)
        
        # Adaptive rate limiting parameters
        self.error_count = 0
        self.success_count = 0
        self.adaptive_rate = requests_per_second
        self.min_rate = 10
        self.max_rate = requests_per_second * 2

    async def wait(self) -> bool:
        """Async wait for rate limit"""
        async with self.lock:
            now = time.time()
            time_passed = now - self.last_update
            self.tokens = min(
                self.burst_size,
                self.tokens + time_passed * self.rate
            )
            
            if self.tokens >= 1:
                self.tokens -= 1
                self.last_update = now
                self.request_history.append(now)
                return True
            
            # Calculate wait time
            wait_time = (1 - self.tokens) / self.rate
            await asyncio.sleep(wait_time)
            
            self.tokens -= 1
            self.last_update = time.time()
            self.request_history.append(self.last_update)
            return True

    async def adjust_rate(self, success: bool):
        """Dynamically adjust the rate based on success/failure"""
        async with self.lock:
            if success:
                self.success_count += 1
                self.error_count = max(0, self.error_count - 1)
                
                if self.success_count > 50:
                    self.adaptive_rate = min(
                        self.max_rate,
                        self.adaptive_rate * 1.2
                    )
                    self.success_count = 0
            else:
                self.error_count += 1
                self.success_count = 0
                
                if self.error_count > 5:
                    self.adaptive_rate = max(
                        self.min_rate,
                        self.adaptive_rate * 0.7
                    )
                    self.error_count = 0
            
            self.rate = self.adaptive_rate

class SmartThrottler:
    def __init__(self, requests_per_second: float = 1000, burst_size: int = 100):
        self.rate_limiter = RateLimiter(requests_per_second=requests_per_second, burst_size=burst_size)
        self.backoff_time = 0.1
        self.max_backoff = 5.0
        self.success_threshold = 20
        self.consecutive_successes = 0
        self.consecutive_failures = 0
        self.lock = asyncio.Lock()

    async def pre_request(self):
        """Called before making a request"""
        await self.rate_limiter.wait()

    async def post_request(self, success: bool):
        """Called after a request completes"""
        async with self.lock:
            if success:
                self.consecutive_successes += 1
                self.consecutive_failures = 0
                await self._decrease_backoff()
            else:
                self.consecutive_failures += 1
                self.consecutive_successes = 0
                await self._increase_backoff()
            
            await self.rate_limiter.adjust_rate(success)

    async def _increase_backoff(self):
        """Increase backoff time after failures"""
        self.backoff_time = min(
            self.max_backoff,
            self.backoff_time * 1.5
        )
        await asyncio.sleep(self.backoff_time)

    async def _decrease_backoff(self):
        """Decrease backoff time after successes"""
        if self.consecutive_successes >= self.success_threshold:
            self.backoff_time = max(
                0.1,
                self.backoff_time * 0.5
            )

class ErrorHandler:
    def __init__(self):
        self.throttler = SmartThrottler()
        self.max_retries = 3
        self.timeout_multiplier = 1.5
        self.current_timeout = 10
        self.error_counts: Dict[str, int] = {}
        self.waf_signatures = [
            'blocked',
            'forbidden',
            'waf',
            'security',
            'cloudflare',
            'protection'
        ]

    async def handle_error(self, url: str, error: Exception, response: Optional[aiohttp.ClientResponse] = None) -> bool:
        """Handle different types of errors and return True if request should be retried"""
        error_type = type(error).__name__
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1

        if isinstance(error, asyncio.TimeoutError):
            return await self.handle_timeout()
        elif isinstance(error, aiohttp.ClientError):
            if response and await self._detect_waf(response):
                return await self.handle_waf(url)
            return await self.handle_general_error()
        
        return False

    async def handle_timeout(self) -> bool:
        """Handle timeout errors"""
        self.current_timeout *= self.timeout_multiplier
        await self.throttler.post_request(success=False)
        return True

    async def handle_connection_error(self) -> bool:
        """Handle connection errors"""
        await asyncio.sleep(random.uniform(0.1, 0.5))
        await self.throttler.post_request(success=False)
        return True

    async def handle_waf(self, url: str) -> bool:
        """Handle WAF detection"""
        logging.warning(f"WAF detected for {url}. Adjusting strategy...")
        self.throttler.backoff_time *= 2
        await asyncio.sleep(random.uniform(1, 3))
        return True

    async def handle_general_error(self) -> bool:
        """Handle general errors"""
        should_retry = self.error_counts.get('general', 0) < self.max_retries
        if should_retry:
            await asyncio.sleep(random.uniform(0.1, 0.3))
        return should_retry

    async def _detect_waf(self, response: aiohttp.ClientResponse) -> bool:
        """Detect if response indicates WAF presence"""
        if response.status in [403, 406, 429, 456]:
            return True
            
        try:
            response_text = (await response.text()).lower()
            response_headers = str(response.headers).lower()
            
            for signature in self.waf_signatures:
                if signature in response_text or signature in response_headers:
                    return True
        except:
            pass
        
        return False

    def reset_error_counts(self):
        """Reset error counters"""
        self.error_counts.clear()
        self.current_timeout = 10

