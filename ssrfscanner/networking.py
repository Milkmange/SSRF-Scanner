"""HTTP session management and low-level request handling."""

import logging
import ssl
from typing import Optional

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector

from .throttling import ErrorHandler, SmartThrottler


class RequestManager:
    def __init__(self, config):
        self.error_handler = ErrorHandler()
        self.throttler = SmartThrottler()
        self.config = config
        self.session = None

    async def create_session(self):
        """Create and configure aiohttp session"""
        concurrency = self.config.scanner.get('concurrency', 100)

        # The overall connection pool must be at least as large as the
        # concurrency semaphore, otherwise coroutines block waiting for a free
        # connection and the effective concurrency is silently capped.
        pool_limit = max(self.config.scanner.get('max_pool_size', 100), concurrency)

        # Per-host limit is the real throttle for single-target scans. Default
        # (0/None) => align with concurrency so raising --concurrency actually
        # takes effect; set --limit-per-host to a smaller value to be gentle.
        configured_lph = self.config.scanner.get('limit_per_host', 0) or 0
        limit_per_host = configured_lph if configured_lph > 0 else concurrency

        # Use system DNS resolver instead of aiodns to avoid timeout issues
        connector = TCPConnector(
            limit=pool_limit,
            limit_per_host=limit_per_host,
            ttl_dns_cache=300,
            ssl=False if not self.config.scanner['verify_ssl'] else ssl.create_default_context(),
            use_dns_cache=True,
            family=0  # Allow both IPv4 and IPv6
        )
        
        timeout = ClientTimeout(
            total=self.config.scanner['timeout'] * 2,  # Double timeout for DNS + request
            connect=self.config.scanner['timeout'],
            sock_read=self.config.scanner['timeout'],
            sock_connect=self.config.scanner['timeout']
        )
        
        # Configure proxy if provided
        session_kwargs = {
            'connector': connector,
            'timeout': timeout,
            'headers': {'User-Agent': self.config.scanner['user_agent']}
        }
        
        # Add proxy configuration
        if self.config.scanner.get('proxy'):
            session_kwargs['trust_env'] = True
        
        self.session = ClientSession(**session_kwargs)
        return self.session

    async def close_session(self):
        """Close the aiohttp session"""
        if self.session:
            await self.session.close()

    async def make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make an async request with error handling and rate limiting"""
        retries = 0
        max_retries = 3

        while retries < max_retries:
            try:
                await self.throttler.pre_request()
                
                async with self.session.request(method, url, **kwargs) as response:
                    # Read response to ensure it's complete
                    await response.read()
                    await self.throttler.post_request(success=True)
                    self.error_handler.reset_error_counts()
                    return response

            except Exception as e:
                retries += 1
                should_retry = await self.error_handler.handle_error(url, e, None)
                
                if not should_retry or retries >= max_retries:
                    if self.config.scanner['debug']:
                        logging.error(f"Max retries reached for {url}: {str(e)}")
                    return None

        return None

