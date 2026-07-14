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
        # Use system DNS resolver instead of aiodns to avoid timeout issues
        connector = TCPConnector(
            limit=self.config.scanner['max_pool_size'],
            limit_per_host=50,
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

