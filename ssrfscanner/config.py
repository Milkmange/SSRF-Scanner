"""Runtime configuration."""


class Config:
    def __init__(self):
        self.scanner = {
            'concurrency': 200,  # Increased for better throughput
            'timeout': 15,  # Increased for reliability
            'retry_count': 2,
            'debug': False,
            'verify_ssl': False,
            'follow_redirects': True,
            'max_redirects': 3,
            'output_dir': "output",
            'user_agent': "SSRF-Scanner/1.0",
            'max_pool_size': 200,  # Connection pool size (auto-raised to >= concurrency)
            'limit_per_host': 0,   # 0 = auto (align with concurrency); set to throttle a single host
            'capture_cookies': True,
            'proxy': None,  # Proxy URL
            'proxy_auth': None  # Proxy authentication
        }
        self.rate_limiting = {
            'requests_per_second': 100,  # Increased default rate
            'burst_size': 200,
            'min_rate': 10,
            'max_rate': 1000
        }
        self.output = {
            'format': 'json',  # json, csv, html, txt, all
            'verbose': False
        }

    def get(self, key, default=None):
        return self.scanner.get(key, default)
