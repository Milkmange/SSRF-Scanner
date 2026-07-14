"""SSRF-Scanner package.

A comprehensive, high-performance SSRF vulnerability scanner split into
focused modules:

- config:      Config
- progress:    ScanProgress
- models:      ScanResult dataclass
- payloads:    PayloadGenerator, ProtocolHandler
- throttling:  RateLimiter, SmartThrottler, ErrorHandler
- networking:  RequestManager
- reporting:   Reporter
- scanner:     SSRFScanner (orchestration + attack phases + detection)
- banner:      printBanner, print_help
- cli:         main entrypoint
"""

__version__ = 'version 1.0'
