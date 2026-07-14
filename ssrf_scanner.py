#!/usr/bin/env python3
"""SSRF-Scanner CLI entrypoint.

The implementation now lives in the ``ssrfscanner`` package. This thin
wrapper preserves the original invocation:

    python3 ssrf_scanner.py -u https://example.com
"""

import asyncio

from ssrfscanner.cli import main

if __name__ == "__main__":
    asyncio.run(main())
