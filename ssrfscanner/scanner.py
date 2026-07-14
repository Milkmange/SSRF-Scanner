"""Core SSRF scanner: orchestration, attack phases and detection."""

import asyncio
import base64
import logging
import os
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from urllib.parse import (
    urlparse,
    quote,
    unquote,
    parse_qsl,
    urlencode,
    urlunparse,
)

import aiohttp
from aiohttp import ClientTimeout
from colorama import Fore

from .banner import printBanner
from .blindlib import BlindPayloadLibrary
from .config import Config
from .models import ScanResult
from .networking import RequestManager
from .oob import NullOOB, SelfHostedOOB
from .payloads import PayloadGenerator, ProtocolHandler
from .progress import ScanProgress
from .reporting import Reporter
from .throttling import ErrorHandler, SmartThrottler


class SSRFScanner:
    # Anchored, high-signal byte sequences that only appear when internal data
    # is actually exfiltrated. Shared by response-diff analysis and the blind
    # phase's signature-only detection. Loose substrings (token/secret/AWS/...)
    # are deliberately avoided - they match ordinary pages and cause noise.
    SSRF_CONTENT_SIGNATURES = [
        b'root:x:0:0:',                          # /etc/passwd (Linux)
        b'root:*:0:0:',                          # /etc/passwd (BSD/macOS)
        b'<title>Index of',                      # directory listing
        b'-----BEGIN RSA PRIVATE KEY-----',      # private key
        b'-----BEGIN PRIVATE KEY-----',          # private key
        b'-----BEGIN OPENSSH PRIVATE KEY-----',  # OpenSSH private key
        b'ssh-rsa ',                             # public key material
        b'security-credentials',                 # AWS IMDS IAM creds path
        b'"AccessKeyId"',                        # AWS credential document
        b'"SecretAccessKey"',                    # AWS credential document
        b'ami-id',                               # AWS EC2 metadata
        b'instance-identity',                    # AWS EC2 metadata
        b'computeMetadata',                      # GCP metadata
        b'Metadata-Flavor',                      # GCP metadata header echo
    ]

    def __init__(self):
        printBanner()
        
        # Initialize configuration
        self.config = Config()
        
        # Initialize components
        self.request_manager = RequestManager(self.config)
        self.error_handler = ErrorHandler()
        self.throttler = SmartThrottler()
        self.payload_generator = PayloadGenerator()
        self.protocol_handler = ProtocolHandler()
        
        # Static headers applied to all requests (set via -H/--header)
        self.static_headers = {}
        
        # Initialize async primitives
        self.semaphore = None  # Will be created in async context
        self.lock = None  # Async lock, created in async context
        self.file_lock = None  # Threading lock for file I/O
        
        # Setup logging first
        self.setup_logging()
        
        # Initialize payload lists
        self.local_ips = []
        self.headers = []
        self.cloud_metadata = []
        self.protocols = []
        self.encoded_payloads = []
        self.parameter_payloads = []
        self.port_payloads = []
        self.dns_rebinding = []
        self.crlf_injection = []
        self.scheme_confusion = []
        self.waf_bypass = []
        self.blind_lib = None  # BlindPayloadLibrary, loaded in load_all_payloads
        
        # Initialize counters and settings
        self.nrTotUrls = 0
        self.nrUrlsAnalyzed = 0
        self.nrErrorUrl = 0
        self.backurl = ""
        self.cookies = None
        self.quiet_mode = False

        # Out-of-band (OOB) confirmation. Disabled by default (NullOOB); set up
        # in run() from the --oob-* CLI options.
        self.oob = NullOOB()
        self.oob_mode = 'off'          # 'off' | 'selfhosted'
        self.oob_listen = '0.0.0.0:8000'
        self.oob_domain = ''           # public authority with wildcard DNS
        self.oob_wait = 8              # seconds to wait for late callbacks
        
        # Request tracking
        self.total_requests_attempted = 0
        self.total_requests_succeeded = 0
        self.total_requests_failed = 0
        self.failure_reasons = {}
        self.response_codes = {}  # Track response codes
        self.scan_start_time = None
        
        # Initialize progress tracking
        self.progress = ScanProgress()
        
        # Setup output
        self.output_filename = datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p")
        self.setup_output_files()
        
        # Load payloads last
        self.load_all_payloads()
        
        # Initialize reporter (will be updated with format in run())
        self.reporter = None


    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO if not self.config.scanner['debug'] else logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('ssrf_scanner')

    def setup_output_files(self):
        """Setup output directory and files"""
        self.output_dir = f"output/{self.output_filename}"
        os.makedirs(self.output_dir, exist_ok=True)
        self.txt_output = f"{self.output_dir}/scan.txt"
        self.csv_output = f"{self.output_dir}/scan.csv"
        self.json_output = f"{self.output_dir}/scan.json"

    def load_all_payloads(self):
        """Load all payload files from the payloads directory"""
        payload_dir = "payloads"
        
        # Create payloads directory if it doesn't exist
        if not os.path.exists(payload_dir):
            os.makedirs(payload_dir)
            self.logger.warning(f"Created {payload_dir} directory")
        
        payload_files = {
            'local_ips.txt': self.local_ips,
            'headers.txt': self.headers,
            'cloud_metadata.txt': self.cloud_metadata,
            'protocols.txt': self.protocols,
            'encoded_payloads.txt': self.encoded_payloads,
            'parameter_payloads.txt': self.parameter_payloads,
            'port_payloads.txt': self.port_payloads,
            'dns_rebinding.txt': self.dns_rebinding,
            'crlf_injection.txt': self.crlf_injection,
            'scheme_confusion.txt': self.scheme_confusion,
            'waf_bypass.txt': self.waf_bypass
        }

        for filename, payload_list in payload_files.items():
            filepath = os.path.join(payload_dir, filename)
            try:
                if not os.path.exists(filepath):
                    # Create empty file if it doesn't exist
                    with open(filepath, 'w') as f:
                        f.write("# Add your payloads here\n")
                    self.logger.warning(f"Created empty payload file: {filename}")
                else:
                    with open(filepath, 'r') as f:
                        payload_list.extend([line.strip() for line in f if line.strip() and not line.startswith('#')])
                        self.logger.info(f"Loaded {len(payload_list)} payloads from {filename}")
            except Exception as e:
                self.logger.error(f"Error processing {filename}: {str(e)}")

        # Load the bundled blind-SSRF / CVE-probe template library (JSON).
        blind_path = os.path.join(payload_dir, "blind-ssrf-payloads.json")
        try:
            self.blind_lib = BlindPayloadLibrary(blind_path, logger=self.logger)
        except Exception as e:
            self.logger.error(f"Error loading blind payload library: {str(e)}")
            self.blind_lib = None

    async def make_request(self, url, method='GET', headers=None, timeout=None):
        """Async request method with rate limiting and error handling"""
        try:
            default_headers = {
                'User-Agent': self.config.scanner['user_agent'],
                'Accept': '*/*'
            }

            # Apply static headers set from CLI (-H/--header), e.g. Authorization
            if hasattr(self, "static_headers") and self.static_headers:
                default_headers.update(self.static_headers)            
           
            if headers:
                default_headers.update(headers)

            if self.cookies:
                if isinstance(self.cookies, str):
                    default_headers['Cookie'] = self.cookies
                elif isinstance(self.cookies, dict):
                    default_headers['Cookie'] = '; '.join([f'{k}={v}' for k, v in self.cookies.items()])

            # Prepare request kwargs
            request_kwargs = {
                'method': method,
                'url': url,
                'headers': default_headers,
                'timeout': ClientTimeout(total=timeout or self.config.scanner['timeout']),
                'ssl': False if not self.config.scanner['verify_ssl'] else None,
                'allow_redirects': self.config.scanner['follow_redirects']
            }
            
            # Add proxy if configured
            if self.config.scanner.get('proxy'):
                request_kwargs['proxy'] = self.config.scanner['proxy']
                if self.config.scanner.get('proxy_auth'):
                    auth_parts = self.config.scanner['proxy_auth'].split(':')
                    if len(auth_parts) == 2:
                        request_kwargs['proxy_auth'] = aiohttp.BasicAuth(auth_parts[0], auth_parts[1])

            self.total_requests_attempted += 1
            
            async with self.semaphore:
                # Rate limiting: block until a token is available so we honor
                # the configured --rate-limit (and adaptive backoff on errors).
                await self.throttler.pre_request()

                request_start = time.perf_counter()
                async with self.request_manager.session.request(**request_kwargs) as response:
                    # Read response body
                    body = await response.read()
                    elapsed_seconds = time.perf_counter() - request_start

                    # Feed the throttler so it can adapt the rate on success
                    await self.throttler.post_request(success=True)

                    # Track successful request
                    self.total_requests_succeeded += 1
                    
                    # Track response code
                    status_code = response.status
                    self.response_codes[status_code] = self.response_codes.get(status_code, 0) + 1
                    
                    # Update progress every 10 successful requests
                    if self.total_requests_succeeded % 10 == 0:
                        self.print_progress()
                    
                    # Check for Set-Cookie header
                    if self.config.scanner['capture_cookies'] and 'Set-Cookie' in response.headers and not self.cookies:
                        self.cookies = response.headers['Set-Cookie']
                        if self.config.scanner['debug']:
                            self.logger.info(f"Captured cookies from response")

                    # Create a response-like object with necessary attributes
                    class ResponseWrapper:
                        def __init__(self, status, headers, body, url, elapsed):
                            self.status_code = status
                            self.headers = headers
                            self.content = body
                            self.text = body.decode('utf-8', errors='ignore')
                            self.url = url
                            # timedelta so callers can use .total_seconds()
                            self.elapsed = timedelta(seconds=elapsed)

                    return ResponseWrapper(response.status, response.headers, body, url, elapsed_seconds)
            
        except asyncio.TimeoutError:
            self.total_requests_failed += 1
            self.failure_reasons['timeout'] = self.failure_reasons.get('timeout', 0) + 1
            # Let the throttler adapt (slow down) after a failure
            await self.throttler.post_request(success=False)
            # Update progress on failures too
            if self.total_requests_failed % 50 == 0:
                self.print_progress()
            if self.config.scanner['debug']:
                self.logger.error(f"Timeout for {url}")
            return None
        except aiohttp.ClientError as e:
            self.total_requests_failed += 1
            error_type = type(e).__name__
            self.failure_reasons[error_type] = self.failure_reasons.get(error_type, 0) + 1
            # Let the throttler adapt (slow down) after a failure
            await self.throttler.post_request(success=False)
            # Update progress on failures too
            if self.total_requests_failed % 50 == 0:
                self.print_progress()
            if self.config.scanner['debug']:
                self.logger.error(f"Client error for {url}: {str(e)}")
            return None
        except Exception as e:
            self.total_requests_failed += 1
            error_type = type(e).__name__
            self.failure_reasons[error_type] = self.failure_reasons.get(error_type, 0) + 1
            # Let the throttler adapt (slow down) after a failure
            await self.throttler.post_request(success=False)
            # Update progress on failures too
            if self.total_requests_failed % 50 == 0:
                self.print_progress()
            if self.config.scanner['debug']:
                self.logger.error(f"Request failed for {url}: {error_type}: {str(e)}")
            return None


    def _ssrf_signature(self, response):
        """Return the first anchored SSRF content signature found, else None.

        High-confidence, path-independent detection: it only matches when the
        response body actually contains exfiltrated internal data (credentials,
        /etc/passwd, cloud-metadata markers, private keys).
        """
        if not response:
            return None
        content = response.content
        for indicator in self.SSRF_CONTENT_SIGNATURES:
            if indicator in content:
                return indicator.decode('utf-8', errors='ignore')
        return None

    def analyze_response(self, original_response, test_response):
        """Analyze differences between original and test responses with smart detection"""
        if not test_response:
            return False, {}

        # Don't flag rate limiting as vulnerability
        if test_response.status_code == 429:
            return False, {}

        # Basic differences
        differences = {
            'status_code_changed': original_response.status_code != test_response.status_code,
            'content_length': len(original_response.content) != len(test_response.content),
            'content_type': original_response.headers.get('content-type') != 
                          test_response.headers.get('content-type'),
            'word_count': len(original_response.text.split()) != 
                         len(test_response.text.split())
        }
        
        # Use baseline if available for smarter detection
        if hasattr(self, 'baseline') and self.baseline:
            # Check if status code differs from baseline (HIGH PRIORITY)
            # But ignore rate limiting
            if test_response.status_code not in self.baseline['status_codes'] and test_response.status_code != 429:
                differences['unexpected_status'] = True
                differences['baseline_status'] = list(self.baseline['status_codes'])
                differences['test_status'] = test_response.status_code
                # Status code change is always significant
                return True, differences
            
            # If baseline is stable and response differs significantly, it's interesting
            if self.baseline['stable']:
                length_diff = abs(len(test_response.content) - self.baseline['avg_length'])
                # Flag if difference is > 10% of baseline
                if length_diff > self.baseline['avg_length'] * 0.1:
                    differences['significant_size_change'] = True
                    differences['size_diff_percent'] = (length_diff / self.baseline['avg_length']) * 100
        else:
            # No baseline - use original response for comparison
            if differences['status_code_changed']:
                differences['unexpected_status'] = True
                differences['baseline_status'] = [original_response.status_code]
                differences['test_status'] = test_response.status_code
                return True, differences
        
        # Look for anchored SSRF content signatures (shared class constant).
        signature = self._ssrf_signature(test_response)
        if signature:
            differences['ssrf_indicator'] = signature
            return True, differences  # Definite hit
        
        # Flag if we have significant differences
        significant_diffs = ['status_code_changed', 'significant_size_change', 'unexpected_status', 'ssrf_indicator']
        has_significant = any(differences.get(k, False) for k in significant_diffs)
        
        # Additional check: if status code matches baseline and no SSRF indicators, not vulnerable
        if hasattr(self, 'baseline') and self.baseline:
            if (test_response.status_code in self.baseline['status_codes'] and 
                'ssrf_indicator' not in differences):
                # Status matches baseline and no suspicious content - likely not vulnerable
                return False, differences
        
        return has_significant, differences

    def _estimate_requests_per_url(self) -> int:
        """Best-effort estimate of requests issued per URL across all phases.

        Approximate (dedup and query-param count are not known up front) but it
        scales with the actual loaded payloads/phases, unlike the old hardcoded
        constant. Used only to drive the progress percentage.
        """
        h = max(len(self.headers), 1)
        li = len(self.local_ips)
        li5 = min(li, 5)
        li3 = min(li, 3)
        est = 0
        est += h * li * 12                                   # Local IP (variations+encodings)
        est += h * len(self.cloud_metadata) * 6              # Cloud Metadata (encodings)
        est += h * len(self.protocols) * li5 * 6             # Protocol
        est += h * len(self.encoded_payloads) * 5            # Encoded
        est += len(self.parameter_payloads)                  # Parameter
        est += h * len(self.port_payloads) * li5             # Port Scan
        est += h * len(self.dns_rebinding)                   # DNS Rebinding
        est += h * len(self.crlf_injection) * li3 * 2        # CRLF Injection
        est += h * (len(self.scheme_confusion) + len(self.protocols) * li5)  # Scheme Confusion
        est += h * max(len(self.waf_bypass), 1)              # WAF Bypass (roughly, deduped)
        if self.blind_lib:                                   # Blind SSRF
            est += 16 if not self._has_callback_target() else self.blind_lib.count()
        if self._has_callback_target():                      # Remote
            est += h * 10
        return max(est, 1)

    def print_progress(self):
        """Print scan progress with phase information and percentages"""
        if self.quiet_mode:
            return
            
        # Non-blocking progress print (no lock needed for reading)
        total_progress = self.progress.get_total_progress()
        current_phase = self.progress.current_phase or "Initializing"
        
        # Clear line and move cursor to beginning
        print('\r' + ' ' * 150 + '\r', end='', flush=True)
        
        # Calculate success rate
        success_rate = 0
        if self.total_requests_attempted > 0:
            success_rate = (self.total_requests_succeeded / self.total_requests_attempted) * 100
        
        # Calculate requests per second
        req_per_sec = 0
        if hasattr(self, 'scan_start_time'):
            elapsed = time.time() - self.scan_start_time
            if elapsed > 0:
                req_per_sec = self.total_requests_succeeded / elapsed
        
        # Progress based on an estimate derived from the loaded payloads and
        # active phases (computed once in run()); far more accurate than the
        # old hardcoded constant now that phases/payloads have changed.
        estimated_total = getattr(self, 'estimated_total_requests', 0) or 1
        actual_progress = min(self.total_requests_attempted / estimated_total * 100, 100)
        
        # Print progress information with request stats
        print(f"URLs: {self.nrUrlsAnalyzed}/{self.nrTotUrls} | "
              f"Requests: {self.total_requests_succeeded:,}/{self.total_requests_attempted:,} "
              f"({req_per_sec:.1f} req/s) | "
              f"Phase: {current_phase} | "
              f"Progress: {actual_progress:.1f}%", end='', flush=True)

    def update_progress(self, phase, completed, total):
        """Update progress for a specific phase"""
        progress = (completed / total * 100) if total > 0 else 100
        self.progress.update_phase(phase, progress/100)
        self.print_progress()

    async def perform_attack(self, url: str, attack_type: str, payload: str, headers: Dict[str, str], original_response) -> Optional[ScanResult]:
        """Perform an attack and record the result"""
        try:
            response = await self.make_request(url, headers=headers)
            if not response:
                return None

            is_vulnerable, differences = self.analyze_response(original_response, response)
            
            result = ScanResult(
                url=url,
                attack_type=attack_type,
                payload=payload,
                response_code=response.status_code,
                response_size=len(response.content),
                timestamp=datetime.now(),
                headers=headers,
                is_vulnerable=is_vulnerable,
                notes=str(differences) if differences else ""
            )

            if is_vulnerable:
                result.verification_method = self.verify_vulnerability(url, payload, response, original_response)
                self.reporter.add_result(result)

            return result

        except Exception as e:
            if self.config.scanner['debug']:
                self.logger.error(f"Error performing {attack_type} attack on {url}: {str(e)}")
            return None

    @staticmethod
    def _unique(seq):
        """Return items from seq with duplicates removed, preserving order."""
        seen = set()
        result = []
        for item in seq:
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result

    async def localAttack(self, url, original_response):
        """Enhanced local IP attack with payload generation"""
        base_ips = self.local_ips.copy()

        # Generate IP variations, then their URL-encoding variations, and
        # deduplicate. Both generators emit overlapping quote()/double-quote
        # forms, so building a unique payload set here avoids sending many
        # identical requests (large reduction with no loss of coverage).
        payloads = []
        for ip in base_ips:
            for variation in self.payload_generator.generate_ip_variations(ip):
                payloads.extend(self.payload_generator.generate_url_encodings(variation))
        payloads = self._unique(payloads)

        total_tests = len(self.headers) * len(payloads)
        completed_tests = 0

        tasks = []
        for header in self.headers:
            for payload in payloads:
                badHeader = {header: payload}
                tasks.append(self.perform_attack(url, 'LocalIP', payload, badHeader, original_response))
        
        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ScanResult) and result.is_vulnerable:
                self.log_vulnerability(result)
            completed_tests += 1
            if completed_tests % 100 == 0:
                self.update_progress('Local IP', completed_tests, total_tests)

    async def cloudMetadataAttack(self, url, original_response):
        """Enhanced cloud metadata attack with payload variations"""
        # Build a deduplicated payload set from all metadata endpoints and
        # their encoding variations before dispatching per header.
        payloads = []
        for metadata_url in self.cloud_metadata:
            payloads.extend(self.payload_generator.generate_url_encodings(metadata_url))
        payloads = self._unique(payloads)

        total_tests = len(self.headers) * len(payloads)
        completed_tests = 0

        tasks = []
        for header in self.headers:
            for payload in payloads:
                badHeader = {header: payload}
                tasks.append(self.perform_attack(url, 'CloudMetadata', payload, badHeader, original_response))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ScanResult) and result.is_vulnerable:
                self.log_vulnerability(result)
            completed_tests += 1
            if completed_tests % 50 == 0:
                self.update_progress('Cloud Metadata', completed_tests, total_tests)

    async def protocolAttack(self, url, original_response):
        """Enhanced protocol attack with protocol-specific handlers"""
        total_tests = len(self.headers) * len(self.protocols) * min(len(self.local_ips), 5)
        completed_tests = 0
        
        tasks = []
        for header in self.headers:
            for protocol in self.protocols:
                for ip in self.local_ips[:5]:
                    # Get protocol-specific payloads
                    if protocol == 'gopher://':
                        payloads = self.protocol_handler.handle_gopher(ip)
                    elif protocol == 'dict://':
                        payloads = self.protocol_handler.handle_dict(ip)
                    elif protocol == 'file://':
                        payloads = self.protocol_handler.handle_file(ip)
                    else:
                        payloads = self.payload_generator.generate_protocol_variations(protocol, ip)
                    
                    for payload in payloads:
                        badHeader = {header: payload}
                        tasks.append(self.perform_attack(url, 'Protocol', payload, badHeader, original_response))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ScanResult) and result.is_vulnerable:
                self.log_vulnerability(result)
            completed_tests += 1
            if completed_tests % 50 == 0:
                self.update_progress('Protocol', completed_tests, total_tests)

    async def encodedAttack(self, url, original_response):
        """Enhanced encoded attack with multiple encoding variations"""
        # Build a deduplicated set of encoded payloads. Some encodings collapse
        # to the base payload (e.g. when it contains no '.' or '/'), so dedup
        # trims redundant requests.
        payloads = []
        for base_payload in self.encoded_payloads:
            payloads.extend([
                base_payload,
                quote(base_payload),
                quote(quote(base_payload)),
                base64.b64encode(base_payload.encode()).decode(),
                base_payload.replace('.', '%2e').replace('/', '%2f'),
            ])
        payloads = self._unique(payloads)

        total_tests = len(self.headers) * len(payloads)
        completed_tests = 0

        tasks = []
        for header in self.headers:
            for payload in payloads:
                badHeader = {header: payload}
                tasks.append(self.perform_attack(url, 'Encoded', payload, badHeader, original_response))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ScanResult) and result.is_vulnerable:
                self.log_vulnerability(result)
            completed_tests += 1
            if completed_tests % 50 == 0:
                self.update_progress('Encoded', completed_tests, total_tests)

    async def parameterAttack(self, url, original_response):
        """Perform SSRF attack using parameter injection"""
        total_tests = len(self.parameter_payloads)
        completed_tests = 0
        
        tasks = []
        for param in self.parameter_payloads:
            # Payload lines carry their own leading '?' by convention. Strip it
            # so we don't emit malformed URLs like 'host??url=...' (or a param
            # literally named '?url' when the base URL already has a query).
            clean_param = param.lstrip('?&')
            separator = '&' if '?' in url else '?'
            test_url = f"{url}{separator}{clean_param}"

            tasks.append(self.make_request(test_url))
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for param, response in zip(self.parameter_payloads, responses):
            completed_tests += 1
            if completed_tests % 20 == 0:
                self.update_progress('Parameter', completed_tests, total_tests)
            
            if response and not isinstance(response, Exception):
                is_vulnerable, differences = self.analyze_response(original_response, response)
                if is_vulnerable:
                    result = ScanResult(
                        url=url,
                        attack_type='Parameter',
                        payload=param,
                        response_code=response.status_code,
                        response_size=len(response.content),
                        timestamp=datetime.now(),
                        headers={},
                        is_vulnerable=True,
                        notes=str(differences)
                    )
                    self.log_vulnerability(result)

    def _oob_enabled(self) -> bool:
        """True when an out-of-band listener is active."""
        return getattr(self, 'oob', None) is not None and self.oob.enabled

    def _callback(self, attack_type: str, payload: str, target_url: str) -> str:
        """Return a callback authority to embed in a payload.

        When OOB is active this mints a unique, correlatable per-payload
        authority (``<token>.<domain>``). Otherwise it falls back to the static
        --backurl so existing manual (Burp Collaborator) workflows are unchanged.
        """
        if self._oob_enabled():
            return self.oob.new_callback(attack_type, payload, target_url)
        return self.backurl

    def _has_callback_target(self) -> bool:
        """Whether any callback destination is configured (OOB or --backurl)."""
        return self._oob_enabled() or bool(self.backurl)

    async def parameterCallbackAttack(self, url, original_response):
        """
        For URLs that already have query parameters, replace each parameter's value
        with SSRF callback-style payloads (Burp Collaborator / backurl variations).
        """
        # Parse URL and check for existing query params
        parsed = urlparse(url)
        if not parsed.query:
            # No parameters to replace, nothing to do
            return

        # Original query params as list of (name, value) pairs
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)

        if not self._has_callback_target():
            # No callback destination (neither OOB nor --backurl); nothing to do.
            return

        def _callback_payloads_for(cb):
            """Build callback-style payload variations for a given authority."""
            payloads = [
                cb,
                f"http://{cb}",
                f"https://{cb}",
                f"{cb}/ssrf-test",
                f"{cb}?callback=true",
                f"http://{cb}:80",
                f"http://{cb}:443",
                f"http://{cb}:8080",
                quote(f"http://{cb}"),
                quote(quote(f"http://{cb}")),
            ]
            # DNS rebinding payloads (same semantics as dnsRebindingAttack)
            for dns in self.dns_rebinding:
                payload = dns
                if '<BURP-COLLABORATOR>' in dns:
                    payload = dns.replace('<BURP-COLLABORATOR>', cb)
                payloads.append(payload)
            return list(dict.fromkeys(payloads))

        tasks = []
        meta = []  # (param_name, payload, test_url)
        total_tests = 0

        # For each parameter, mint its own callback so an OOB hit identifies the
        # exact parameter that is the SSRF sink.
        for idx, (name, value) in enumerate(query_pairs):
            cb = self._callback('ParameterCallback', f'param={name}', url)
            callback_payloads = _callback_payloads_for(cb)
            total_tests += len(callback_payloads)
            for payload in callback_payloads:
                # Create a new list of query params with this one modified
                new_pairs = [
                    (n, payload if i == idx else v)
                    for i, (n, v) in enumerate(query_pairs)
                ]
                new_query = urlencode(new_pairs, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))

                tasks.append(self.make_request(new_url))
                meta.append((name, payload, new_url))

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for (param_name, payload, test_url), response in zip(meta, responses):
            completed_tests += 1
            # Re-use "Parameter" phase for progress
            if completed_tests % 20 == 0:
                self.update_progress('Parameter', completed_tests, total_tests)

            if not response or isinstance(response, Exception):
                continue

            is_vulnerable, differences = self.analyze_response(original_response, response)
            if is_vulnerable:
                # Record the finding
                result = ScanResult(
                    url=test_url,
                    attack_type='ParameterCallback',
                    payload=f"{param_name}={payload}",
                    response_code=response.status_code,
                    response_size=len(response.content),
                    timestamp=datetime.now(),
                    headers={},  # this attack is URL-parameter-based
                    is_vulnerable=True,
                    notes=str(differences)
                )
                # Try to verify with existing verification logic
                result.verification_method = self.verify_vulnerability(
                    test_url,
                    payload,
                    response,
                    original_response
                )
                # Log + report
                self.log_vulnerability(result)
                if self.reporter:
                    self.reporter.add_result(result)

    async def portScanAttack(self, url, original_response):
        """Perform SSRF port scan attack"""
        total_tests = len(self.headers) * len(self.port_payloads) * min(len(self.local_ips), 5)
        completed_tests = 0
        
        tasks = []
        for header in self.headers:
            for port in self.port_payloads:
                for ip in self.local_ips[:5]:
                    payload = f"{ip}{port}"
                    badHeader = {header: payload}
                    tasks.append(self.perform_attack(url, 'PortScan', payload, badHeader, original_response))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ScanResult) and result.is_vulnerable:
                self.log_vulnerability(result)
            completed_tests += 1
            if completed_tests % 50 == 0:
                self.update_progress('Port Scan', completed_tests, total_tests)

    async def dnsRebindingAttack(self, url, original_response):
        """Perform DNS rebinding attack"""
        total_tests = len(self.headers) * len(self.dns_rebinding)
        completed_tests = 0
        
        tasks = []
        for header in self.headers:
            # One callback authority per header for OOB attribution.
            cb = self._callback('DNSRebinding', f'header={header}', url) if self._has_callback_target() else ''
            for dns in self.dns_rebinding:
                payload = dns
                if '<BURP-COLLABORATOR>' in dns and cb:
                    payload = dns.replace('<BURP-COLLABORATOR>', cb)

                badHeader = {header: payload}
                tasks.append(self.perform_attack(url, 'DNSRebinding', payload, badHeader, original_response))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ScanResult) and result.is_vulnerable:
                self.log_vulnerability(result)
            completed_tests += 1
            if completed_tests % 20 == 0:
                self.update_progress('DNS Rebinding', completed_tests, total_tests)

    async def remoteAttack(self, url, original_response):
        """Perform remote SSRF attack using callback URL"""
        if not self._has_callback_target():
            return

        tasks = []
        # Mint one callback authority per header so an out-of-band hit pinpoints
        # which header is the SSRF vector.
        for header in self.headers:
            cb = self._callback('Remote', f'header={header}', url)
            callback_variations = [
                cb,
                f"http://{cb}",
                f"https://{cb}",
                f"{cb}/ssrf-test",
                f"{cb}?callback=true",
                f"http://{cb}:80",
                f"http://{cb}:443",
                f"http://{cb}:8080",
                quote(f"http://{cb}"),
                quote(quote(f"http://{cb}")),
            ]
            for callback in callback_variations:
                badHeader = {header: callback}
                tasks.append(self.perform_attack(url, 'Remote', callback, badHeader, original_response))

        total_tests = len(tasks)
        completed_tests = 0
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ScanResult) and result.is_vulnerable:
                self.log_vulnerability(result)
            completed_tests += 1
            if completed_tests % 20 == 0:
                self.update_progress('Remote', completed_tests, total_tests)

    async def crlfInjectionAttack(self, url, original_response):
        """Perform CRLF injection attack to manipulate HTTP requests"""
        # Calculate actual total: 2 tasks per (header × crlf × ip)
        total_tests = len(self.headers) * len(self.crlf_injection) * min(len(self.local_ips), 3) * 2
        completed_tests = 0
        
        tasks = []
        for header in self.headers:
            for crlf_payload in self.crlf_injection:
                # Test CRLF with local IPs
                for ip in self.local_ips[:3]:
                    # Inject CRLF before the IP
                    payload = f"{ip}{crlf_payload}"
                    badHeader = {header: payload}
                    tasks.append(self.perform_attack(url, 'CRLF_Injection', payload, badHeader, original_response))
                    
                    # Also test CRLF after protocol
                    payload_with_protocol = f"http://{ip}{crlf_payload}"
                    badHeader = {header: payload_with_protocol}
                    tasks.append(self.perform_attack(url, 'CRLF_Injection', payload_with_protocol, badHeader, original_response))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ScanResult) and result.is_vulnerable:
                self.log_vulnerability(result)
            completed_tests += 1
            if completed_tests % 50 == 0:
                self.update_progress('CRLF Injection', completed_tests, total_tests)

    async def schemeConfusionAttack(self, url, original_response):
        """Perform scheme confusion attack using alternative protocols"""
        # Combine scheme_confusion payloads with existing protocols
        all_schemes = self.scheme_confusion.copy()
        
        # Also test protocols.txt with local IPs
        for protocol in self.protocols:
            for ip in self.local_ips[:5]:
                all_schemes.append(f"{protocol}{ip}")

        # Remove any duplicate scheme payloads before dispatch
        all_schemes = self._unique(all_schemes)

        total_tests = len(self.headers) * len(all_schemes)
        completed_tests = 0
        
        tasks = []
        for header in self.headers:
            for scheme_payload in all_schemes:
                badHeader = {header: scheme_payload}
                tasks.append(self.perform_attack(url, 'Scheme_Confusion', scheme_payload, badHeader, original_response))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ScanResult) and result.is_vulnerable:
                self.log_vulnerability(result)
            completed_tests += 1
            if completed_tests % 50 == 0:
                self.update_progress('Scheme Confusion', completed_tests, total_tests)

    async def wafBypassAttack(self, url, original_response):
        """Perform WAF/filter bypass attack using payloads/waf_bypass.txt.

        Entries are filter-evasion primitives: encoded schemes, case
        variations, protocol confusion, null bytes and traversal. Each is
        injected as a header value. Prefix-style entries that end in a scheme
        separator (e.g. 'http://', 'http:\\\\') are also combined with a few
        local IPs so they resolve to an actual internal target.
        """
        if not self.waf_bypass:
            return

        separators = ('/', ':', '\\', '\uff0f')  # incl. unicode full-width slash
        payloads = []
        for entry in self.waf_bypass:
            payloads.append(entry)
            # If it looks like a bare scheme/prefix, attach internal targets.
            if entry.endswith(separators):
                for ip in self.local_ips[:5]:
                    payloads.append(f"{entry}{ip}")
        payloads = self._unique(payloads)

        total_tests = len(self.headers) * len(payloads)
        completed_tests = 0

        tasks = []
        for header in self.headers:
            for payload in payloads:
                badHeader = {header: payload}
                tasks.append(self.perform_attack(url, 'WAF_Bypass', payload, badHeader, original_response))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, ScanResult) and result.is_vulnerable:
                self.log_vulnerability(result)
            completed_tests += 1
            if completed_tests % 50 == 0:
                self.update_progress('WAF Bypass', completed_tests, total_tests)

    async def blindSsrfAttack(self, url, original_response):
        """Blind-SSRF / known-CVE probe phase using the bundled template library
        (payloads/blind-ssrf-payloads.json, from errorfiathck/ssrf-exploit).

        Routing by template shape:
          - "url"     -> request the rendered CVE-probe URL directly against the
                         target (e.g. Weblogic/Solr/Jenkins/Confluence probes).
          - "gopher"/"smuggle" -> inject the rendered SSRF target string into an
                         appended 'url=' parameter (best generic fetch vector).

        Canary ({canary_addr}) is filled from --backurl. Templates that require a
        canary are skipped when no --backurl is set, since they can only be
        confirmed out-of-band. NOTE: blind payloads truly need OOB (interactsh/
        Collaborator) confirmation; here we fall back to baseline/response-diff,
        which reliably catches the direct-URL CVE probes but not pure-blind hits.
        """
        if not self.blind_lib or self.blind_lib.count() == 0:
            return

        static_canary = self.backurl or ''
        oob_active = self._oob_enabled()

        tasks = []
        meta = []  # (category, name, request_url)
        for category, name, template, kind, needs_canary in self.blind_lib.iter_templates(include_smuggle=True):
            if needs_canary:
                if not self._has_callback_target():
                    # OOB-only payload with no callback configured; can't confirm.
                    continue
                # Mint a unique canary per payload so a callback identifies the
                # exact CVE/template that fired.
                canary = self._callback(f'Blind:{category}', name, url) if oob_active else static_canary
            else:
                canary = static_canary

            value = self.blind_lib.render_one(template, url, canary=canary)

            if kind == 'url':
                request_url = value
            else:
                separator = '&' if '?' in url else '?'
                request_url = f"{url}{separator}url={quote(value, safe='')}"
            tasks.append(self.make_request(request_url))
            meta.append((category, name, request_url))

        if not tasks:
            return

        total_tests = len(tasks)
        completed_tests = 0

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for (category, name, request_url), response in zip(meta, responses):
            completed_tests += 1
            if completed_tests % 25 == 0:
                self.update_progress('Blind SSRF', completed_tests, total_tests)

            if not response or isinstance(response, Exception):
                continue

            # These probes deliberately hit different paths / inject nested
            # targets, so generic status/size diffing vs the baseline would
            # false-positive constantly. Confirmation for this phase comes from
            # out-of-band callbacks (reported in _finalize_oob); the in-band
            # signal here is limited to a concrete content signature (leaked
            # credentials, /etc/passwd, metadata markers).
            signature = self._ssrf_signature(response)
            if signature:
                result = ScanResult(
                    url=request_url,
                    attack_type=f"Blind:{category}",
                    payload=name,
                    response_code=response.status_code,
                    response_size=len(response.content),
                    timestamp=datetime.now(),
                    headers={},
                    is_vulnerable=True,
                    verification_method="Response Content Analysis",
                    notes=f"content signature: {signature}"
                )
                self.log_vulnerability(result)
                if self.reporter:
                    self.reporter.add_result(result)

    def verify_vulnerability(self, url: str, payload: str, response, original_response=None) -> str:
        """Verify if the potential vulnerability is real"""
        # Pass original_response to verification methods that need it
        verification_methods = [
            lambda r: self._verify_response_code(r, original_response),
            self._verify_response_content,
            self._verify_response_headers,
            self._verify_timing_difference
        ]

        for i, method in enumerate(verification_methods):
            try:
                if method(response):
                    # Return the actual method name for the first one
                    if i == 0:
                        return "_verify_response_code"
                    else:
                        return method.__name__
            except:
                continue
        return "unverified"

    def _verify_response_code(self, response, original_response=None) -> bool:
        """Verify vulnerability based on response code"""
        # Don't flag rate limiting as vulnerability
        if response.status_code == 429:
            return False
        
        # If we have original response, only flag if status changed
        if original_response:
            # Check against baseline if available
            if hasattr(self, 'baseline') and self.baseline:
                # Only flag if status is NOT in baseline
                return response.status_code not in self.baseline['status_codes']
            else:
                # No baseline - check if different from original
                return response.status_code != original_response.status_code
        
        # Fallback: flag common success codes (but this shouldn't happen)
        return response.status_code in [200, 301, 302, 307]

    def _verify_response_content(self, response) -> bool:
        """Verify vulnerability based on response content"""
        # Don't flag rate limiting as vulnerability
        if response.status_code == 429:
            return False
            
        # Anchored, high-signal markers only. Generic words such as 'key',
        # 'password', 'internal', 'aws' or 'secret' appear on countless normal
        # pages and caused false positives; these patterns indicate that
        # internal/credential data was actually returned.
        indicators = [
            'root:x:0:0:',
            'root:*:0:0:',
            'security-credentials',
            '"accesskeyid"',
            '"secretaccesskey"',
            'ami-id',
            'instance-identity',
            'computemetadata',
            'metadata-flavor',
            'begin rsa private key',
            'begin private key',
            'begin openssh private key',
            'uid=0(root)',
        ]
        text = response.text.lower()
        return any(indicator in text for indicator in indicators)

    def _verify_response_headers(self, response) -> bool:
        """Verify vulnerability based on response headers"""
        suspicious_headers = [
            'x-internal',
            'server-internal',
            'x-backend-server',
            'x-upstream',
            'x-host',
            'x-forwarded-server'
        ]
        return any(header.lower() in response.headers for header in suspicious_headers)

    def _verify_timing_difference(self, response) -> bool:
        """Verify vulnerability based on response timing"""
        return response.elapsed.total_seconds() > 2.0

    def log_vulnerability(self, result: ScanResult):
        """Log detected vulnerability"""
        with self.file_lock:
            # Rename verification method names for output
            verification_name = result.verification_method
            if verification_name == "_verify_response_code":
                verification_name = "Response Code Analysis"
            elif verification_name == "_verify_response_content":
                verification_name = "Response Content Analysis"
            elif verification_name == "_verify_response_headers":
                verification_name = "Response Headers Analysis"
            elif verification_name == "_verify_timing_difference":
                verification_name = "Timing Analysis"
            
            self.logger.warning(f"\nPotential SSRF vulnerability found!")
            self.logger.warning(f"URL: {result.url}")
            self.logger.warning(f"Attack Type: {result.attack_type}")
            self.logger.warning(f"Payload: {result.payload}")
            self.logger.warning(f"Response Code: {result.response_code}")
            self.logger.warning(f"Verification Method: {verification_name}")
            self.logger.warning("-" * 50)

    async def performAllAttack(self, url, baseline=None):
        """Perform all SSRF attacks"""
        if not self.quiet_mode:
            print(f"[*] Fetching original response from {url}...")
        
        original_response = await self.make_request(url)
        
        if original_response:
            if not self.quiet_mode:
                print(f"[*] Got response (Status: {original_response.status_code}, Size: {len(original_response.content)} bytes)")
                print(f"[*] Starting attack phases...")
            
            # Store baseline for comparison
            self.baseline = baseline
            
            try:
                self.progress.current_phase = "Local IP"
                await self.localAttack(url, original_response)
            except Exception as e:
                self.logger.error(f"Error in Local IP attack: {str(e)}")
            
            try:
                self.progress.current_phase = "Cloud Metadata"
                await self.cloudMetadataAttack(url, original_response)
            except Exception as e:
                self.logger.error(f"Error in Cloud Metadata attack: {str(e)}")
            
            try:
                self.progress.current_phase = "Protocol"
                await self.protocolAttack(url, original_response)
            except Exception as e:
                self.logger.error(f"Error in Protocol attack: {str(e)}")
            
            try:
                self.progress.current_phase = "Encoded"
                await self.encodedAttack(url, original_response)
            except Exception as e:
                self.logger.error(f"Error in Encoded attack: {str(e)}")
            
            try:
                self.progress.current_phase = "Parameter"
                # Existing behavior: append extra parameters from payloads/parameter_payloads.txt
                await self.parameterAttack(url, original_response)
                # New behavior: replace existing parameter values with callback-style payloads
                await self.parameterCallbackAttack(url, original_response)
            except Exception as e:
                self.logger.error(f"Error in Parameter attack: {str(e)}")
            
            try:
                self.progress.current_phase = "Port Scan"
                await self.portScanAttack(url, original_response)
            except Exception as e:
                self.logger.error(f"Error in Port Scan attack: {str(e)}")
            
            try:
                self.progress.current_phase = "DNS Rebinding"
                await self.dnsRebindingAttack(url, original_response)
            except Exception as e:
                self.logger.error(f"Error in DNS Rebinding attack: {str(e)}")
            
            try:
                self.progress.current_phase = "CRLF Injection"
                await self.crlfInjectionAttack(url, original_response)
            except Exception as e:
                self.logger.error(f"Error in CRLF Injection attack: {str(e)}")
            
            try:
                self.progress.current_phase = "Scheme Confusion"
                await self.schemeConfusionAttack(url, original_response)
            except Exception as e:
                self.logger.error(f"Error in Scheme Confusion attack: {str(e)}")

            try:
                self.progress.current_phase = "WAF Bypass"
                await self.wafBypassAttack(url, original_response)
            except Exception as e:
                self.logger.error(f"Error in WAF Bypass attack: {str(e)}")

            try:
                self.progress.current_phase = "Blind SSRF"
                await self.blindSsrfAttack(url, original_response)
            except Exception as e:
                self.logger.error(f"Error in Blind SSRF attack: {str(e)}")
            
            # Run remote attack when a callback destination exists (OOB or --backurl)
            if self._has_callback_target():
                try:
                    self.progress.current_phase = "Remote"
                    await self.remoteAttack(url, original_response)
                except Exception as e:
                    self.logger.error(f"Error in Remote attack: {str(e)}")
        else:
            async with self.lock:
                self.nrErrorUrl += 1
            if not self.quiet_mode:
                print(Fore.RED + f"\n[!] Failed to get response from {url}")
                print(Fore.YELLOW + f"[*] Check network connectivity or try with -d for debug info")

    async def baseline_target(self, url):
        """Create baseline fingerprint of target to reduce false positives"""
        baselines = []
        max_attempts = 3
        
        for attempt in range(max_attempts):
            try:
                response = await self.make_request(url)
                if response:
                    baselines.append({
                        'status': response.status_code,
                        'length': len(response.content),
                        'content_hash': hash(response.content)
                    })
                await asyncio.sleep(0.2)  # Small delay between baselines
            except Exception as e:
                if self.config.scanner['debug']:
                    self.logger.error(f"Baseline attempt {attempt + 1} failed: {str(e)}")
                await asyncio.sleep(0.5)  # Wait longer on error
                continue
        
        if not baselines:
            if not self.quiet_mode:
                print(f"\n[!] Warning: Could not establish baseline for {url}")
                print(f"[*] Continuing scan without baseline (may have more false positives)")
            return None
            
        # Calculate baseline statistics
        return {
            'status_codes': set(b['status'] for b in baselines),
            'avg_length': sum(b['length'] for b in baselines) / len(baselines),
            'length_variance': max(b['length'] for b in baselines) - min(b['length'] for b in baselines),
            'stable': len(set(b['content_hash'] for b in baselines)) == 1  # All responses identical
        }
    
    async def scan_url(self, url):
        """Process a single URL"""
        async with self.lock:
            self.nrUrlsAnalyzed += 1
        self.print_progress()
        
        # Create baseline first
        if not self.quiet_mode:
            print(f"\n[*] Creating baseline for {url}...")
        
        baseline = await self.baseline_target(url)
        
        if baseline:
            if not self.quiet_mode:
                print(f"[*] Baseline: Status={baseline['status_codes']}, "
                      f"AvgSize={baseline['avg_length']:.0f}, "
                      f"Stable={'Yes' if baseline['stable'] else 'No'}")
        else:
            # Create a minimal baseline to allow scanning to continue
            if not self.quiet_mode:
                print(f"[*] Using permissive detection mode (no baseline)")
        
        await self.performAllAttack(url, baseline)

    def print_final_summary(self):
        """Print scanner-specific statistics (response codes, failures, etc.)"""
        if not self.quiet_mode:
            # Only print scanner-specific stats, not duplicating reporter output
            if self.response_codes:
                print(f"\n📋 Response Code Breakdown:")
                for code, count in sorted(self.response_codes.items(), key=lambda x: x[1], reverse=True)[:10]:
                    print(f"  {code}: {count:,} responses")
            
            if self.failure_reasons:
                print(f"\n❌ Failure Breakdown:")
                for reason, count in sorted(self.failure_reasons.items(), key=lambda x: x[1], reverse=True)[:5]:
                    print(f"  {reason}: {count:,}")

    async def _setup_oob(self):
        """Create and start the OOB provider based on --oob-* options."""
        if self.oob_mode != 'selfhosted':
            self.oob = NullOOB()
            return

        if not self.oob_domain:
            self.logger.error(
                "OOB mode 'selfhosted' requires --oob-domain (a public authority "
                "with wildcard DNS pointing at the listener). OOB disabled."
            )
            self.oob = NullOOB()
            return

        host, _, port = self.oob_listen.partition(':')
        host = host or '0.0.0.0'
        try:
            port = int(port) if port else 8000
        except ValueError:
            port = 8000

        provider = SelfHostedOOB(host, port, self.oob_domain, logger=self.logger)
        started = await provider.start()
        if started:
            self.oob = provider
            if not self.quiet_mode:
                print(Fore.YELLOW + (
                    "[!] OOB listener is UNAUTHENTICATED and accepts inbound "
                    f"connections on {host}:{port}. It only logs requests."
                ))
        else:
            self.oob = NullOOB()

    async def _finalize_oob(self):
        """Wait for late callbacks, correlate them, and report confirmed hits."""
        if not self._oob_enabled():
            return

        wait = max(0, int(self.oob_wait))
        if wait and not self.quiet_mode:
            print(f"\n[*] Waiting {wait}s for out-of-band callbacks...")
        if wait:
            await asyncio.sleep(wait)

        interactions = self.oob.collect()
        confirmed_tokens = set()
        confirmed = 0
        for it in interactions:
            meta = self.oob.meta_for(it.token)
            if not meta or it.token in confirmed_tokens:
                continue
            confirmed_tokens.add(it.token)
            confirmed += 1
            result = ScanResult(
                url=meta.target_url,
                attack_type=f"OOB:{meta.attack_type}",
                payload=meta.payload,
                response_code=0,
                response_size=0,
                timestamp=datetime.now(),
                headers={},
                is_vulnerable=True,
                verification_method="OOB Interaction",
                notes=(f"Confirmed out-of-band {it.protocol} callback from "
                       f"{it.remote_addr} ({it.method} {it.path}) at "
                       f"{datetime.fromtimestamp(it.timestamp).isoformat()}"),
            )
            self.log_vulnerability(result)
            if self.reporter:
                self.reporter.add_result(result)

        if not self.quiet_mode:
            if confirmed:
                print(Fore.GREEN + f"[+] {confirmed} CONFIRMED out-of-band SSRF "
                      f"interaction(s) - see report for attribution.")
            else:
                print(f"[*] No out-of-band callbacks received "
                      f"({len(interactions)} unmatched hits).")

    async def run(self, urls=None, url_file=None):
        """Run the SSRF scanner"""
        url_list = []
        
        if urls:
            url_list = urls
            self.nrTotUrls = len(urls)
        elif url_file:
            with open(url_file) as f:
                url_list = [line.strip() for line in f if line.strip()]
                self.nrTotUrls = len(url_list)

        # Initialize reporter with output format
        self.reporter = Reporter(
            self.config.scanner['output_dir'],
            self.config.output['format']
        )

        # Initialize locks
        self.lock = asyncio.Lock()
        self.file_lock = threading.Lock()
        
        # Create semaphore for concurrency control
        self.semaphore = asyncio.Semaphore(self.config.scanner['concurrency'])

        # Build the throttler now that CLI overrides (e.g. --rate-limit) have
        # been applied. The active request path uses this throttler to enforce
        # the configured requests-per-second and adapt on errors.
        rps = self.config.rate_limiting['requests_per_second']
        burst = self.config.rate_limiting.get('burst_size', 100)
        self.throttler = SmartThrottler(requests_per_second=rps, burst_size=burst)
        
        # Create session
        await self.request_manager.create_session()

        # Set up out-of-band (OOB) confirmation listener if requested.
        await self._setup_oob()

        # Estimate total requests (per URL x number of URLs) for the progress %.
        self.estimated_total_requests = self._estimate_requests_per_url() * max(len(url_list), 1)

        # Print configuration
        if not self.quiet_mode:
            print(f"\n[*] Configuration:")
            _conc = self.config.scanner['concurrency']
            _lph = self.config.scanner.get('limit_per_host', 0) or _conc
            print(f"    Concurrency: {_conc} (per-host: {_lph})")
            print(f"    Rate Limit: {self.config.rate_limiting['requests_per_second']} req/s")
            print(f"    Timeout: {self.config.scanner['timeout']}s")
            print(f"    Output Format: {self.config.output['format']}")
            if self.config.scanner.get('proxy'):
                print(f"    Proxy: {self.config.scanner['proxy']}")
            if self._oob_enabled():
                print(f"    OOB Mode: {self.oob_mode} (listen {self.oob_listen}, "
                      f"domain {self.oob_domain})")
            print()
        
        # Start timing
        self.scan_start_time = time.time()
        
        try:
            # Process all URLs concurrently
            tasks = [self.scan_url(url) for url in url_list]
            await asyncio.gather(*tasks, return_exceptions=True)

            # Wait for (and collect) any out-of-band callbacks, then report them.
            await self._finalize_oob()
        finally:
            # Close session
            await self.request_manager.close_session()

            # Stop the OOB listener if running
            try:
                await self.oob.stop()
            except Exception:
                pass

            # Calculate total scan time
            if self.scan_start_time:
                scan_duration = time.time() - self.scan_start_time
                if not self.quiet_mode:
                    print(f"\n\n⏱️  Total Scan Time: {scan_duration:.2f} seconds")
        
        # Pass scanner stats to reporter for accurate final summary
        self.reporter._scanner_stats = {
            'total_attempted': self.total_requests_attempted,
            'total_succeeded': self.total_requests_succeeded,
            'total_failed': self.total_requests_failed,
            'success_rate': (self.total_requests_succeeded / self.total_requests_attempted * 100) if self.total_requests_attempted > 0 else 0,
            'response_codes': self.response_codes,
            'failure_reasons': self.failure_reasons
        }
        
        # Print scanner-specific stats first
        self.print_final_summary()
        
        # Generate and print reporter summary
        summary = self.reporter.generate_summary()
        print(summary)



