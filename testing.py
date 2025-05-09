#!/usr/bin/env python3
"""
Advanced Enterprise Network Testing Framework

For professional performance testing of web applications and infrastructure.
ONLY use on systems you own or have explicit permission to test.
"""

import requests
import threading
import time
import argparse
import random
import sys
import socket
import ssl
import json
import os
import csv
import datetime
import re
import uuid
import logging
import multiprocessing
import http.client
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from urllib.parse import urlparse, urljoin, parse_qs
import statistics
import ipaddress
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import asyncio
import aiohttp

# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configure logging
LOG_FORMAT = '%(asctime)s - %(levelname)s - [%(processName)s] %(message)s'

logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('network_tester')

# Constants for the application
HTTP_METHODS = ['GET', 'HEAD', 'OPTIONS']  # Safe methods only
CONTENT_TYPES = ['application/json', 'application/x-www-form-urlencoded', 'text/plain']

# Default headers for request variation
DEFAULT_HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'DNT': '1',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Cache-Control': 'max-age=0'
}

# User agents for request variation
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
    'Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/84.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36'
]

# Mobile device strings for mobile simulation
MOBILE_DEVICES = [
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.210 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 9; Pixel 3 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.105 Mobile Safari/537.36'
]


class NetworkScanner:
    """Class to scan network infrastructure and find endpoints"""
    
    def __init__(self, base_url, check_cdn=True, check_waf=True, 
                 enumerate_endpoints=True, scan_depth=2, timeout=10):
        """
        Initialize the network scanner
        
        Args:
            base_url: Base URL to scan
            check_cdn: Whether to check for CDN usage
            check_waf: Whether to check for WAF
            enumerate_endpoints: Whether to crawl and find endpoints
            scan_depth: Depth of crawling (1-3)
            timeout: Request timeout in seconds
        """
        self.base_url = base_url
        self.check_cdn = check_cdn
        self.check_waf = check_waf
        self.enumerate_endpoints = enumerate_endpoints
        self.scan_depth = min(scan_depth, 3)  # Limit depth to 3 for safety
        self.timeout = timeout
        self.domain = urlparse(base_url).netloc
        
        # Results
        self.endpoints = set()
        self.server_info = {}
        self.infrastructure = {}

    async def scan_site(self):
        """Perform full scan of the site"""
        logger.info(f"Starting network scan of {self.base_url}")
        
        # Basic server info
        await self.get_server_info()
        
        # Find endpoints if requested
        if self.enumerate_endpoints:
            await self.find_endpoints()
            
        # Check for CDN
        if self.check_cdn:
            await self.detect_cdn()
            
        # Check for WAF
        if self.check_waf:
            await self.detect_waf()
            
        return {
            'server_info': self.server_info,
            'endpoints': list(self.endpoints),
            'infrastructure': self.infrastructure
        }
        
    async def get_server_info(self):
        """Get basic server information"""
        logger.info(f"Gathering server information for {self.domain}")
        
        try:
            parsed_url = urlparse(self.base_url)
            
            # Get IP address
            try:
                ip_address = socket.gethostbyname(self.domain)
                self.server_info['ip_address'] = ip_address
                logger.info(f"IP Address: {ip_address}")
                
                # Check if IP is in private range
                try:
                    ip_obj = ipaddress.ip_address(ip_address)
                    self.server_info['is_private_ip'] = ip_obj.is_private
                except Exception:
                    pass
                    
            except socket.gaierror as e:
                logger.warning(f"Could not resolve hostname: {self.domain} - {str(e)}")
            
            # Check server headers using aiohttp
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.head(
                        self.base_url, 
                        timeout=self.timeout,
                        ssl=False
                    ) as response:
                        headers = dict(response.headers)
                        self.server_info['headers'] = headers
                        
                        # Check for interesting headers
                        interesting_headers = [
                            'Server', 'X-Powered-By', 'X-AspNet-Version', 
                            'X-Runtime', 'X-Generator', 'X-Page-Speed',
                            'X-Drupal-Cache', 'X-Varnish', 'CF-Cache-Status',
                            'X-Cache', 'Via', 'X-Frame-Options', 'X-XSS-Protection'
                        ]
                        
                        for header in interesting_headers:
                            if header.lower() in [h.lower() for h in headers]:
                                actual_header = next(h for h in headers if h.lower() == header.lower())
                                logger.info(f"{header}: {headers[actual_header]}")
                                
            except Exception as e:
                logger.warning(f"Could not get server headers: {str(e)}")
                
            # Test SSL if HTTPS
            if parsed_url.scheme == 'https':
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((self.domain, 443)) as sock:
                        with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                            cert = ssock.getpeercert()
                            
                            # Extract certificate info
                            issuer = dict(x[0] for x in cert['issuer'])
                            subject = dict(x[0] for x in cert['subject'])
                            expiry = cert['notAfter']
                            sans = [x[1] for x in cert.get('subjectAltName', []) if x[0] == 'DNS']
                            
                            self.server_info['ssl'] = {
                                'issuer': issuer.get('organizationName', 'N/A'),
                                'subject': subject.get('commonName', 'N/A'),
                                'expiry': expiry,
                                'sans': sans
                            }
                            
                            logger.info(f"SSL Certificate Issuer: {issuer.get('organizationName', 'N/A')}")
                            logger.info(f"SSL Certificate Subject: {subject.get('commonName', 'N/A')}")
                            logger.info(f"SSL Certificate Expiry: {expiry}")
                except Exception as e:
                    logger.warning(f"Could not check SSL certificate: {str(e)}")
                    
        except Exception as e:
            logger.warning(f"Error in server info check: {str(e)}")
            
    async def find_endpoints(self):
        """Find endpoints by crawling the site"""
        logger.info(f"Discovering endpoints on {self.base_url} (depth: {self.scan_depth})")
        self.endpoints.add('/')  # Add root path
        
        # Start with the base URL
        to_visit = {self.base_url}
        visited = set()
        
        # Track current depth
        current_depth = 0
        
        while to_visit and current_depth < self.scan_depth:
            current_urls = to_visit.copy()
            to_visit = set()
            
            for url in current_urls:
                if url in visited:
                    continue
                    
                visited.add(url)
                parsed_url = urlparse(url)
                base_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
                
                try:
                    logger.debug(f"Visiting: {url}")
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            url, 
                            timeout=self.timeout,
                            ssl=False,
                            headers={'User-Agent': random.choice(USER_AGENTS)}
                        ) as response:
                            if response.status == 200:
                                content_type = response.headers.get('Content-Type', '')
                                
                                # Only parse HTML responses
                                if 'text/html' in content_type:
                                    text = await response.text()
                                    
                                    # Add the current path
                                    path = parsed_url.path
                                    if path:
                                        self.endpoints.add(path)
                                    
                                    # Extract links
                                    href_pattern = re.compile(r'href=[\'"]([^\'"]+)[\'"]')
                                    src_pattern = re.compile(r'src=[\'"]([^\'"]+)[\'"]')
                                    action_pattern = re.compile(r'action=[\'"]([^\'"]+)[\'"]')
                                    
                                    # Combine all found URLs
                                    raw_urls = []
                                    raw_urls.extend(href_pattern.findall(text))
                                    raw_urls.extend(src_pattern.findall(text))
                                    raw_urls.extend(action_pattern.findall(text))
                                    
                                    for raw_url in raw_urls:
                                        # Skip anchors and javascript
                                        if raw_url.startswith('#') or raw_url.startswith('javascript:'):
                                            continue
                                            
                                        # Skip common file extensions
                                        if any(raw_url.endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js']):
                                            continue
                                            
                                        # Handle relative URLs
                                        if not raw_url.startswith('http'):
                                            if raw_url.startswith('/'):
                                                full_url = f"{base_domain}{raw_url}"
                                                path = raw_url
                                            else:
                                                # Join with current path
                                                full_url = urljoin(url, raw_url)
                                                path = urlparse(full_url).path
                                        else:
                                            full_url = raw_url
                                            parsed_raw = urlparse(raw_url)
                                            
                                            # Skip external domains
                                            if parsed_raw.netloc != self.domain:
                                                continue
                                                
                                            path = parsed_raw.path
                                            
                                        # Add to endpoints and to visit if it's on the same domain
                                        if path:
                                            self.endpoints.add(path)
                                            
                                        # Add to next round of URLs to visit
                                        if full_url not in visited:
                                            to_visit.add(full_url)
                except Exception as e:
                    logger.debug(f"Error crawling {url}: {str(e)}")
                    
            # Move to next depth
            current_depth += 1
            logger.info(f"Completed depth {current_depth}/{self.scan_depth}, found {len(self.endpoints)} endpoints")
            
        logger.info(f"Endpoint discovery complete. Found {len(self.endpoints)} unique endpoints.")
        
    async def detect_cdn(self):
        """Detect if the site is using a CDN"""
        logger.info(f"Checking for CDN usage on {self.domain}")
        
        # Common CDN headers and values
        cdn_headers = {
            'CF-Cache-Status': 'Cloudflare',
            'X-CDN': 'Any',
            'X-Cache': 'Any',
            'X-Fastly-Request-ID': 'Fastly',
            'X-Akamai-Transformed': 'Akamai',
            'Via': ['cloudfront', 'akamai', 'varnish'],
            'Server': ['cloudflare', 'cloudfront', 'fastly'],
            'X-Amz-Cf-Id': 'CloudFront',
            'X-CDN-Provider': 'Any'
        }
        
        # Check headers
        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(
                    self.base_url, 
                    timeout=self.timeout,
                    ssl=False
                ) as response:
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    
                    cdn_detected = []
                    
                    for header, cdn in cdn_headers.items():
                        header_lower = header.lower()
                        if header_lower in headers:
                            if cdn == 'Any':
                                cdn_detected.append(f"{header}: {headers[header_lower]}")
                            elif isinstance(cdn, list):
                                for cdn_name in cdn:
                                    if cdn_name.lower() in headers[header_lower].lower():
                                        cdn_detected.append(f"{cdn_name} (via {header})")
                            elif cdn.lower() in headers[header_lower].lower():
                                cdn_detected.append(cdn)
                    
                    if cdn_detected:
                        self.infrastructure['cdn'] = cdn_detected
                        logger.info(f"CDN detected: {', '.join(cdn_detected)}")
                    else:
                        logger.info("No CDN detected via headers")
                        
                    # Additional checks through DNS
                    # (simplified for this version)
                    
        except Exception as e:
            logger.warning(f"Error checking for CDN: {str(e)}")
            
    async def detect_waf(self):
        """Detect if the site is protected by a WAF"""
        logger.info(f"Checking for WAF protection on {self.domain}")
        
        # Common WAF signatures in headers
        waf_headers = {
            'X-Powered-By': ['waf', 'firewall', 'fortinet', 'fortigate', 'forcepoint'],
            'Server': ['cloudflare', 'sucuri', 'incapsula', 'bigip', 'fortiweb'],
            'X-Sucuri-ID': 'Sucuri',
            'X-Sucuri-Cache': 'Sucuri',
            'Powered-By-ChinaCache': 'ChinaCache',
            'X-CDN': ['incapsula'],
            'X-Iinfo': 'Incapsula',
            'X-Secure-By': 'Any',
            'X-Security-Mode': 'Any',
            'X-Protected-By': 'Any',
            'X-FW-Protected-By': 'Any'
        }
        
        # Try a benign but suspicious request
        # This is intentionally benign but might trigger WAF detection patterns
        test_path = f"/?id=1'&test=<script>"
        full_url = urljoin(self.base_url, test_path)
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    full_url, 
                    timeout=self.timeout,
                    ssl=False,
                    headers={'User-Agent': random.choice(USER_AGENTS)}
                ) as response:
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    
                    waf_detected = []
                    
                    # Check headers for WAF signatures
                    for header, waf in waf_headers.items():
                        header_lower = header.lower()
                        if header_lower in headers:
                            if waf == 'Any':
                                waf_detected.append(f"{header}: {headers[header_lower]}")
                            elif isinstance(waf, list):
                                for waf_name in waf:
                                    if waf_name.lower() in headers[header_lower].lower():
                                        waf_detected.append(f"{waf_name} (via {header})")
                            elif waf.lower() in headers[header_lower].lower():
                                waf_detected.append(waf)
                    
                    # Check for common WAF response codes and body patterns
                    if response.status in [403, 406, 501]:
                        text = await response.text()
                        
                        # Look for WAF signatures in response body
                        waf_signatures = [
                            ('Cloudflare', 'Cloudflare Ray ID:'),
                            ('Cloudflare', 'DDoS protection by Cloudflare'),
                            ('ModSecurity', 'This request has been blocked by ModSecurity'),
                            ('Incapsula', 'Request Blocked by Incapsula'),
                            ('F5 BIG-IP', 'Request rejected, security policy violation'),
                            ('Sucuri', 'Sucuri WebSite Firewall'),
                            ('FortiWeb', 'FortiWeb Firewall')
                        ]
                        
                        for waf_name, signature in waf_signatures:
                            if signature in text:
                                waf_detected.append(waf_name)
                    
                    if waf_detected:
                        self.infrastructure['waf'] = list(set(waf_detected))
                        logger.info(f"WAF detected: {', '.join(set(waf_detected))}")
                    else:
                        logger.info("No WAF detected")
                        
        except Exception as e:
            logger.warning(f"Error checking for WAF: {str(e)}")


class RequestGenerator:
    """Class to generate diverse HTTP requests for testing"""
    
    def __init__(self, base_url, endpoints=None, post_data=None, 
                 cookies=None, custom_headers=None):
        """
        Initialize the request generator
        
        Args:
            base_url: Base URL for requests
            endpoints: List of endpoints to use
            post_data: Dictionary of POST data to use (if applicable)
            cookies: Dictionary of cookies to send
            custom_headers: Dictionary of custom headers to send
        """
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.endpoints = endpoints or ['/']
        self.post_data = post_data or {}
        self.cookies = cookies or {}
        self.custom_headers = custom_headers or {}
        
    def generate_url(self):
        """Generate a random URL from the available endpoints"""
        endpoint = random.choice(self.endpoints)
        
        # Handle both absolute and relative URLs
        if endpoint.startswith('http'):
            return endpoint
        elif not endpoint.startswith('/'):
            endpoint = f"/{endpoint}"
            
        return urljoin(self.base_url, endpoint)
        
    def generate_headers(self):
        """Generate random headers for request variation"""
        headers = DEFAULT_HEADERS.copy()
        
        # Add random user agent
        headers['User-Agent'] = random.choice(USER_AGENTS)
        
        # Add custom headers
        headers.update(self.custom_headers)
        
        # Sometimes add common browser headers
        if random.random() < 0.3:
            headers['Referer'] = self.base_url
            
        if random.random() < 0.3:
            headers['Accept'] = random.choice([
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'application/json,text/plain,*/*',
                '*/*'
            ])
            
        return headers
        
    def generate_request_params(self):
        """Generate a full set of request parameters"""
        url = self.generate_url()
        method = random.choice(HTTP_METHODS)
        headers = self.generate_headers()
        
        return {
            'url': url,
            'method': method,
            'headers': headers,
            'cookies': self.cookies.copy() if self.cookies else None,
            'params': None,  # GET parameters go in the URL
            'data': None,    # POST data, only used for POST requests
        }


class AsyncLoadTester:
    """Class for asynchronous load testing with detailed metrics"""
    
    def __init__(self, base_url, num_requests=1000, concurrency=10, 
                 ramp_up=0, duration=None, delay=0, timeout=10, 
                 verify_ssl=True, endpoints=None, post_data=None,
                 cookies=None, headers=None, proxy=None,
                 report_interval=5, distributed=False, worker_processes=None,
                 test_name=None):
        """
        Initialize the async load tester
        
        Args:
            base_url: Base URL to test
            num_requests: Total number of requests to make
            concurrency: Maximum number of concurrent requests
            ramp_up: Ramp up time in seconds to reach full concurrency
            duration: Run test for specific duration instead of fixed number of requests
            delay: Delay between batches in seconds
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            endpoints: List of endpoints to test beyond the base URL
            post_data: Dictionary of POST data for testing POST requests
            cookies: Dictionary of cookies to send with requests
            headers: Dictionary of custom headers to send with requests
            proxy: Proxy URL to use for requests
            report_interval: How often to report progress (in seconds)
            distributed: Whether to use multiple processes for testing
            worker_processes: Number of worker processes to use if distributed
            test_name: Name of the test for reporting
        """
        self.base_url = base_url
        self.num_requests = num_requests
        self.concurrency = concurrency
        self.ramp_up = ramp_up
        self.duration = duration
        self.delay = delay
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.endpoints = endpoints or ['/']
        self.post_data = post_data
        self.cookies = cookies
        self.headers = headers
        self.proxy = proxy
        self.report_interval = report_interval
        self.distributed = distributed
        self.worker_processes = worker_processes or min(multiprocessing.cpu_count(), 4)
        self.test_name = test_name or f"LoadTest-{int(time.time())}"
        
        # Results and statistics
        self.results = {}
        self.response_times = []
        self.status_counts = {}
        self.error_counts = {}
        self.bytes_received = 0
        self.start_time = None
        self.end_time = None
        self.completed_requests = 0
        self.request_timestamps = []
        self.lock = threading.Lock()
        self.stop_event = asyncio.Event()
        
        # Prepare request generator
        self.request_generator = RequestGenerator(
            base_url=base_url,
            endpoints=endpoints,
            post_data=post_data,
            cookies=cookies,
            custom_headers=headers
        )
        
        # For reporting
        self.last_report_time = 0
        self.last_completed = 0
        
        # For distributed mode
        self.manager = None
        self.shared_completed = None
        self.result_queue = None
        
    async def make_request(self, session, request_id):
        """Make a single HTTP request"""
        request_params = self.request_generator.generate_request_params()
        url = request_params['url']
        method = request_params['method']
        headers = request_params['headers']
        cookies = request_params['cookies']
        
        request_time = time.time()
        
        try:
            if method == 'GET':
                start = time.time()
                async with session.get(
                    url, 
                    headers=headers,
                    cookies=cookies,
                    timeout=self.timeout,
                    ssl=not self.verify_ssl,
                    proxy=self.proxy
                ) as response:
                    body = await response.read()
                    end = time.time()
                    
                    # Record results
                    status_code = response.status
                    response_headers = dict(response.headers)
                    content_length = len(body)
                    response_time = end - start
                    
                    return {
                        'request_id': request_id,
                        'url': url,
                        'method': method,
                        'status_code': status_code,
                        'response_time': response_time,
                        'response_size': content_length,
                        'timestamp': request_time,
                        'headers': response_headers,
                        'error': None
                    }
                    
            elif method == 'HEAD':
                start = time.time()
                async with session.head(
                    url, 
                    headers=headers,
                    cookies=cookies,
                    timeout=self.timeout,
                    ssl=not self.verify_ssl,
                    proxy=self.proxy
                ) as response:
                    end = time.time()
                    
                    # Record results
                    status_code = response.status
                    response_headers = dict(response.headers)
                    response_time = end - start
                    
                    return {
                        'request_id': request_id,
                        'url': url,
                        'method': method,
                        'status_code': status_code,
                        'response_time': response_time,
                        'response_size': 0,
                        'timestamp': request_time,
                        'headers': response_headers,
                        'error': None
                    }
                    
            elif method == 'OPTIONS':
                start = time.time()
                async with session.options(
                    url, 
                    headers=headers,
                    cookies=cookies,
                    timeout=self.timeout,
                    ssl=not self.verify_ssl,
                    proxy=self.proxy
                ) as response:
                    end = time.time()
                    
                    # Record results
                    status_code = response.status
                    response_headers = dict(response.headers)
                    response_time = end - start
                    
                    return {
                        'request_id': request_id,
                        'url': url,
                        'method': method,
                        'status_code': status_code,
                        'response_time': response_time,
                        'response_size': 0,
                        'timestamp': request_time,
                        'headers': response_headers,
                        'error': None
                    }
                
        except asyncio.TimeoutError:
            return {
                'request_id': request_id,
                'url': url,
                'method': method,
                'status_code': None,
                'response_time': self.timeout,
                'response_size': 0,
                'timestamp': request_time,
                'headers': {},
                'error': 'Timeout'
            }
            
        except aiohttp.ClientSSLError:
            return {
                'request_id': request_id,
                'url': url,
                'method': method,
                'status_code': None,
                'response_time': 0,
                'response_size': 0,
                'timestamp': request_time,
                'headers': {},
                'error': 'SSL Error'
            }
            
        except aiohttp.ClientConnectorError:
            return {
                'request_id': request_id,
                'url': url,
                'method': method,
                'status_code': None,
                'response_time': 0,
                'response_size': 0,
                'timestamp': request_time,
                'headers': {},
                'error': 'Connection Error'
            }
            
        except Exception as e:
            return {
                'request_id': request_id,
                'url': url,
                'method': method,
                'status_code': None,
                'response_time': 0,
                'response_size': 0,
                'timestamp': request_time,
                'headers': {},
                'error': f'Error: {str(e)}'
            }
            
    async def process_result(self, result):
        """Process and store a request result"""
        with self.lock:
            self.completed_requests += 1
            
            # Store response time
            if result['response_time'] > 0:
                self.response_times.append(result['response_time'])
                
            # Store status code counts
            status_code = result['status_code'] or 0
            self.status_counts[status_code] = self.status_counts.get(status_code, 0) + 1
            
            # Store error counts
            if result['error']:
                self.error_counts[result['error']] = self.error_counts.get(result['error'], 0) + 1
                
            # Add bytes received
            self.bytes_received += result['response_size']
            
            # Store timestamp
            self.request_timestamps.append(result['timestamp'])
            
            # Store full result
            self.results[result['request_id']] = result
            
            # Check if we should report progress
            current_time = time.time()
            if current_time - self.last_report_time >= self.report_interval:
                self.report_progress()
                self.last_report_time = current_time
                
    def report_progress(self):
        """Report progress of the load test"""
        if not self.start_time:
            return
            
        current_time = time.time()
        elapsed = current_time - self.start_time
        
        # Calculate requests per second
        if self.last_report_time > 0:
            time_diff = current_time - self.last_report_time
            completed_diff = self.completed_requests - self.last_completed
            requests_per_second = completed_diff / time_diff if time_diff > 0 else 0
        else:
            requests_per_second = self.completed_requests / elapsed if elapsed > 0 else 0
            
        # Calculate response time statistics if we have data
        if self.response_times:
            avg_response = sum(self.response_times) / len(self.response_times)
            
            # Only calculate percentiles if we have enough data
            if len(self.response_times) >= 10:
                sorted_times = sorted(self.response_times)
                p50 = sorted_times[int(len(sorted_times) * 0.5)]
                p90 = sorted_times[int(len(sorted_times) * 0.9)]
                p95 = sorted_times[int(len(sorted_times) * 0.95)]
                p99 = sorted_times[int(len(sorted_times) * 0.99)]
            else:
                p50 = p90 = p95 = p99 = 'N/A'
        else:
            avg_response = p50 = p90 = p95 = p99 = 'N/A'
            
        # Update last completed for rate calculation
        self.last_completed = self.completed_requests
        
        # Log progress
        logger.info(f"Progress: {self.completed_requests}/{self.num_requests} requests completed")
        logger.info(f"Elapsed time: {elapsed:.2f}s, Requests/sec: {requests_per_second:.2f}")
        logger.info(f"Response times - Avg: {avg_response if avg_response == 'N/A' else f'{avg_response:.3f}s'}, "
                    f"P50: {p50 if p50 == 'N/A' else f'{p50:.3f}s'}, "
                    f"P90: {p90 if p90 == 'N/A' else f'{p90:.3f}s'}, "
                    f"P95: {p95 if p95 == 'N/A' else f'{p95:.3f}s'}, "
                    f"P99: {p99 if p99 == 'N/A' else f'{p99:.3f}s'}")
        
        # Log status code distribution
        status_info = ', '.join([f"{code}: {count}" for code, count in self.status_counts.items()])
        logger.info(f"Status codes: {status_info if status_info else 'None'}")
        
        # Log errors if any
        if self.error_counts:
            error_info = ', '.join([f"{error}: {count}" for error, count in self.error_counts.items()])
            logger.info(f"Errors: {error_info}")
            
    async def run_worker(self, worker_id, num_requests):
        """Run a worker for distributed load testing"""
        logger.info(f"Worker {worker_id} starting, will process {num_requests} requests")
        
        connector = aiohttp.TCPConnector(
            limit=self.concurrency,
            ssl=None if not self.verify_ssl else False,
            use_dns_cache=True,
            ttl_dns_cache=300
        )
        
        timeout = aiohttp.ClientTimeout(total=None, sock_connect=self.timeout, sock_read=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = []
            for i in range(num_requests):
                if self.ramp_up > 0 and self.start_time:
                    # Calculate target concurrency based on ramp up time
                    elapsed = time.time() - self.start_time
                    if elapsed < self.ramp_up:
                        # Calculate how many concurrent requests we should have at this point
                        target_concurrency = max(1, int((elapsed / self.ramp_up) * self.concurrency))
                        
                        # If we already have more tasks than target concurrency, wait for some to complete
                        while len([t for t in tasks if not t.done()]) >= target_concurrency:
                            await asyncio.sleep(0.1)
                
                # Check if stop event is set
                if self.stop_event.is_set():
                    break
                    
                # Generate unique request ID
                request_id = f"{worker_id}-{i}"
                
                # Create task
                task = asyncio.create_task(self.make_request(session, request_id))
                tasks.append(task)
                
                # Add callback for result processing
                task.add_done_callback(
                    lambda t, r_id=request_id: self.result_queue.put(t.result()) if self.distributed else 
                    asyncio.create_task(self.process_result(t.result()))
                )
                
                # Apply delay if specified
                if self.delay > 0:
                    await asyncio.sleep(self.delay)
                    
            # Wait for all tasks to complete
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
                
        logger.info(f"Worker {worker_id} completed")
        
    async def run_test(self):
        """Run the load test"""
        logger.info(f"Starting load test for {self.base_url}")
        logger.info(f"Configuration: {self.num_requests} requests, {self.concurrency} concurrency, "
                   f"{self.ramp_up}s ramp-up, {self.timeout}s timeout")
        
        self.start_time = time.time()
        self.last_report_time = self.start_time
        
        if self.distributed:
            # Run distributed test across multiple processes
            await self.run_distributed_test()
        else:
            # Run single-process test
            await self.run_single_process_test()
            
        self.end_time = time.time()
        elapsed = self.end_time - self.start_time
        
        # Final report
        logger.info("Load test completed")
        logger.info(f"Total time: {elapsed:.2f}s")
        logger.info(f"Requests completed: {self.completed_requests}")
        logger.info(f"Average throughput: {self.completed_requests / elapsed:.2f} requests/second")
        
        if self.response_times:
            # Calculate statistics
            avg_response = sum(self.response_times) / len(self.response_times)
            min_response = min(self.response_times)
            max_response = max(self.response_times)
            
            # Standard deviation
            if len(self.response_times) > 1:
                stdev_response = statistics.stdev(self.response_times)
            else:
                stdev_response = 0
                
            # Calculate percentiles
            sorted_times = sorted(self.response_times)
            p50 = sorted_times[int(len(sorted_times) * 0.5)]
            p90 = sorted_times[int(len(sorted_times) * 0.9)]
            p95 = sorted_times[int(len(sorted_times) * 0.95)]
            p99 = sorted_times[int(len(sorted_times) * 0.99)]
            
            logger.info(f"Response time summary:")
            logger.info(f"  Min: {min_response:.3f}s")
            logger.info(f"  Avg: {avg_response:.3f}s")
            logger.info(f"  Max: {max_response:.3f}s")
            logger.info(f"  StdDev: {stdev_response:.3f}s")
            logger.info(f"  P50: {p50:.3f}s")
            logger.info(f"  P90: {p90:.3f}s")
            logger.info(f"  P95: {p95:.3f}s")
            logger.info(f"  P99: {p99:.3f}s")
            
        # Status code distribution
        logger.info("Status code distribution:")
        for code, count in sorted(self.status_counts.items()):
            percentage = (count / self.completed_requests) * 100
            logger.info(f"  {code}: {count} ({percentage:.1f}%)")
            
        # Error summary
        if self.error_counts:
            logger.info("Error summary:")
            for error, count in sorted(self.error_counts.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / self.completed_requests) * 100
                logger.info(f"  {error}: {count} ({percentage:.1f}%)")
                
        return self.create_test_report()
        
    async def run_single_process_test(self):
        """Run load test in a single process"""
        if self.duration:
            logger.info(f"Running test for duration of {self.duration}s")
            # Set up a timer to stop the test after duration
            asyncio.create_task(self._duration_timer())
            worker_task = asyncio.create_task(self.run_worker(0, self.num_requests * 2))  # Multiply to ensure we don't run out
            await asyncio.sleep(self.duration)
            self.stop_event.set()
            await worker_task
        else:
            await self.run_worker(0, self.num_requests)
            
    async def run_distributed_test(self):
        """Run load test distributed across multiple processes"""
        # Create manager for shared objects
        self.manager = multiprocessing.Manager()
        self.shared_completed = self.manager.Value('i', 0)
        self.result_queue = self.manager.Queue()
        
        # Calculate requests per worker
        requests_per_worker = self.num_requests // self.worker_processes
        remainder = self.num_requests % self.worker_processes
        
        # Start result consumer
        consumer_task = asyncio.create_task(self._consume_results())
        
        # Start worker processes
        processes = []
        for worker_id in range(self.worker_processes):
            # Add remainder to first worker
            worker_requests = requests_per_worker + (remainder if worker_id == 0 else 0)
            
            process = multiprocessing.Process(
                target=self._worker_process_entrypoint,
                args=(worker_id, worker_requests, self.base_url, self.concurrency, 
                      self.ramp_up, self.delay, self.timeout, self.verify_ssl,
                      self.result_queue)
            )
            process.start()
            processes.append(process)
            
        # Wait for all processes to complete
        for p in processes:
            p.join()
            
        # Signal consumer we're done
        self.result_queue.put(None)
        
        # Wait for consumer to finish
        await consumer_task
        
        # Clean up manager
        self.manager.shutdown()
        
    @staticmethod
    def _worker_process_entrypoint(worker_id, num_requests, base_url, concurrency, 
                                  ramp_up, delay, timeout, verify_ssl, result_queue):
        """Entry point for worker processes"""
        # Create a new event loop for this process
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Create a test instance for this worker
        tester = AsyncLoadTester(
            base_url=base_url,
            num_requests=num_requests,
            concurrency=concurrency,
            ramp_up=ramp_up,
            delay=delay,
            timeout=timeout,
            verify_ssl=verify_ssl,
            distributed=True
        )
        tester.result_queue = result_queue
        
        # Run the worker
        loop.run_until_complete(tester.run_worker(worker_id, num_requests))
        loop.close()
        
    async def _consume_results(self):
        """Consume and process results from the queue"""
        while True:
            # Get result from queue
            result = await asyncio.get_event_loop().run_in_executor(
                None, self.result_queue.get
            )
            
            # Check for end marker
            if result is None:
                break
                
            # Process result
            await self.process_result(result)
            
    async def _duration_timer(self):
        """Timer for duration-based testing"""
        logger.info(f"Test will run for {self.duration}s")
        await asyncio.sleep(self.duration)
        logger.info(f"Test duration of {self.duration}s reached, stopping test")
        self.stop_event.set()
        
    def create_test_report(self):
        """Create a comprehensive test report"""
        elapsed = self.end_time - self.start_time
        
        # Basic info
        report = {
            'test_name': self.test_name,
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'duration': elapsed,
            'target_url': self.base_url,
            'configuration': {
                'num_requests': self.num_requests,
                'concurrency': self.concurrency,
                'ramp_up': self.ramp_up,
                'timeout': self.timeout,
                'verify_ssl': self.verify_ssl,
                'distributed': self.distributed,
                'worker_processes': self.worker_processes if self.distributed else 1
            },
            'results': {
                'completed_requests': self.completed_requests,
                'requests_per_second': self.completed_requests / elapsed if elapsed > 0 else 0,
                'total_bytes': self.bytes_received,
                'bytes_per_second': self.bytes_received / elapsed if elapsed > 0 else 0
            },
            'status_distribution': self.status_counts,
            'errors': self.error_counts
        }
        
        # Response time statistics (if available)
        if self.response_times:
            sorted_times = sorted(self.response_times)
            
            report['response_times'] = {
                'min': min(self.response_times),
                'max': max(self.response_times),
                'avg': sum(self.response_times) / len(self.response_times),
                'median': statistics.median(self.response_times),
                'p90': sorted_times[int(len(sorted_times) * 0.9)],
                'p95': sorted_times[int(len(sorted_times) * 0.95)],
                'p99': sorted_times[int(len(sorted_times) * 0.99)],
                'stdev': statistics.stdev(self.response_times) if len(self.response_times) > 1 else 0
            }
            
        return report
        
    def save_report(self, filename=None):
        """Save the test report to a file"""
        report = self.create_test_report()
        
        if not filename:
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{self.test_name}_{timestamp}.json"
            
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
            
        logger.info(f"Test report saved to {filename}")
        return filename
        
    def save_raw_data(self, filename=None):
        """Save the raw request data to a CSV file"""
        if not filename:
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{self.test_name}_{timestamp}_raw.csv"
            
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['request_id', 'url', 'method', 'status_code', 
                           'response_time', 'response_size', 'timestamp', 'error'])
                           
            for result_id, result in self.results.items():
                writer.writerow([
                    result_id,
                    result['url'],
                    result['method'],
                    result['status_code'],
                    result['response_time'],
                    result['response_size'],
                    result['timestamp'],
                    result['error'] or ''
                ])
                
        logger.info(f"Raw data saved to {filename}")
        return filename


def main():
    """Main entry point for the application"""
    parser = argparse.ArgumentParser(description='Advanced Enterprise Network Testing Framework')
    
    # Test mode selection
    mode_group = parser.add_argument_group('Test Mode')
    mode_group.add_argument('--scan', action='store_true', help='Perform network scan of target')
    mode_group.add_argument('--load-test', action='store_true', help='Perform load test on target')
    
    # Common arguments
    parser.add_argument('--url', '-u', required=True, help='Target URL to test')
    parser.add_argument('--timeout', '-t', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL certificate verification')
    parser.add_argument('--output', '-o', help='Output file for test results')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--quiet', '-q', action='store_true', help='Minimal output')
    
    # Network scan arguments
    scan_group = parser.add_argument_group('Network Scan Options')
    scan_group.add_argument('--scan-depth', type=int, default=2, choices=[1, 2, 3], 
                           help='Depth for endpoint discovery (1-3)')
    scan_group.add_argument('--no-cdn-check', action='store_true', help='Skip CDN detection')
    scan_group.add_argument('--no-waf-check', action='store_true', help='Skip WAF detection')
    scan_group.add_argument('--no-endpoint-discovery', action='store_true', help='Skip endpoint discovery')
    
    # Load test arguments
    load_group = parser.add_argument_group('Load Test Options')
    load_group.add_argument('--requests', '-n', type=int, default=1000, help='Number of requests to make')
    load_group.add_argument('--concurrency', '-c', type=int, default=10, help='Number of concurrent requests')
    load_group.add_argument('--ramp-up', type=int, default=0, help='Ramp up time in seconds')
    load_group.add_argument('--duration', '-d', type=int, help='Test duration in seconds (overrides requests)')
    load_group.add_argument('--delay', type=float, default=0, help='Delay between requests in seconds')
    load_group.add_argument('--endpoints', type=str, help='File with list of endpoints to test')
    load_group.add_argument('--cookies', type=str, help='File with cookies in JSON format')
    load_group.add_argument('--headers', type=str, help='File with headers in JSON format')
    load_group.add_argument('--distributed', action='store_true', help='Run in distributed mode')
    load_group.add_argument('--workers', type=int, help='Number of worker processes for distributed mode')
    load_group.add_argument('--report-interval', type=int, default=5, help='Progress report interval in seconds')
    load_group.add_argument('--save-raw', action='store_true', help='Save raw request data to CSV')
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    elif args.quiet:
        logger.setLevel(logging.WARNING)
    
    # Validate URL
    try:
        parsed_url = urlparse(args.url)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            logger.error("Invalid URL provided. Must include scheme (http/https) and host.")
            return 1
    except Exception:
        logger.error("Failed to parse URL.")
        return 1
        
    # Execute chosen mode
    if args.scan:
        return run_network_scan(args)
    elif args.load_test:
        return run_load_test(args)
    else:
        logger.error("No test mode selected. Please use --scan or --load-test.")
        parser.print_help()
        return 1


async def run_network_scan_async(args):
    """Run network scan asynchronously"""
    scanner = NetworkScanner(
        base_url=args.url,
        check_cdn=not args.no_cdn_check,
        check_waf=not args.no_waf_check,
        enumerate_endpoints=not args.no_endpoint_discovery,
        scan_depth=args.scan_depth,
        timeout=args.timeout
    )
    
    results = await scanner.scan_site()
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Network scan results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))
        
    return 0


def run_network_scan(args):
    """Run the network scan"""
    try:
        asyncio.run(run_network_scan_async(args))
        return 0
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user.")
        return 130
    except Exception as e:
        logger.error(f"Error in network scan: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


async def run_load_test_async(args):
    """Run load test asynchronously"""
    # Load endpoints if provided
    endpoints = None
    if args.endpoints:
        try:
            with open(args.endpoints, 'r') as f:
                endpoints = [line.strip() for line in f if line.strip()]
            logger.info(f"Loaded {len(endpoints)} endpoints from {args.endpoints}")
        except Exception as e:
            logger.error(f"Failed to load endpoints file: {str(e)}")
            return 1
            
    # Load cookies if provided
    cookies = None
    if args.cookies:
        try:
            with open(args.cookies, 'r') as f:
                cookies = json.load(f)
            logger.info(f"Loaded cookies from {args.cookies}")
        except Exception as e:
            logger.error(f"Failed to load cookies file: {str(e)}")
            return 1
            
    # Load headers if provided
    headers = None
    if args.headers:
        try:
            with open(args.headers, 'r') as f:
                headers = json.load(f)
            logger.info(f"Loaded headers from {args.headers}")
        except Exception as e:
            logger.error(f"Failed to load headers file: {str(e)}")
            return 1
    
    # Create and run load tester
    load_tester = AsyncLoadTester(
        base_url=args.url,
        num_requests=args.requests,
        concurrency=args.concurrency,
        ramp_up=args.ramp_up,
        duration=args.duration,
        delay=args.delay,
        timeout=args.timeout,
        verify_ssl=not args.no_verify_ssl,
        endpoints=endpoints,
        cookies=cookies,
        headers=headers,
        report_interval=args.report_interval,
        distributed=args.distributed,
        worker_processes=args.workers
    )
    
    try:
        await load_tester.run_test()
        
        # Save report if requested
        if args.output:
            load_tester.save_report(args.output)
            
        # Save raw data if requested
        if args.save_raw:
            raw_output = f"{args.output}_raw.csv" if args.output else None
            load_tester.save_raw_data(raw_output)
            
        return 0
    except Exception as e:
        logger.error(f"Error in load test: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def run_load_test(args):
    """Run the load test"""
    try:
        asyncio.run(run_load_test_async(args))
        return 0
    except KeyboardInterrupt:
        logger.info("Load test interrupted by user.")
        return 130
    except Exception as e:
        logger.error(f"Error in load test: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
