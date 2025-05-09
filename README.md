# Advanced Enterprise Network Testing Framework

A professional Python tool for comprehensive web application and network infrastructure testing, including network scanning and load testing capabilities.

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/downloads/)


## Overview

This framework provides two primary testing modes:

1. **Network Scanning**: Analyzes website infrastructure, detects CDN/WAF usage, and discovers endpoints
2. **Load Testing**: Performs high-concurrency load tests with detailed metrics and reporting

## Features

### Network Scanning
- Server information discovery
- SSL certificate analysis
- CDN detection
- WAF (Web Application Firewall) detection
- Endpoint discovery with configurable crawl depth
- Comprehensive output in JSON format

### Load Testing
- Configurable request volume and concurrency
- Ramp-up period support
- Detailed metrics (response times, throughput, status codes)
- Percentile-based statistics (P50, P90, P95, P99)
- Support for distributed testing across multiple processes
- Duration-based or request count-based testing
- Custom headers, cookies, and endpoints
- Comprehensive reporting in JSON and CSV formats

## Installation

### Prerequisites
- Python 3.7+
- pip (Python package manager)

### Dependencies
```bash
pip install requests aiohttp
```

## Usage

### Basic Commands

```bash
# Network Scan
python network_tester.py --scan --url https://example.com

# Load Test
python network_tester.py --load-test --url https://example.com --requests 1000 --concurrency 10
```

### Network Scanning Options

```bash
python network_tester.py --scan --url https://example.com [options]

Options:
  --scan-depth {1,2,3}     Depth for endpoint discovery (default: 2)
  --no-cdn-check           Skip CDN detection
  --no-waf-check           Skip WAF detection
  --no-endpoint-discovery  Skip endpoint discovery
  --timeout SECONDS        Request timeout in seconds (default: 10)
  --no-verify-ssl          Disable SSL certificate verification
  --output FILENAME        Save results to file
  --verbose                Enable verbose output
  --quiet                  Minimal output
```

### Load Testing Options

```bash
python network_tester.py --load-test --url https://example.com [options]

Options:
  --requests, -n NUMBER    Number of requests to make (default: 1000)
  --concurrency, -c NUMBER Number of concurrent requests (default: 10)
  --ramp-up SECONDS        Ramp up time in seconds (default: 0)
  --duration, -d SECONDS   Test duration in seconds (overrides requests)
  --delay SECONDS          Delay between requests in seconds (default: 0)
  --endpoints FILENAME     File with list of endpoints to test
  --cookies FILENAME       File with cookies in JSON format
  --headers FILENAME       File with headers in JSON format
  --distributed            Run in distributed mode
  --workers NUMBER         Number of worker processes for distributed mode
  --report-interval SECONDS Progress report interval in seconds (default: 5)
  --save-raw               Save raw request data to CSV
  --timeout SECONDS        Request timeout in seconds (default: 10)
  --no-verify-ssl          Disable SSL certificate verification
  --output FILENAME        Save results to file
  --verbose                Enable verbose output
  --quiet                  Minimal output
```

## Examples

### Network Scanning Examples

```bash
# Basic scan
python network_tester.py --scan --url https://example.com

# Detailed scan with maximum crawl depth
python network_tester.py --scan --url https://example.com --scan-depth 3 --verbose

# Quick scan without endpoint discovery
python network_tester.py --scan --url https://example.com --no-endpoint-discovery

# Save scan results to file
python network_tester.py --scan --url https://example.com --output scan_results.json
```

### Load Testing Examples

```bash
# Basic load test
python network_tester.py --load-test --url https://example.com

# Higher volume test (100 concurrent requests, 10000 total)
python network_tester.py --load-test --url https://example.com --requests 10000 --concurrency 100

# Time-based test (run for 5 minutes)
python network_tester.py --load-test --url https://example.com --duration 300 --concurrency 50

# Test with gradual ramp-up over 30 seconds
python network_tester.py --load-test --url https://example.com --concurrency 100 --ramp-up 30

# Distributed test across multiple processes
python network_tester.py --load-test --url https://example.com --distributed --workers 4

# Test with custom endpoints file
python network_tester.py --load-test --url https://example.com --endpoints endpoints.txt

# Test with custom headers and cookies
python network_tester.py --load-test --url https://example.com --headers headers.json --cookies cookies.json

# Save detailed test results
python network_tester.py --load-test --url https://example.com --output results.json --save-raw
```

## Input File Formats

### Endpoints File
Plain text file with one endpoint per line:
```
/
/about
/products
/contact
```

### Cookies File
JSON format:
```json
{
  "session_id": "abc123",
  "user_preference": "dark_mode"
}
```

### Headers File
JSON format:
```json
{
  "Authorization": "Bearer token123",
  "X-Custom-Header": "value"
}
```

## Output Formats

### Network Scan Output
JSON format containing:
- Server information (headers, IP, SSL details)
- Discovered endpoints
- Infrastructure details (CDN, WAF)

### Load Test Output
JSON report with:
- Test configuration
- Request statistics (completed, per second)
- Response time statistics (min, max, avg, percentiles)
- Status code distribution
- Error counts

Raw data CSV includes per-request details:
- Request ID
- URL
- Method
- Status code
- Response time
- Response size
- Timestamp
- Error (if any)

## Important Notes

- **Legal Use Only**: This tool is for legitimate testing on systems you own or have explicit permission to test.
- **Rate Limiting**: Be aware of rate limiting on target systems. Use appropriate delays and concurrency.
- **SSL Verification**: The `--no-verify-ssl` option bypasses certificate checks. Use with caution.
- **Resource Usage**: Distributed mode can consume significant system resources.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for professional testing purposes only. Users are responsible for ensuring they have proper authorization before testing any system or network.
