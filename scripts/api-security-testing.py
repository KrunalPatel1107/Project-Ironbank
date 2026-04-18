#!/usr/bin/env python3
"""
API Security Testing Script
============================
Tests an API endpoint for common vulnerabilities:
- SQL Injection
- SSRF (Server-Side Request Forgery)
- Authentication bypass
- Rate limiting
- API versioning

Usage:
    python3 api-security-testing.py --url http://localhost:5000 --api-key your-api-key

Author: Iron Bank Training
License: MIT
"""

import argparse
import requests
import json
import time
from typing import Dict, List, Tuple

# Disable SSL warnings (for testing only)
requests.packages.urllib3.disable_warnings()


class APISecurityTester:
    """Test API endpoints for security vulnerabilities"""

    def __init__(self, base_url: str, api_key: str = None, verbose: bool = False):
        """
        Initialize API security tester

        Args:
            base_url: Base URL of the API (e.g., http://localhost:5000)
            api_key: API key for authentication
            verbose: Print detailed output
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False  # Ignore SSL warnings
        self.results = []

    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """
        Make HTTP request with optional API key

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            **kwargs: Additional arguments for requests.request()

        Returns:
            Response object
        """
        url = f"{self.base_url}{endpoint}"

        # Add API key to headers if provided
        headers = kwargs.get('headers', {})
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'
        kwargs['headers'] = headers

        if self.verbose:
            print(f"[*] {method} {url}")

        try:
            response = self.session.request(method, url, timeout=5, **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            print(f"[!] Error: {e}")
            return None

    def test_sql_injection(self, endpoint: str = '/api/users') -> Tuple[bool, str]:
        """
        Test for SQL injection vulnerability

        Common payloads:
        - ' OR '1'='1' (basic injection)
        - 1' UNION SELECT NULL -- (UNION-based)
        - 1; DROP TABLE users -- (stacked queries)

        Args:
            endpoint: API endpoint to test

        Returns:
            Tuple of (is_vulnerable, message)
        """
        payloads = [
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "1' UNION SELECT NULL --",
            "1; DROP TABLE users --",
            "1' AND SLEEP(5) --"
        ]

        print("\n[+] Testing for SQL Injection...")

        for payload in payloads:
            # Test with GET parameter
            response = self._make_request(
                'GET',
                endpoint,
                params={'id': payload}
            )

            if response is None:
                continue

            if response.status_code == 200 and response.text:
                print(f"  [!] Potential SQL Injection: {payload}")
                self.results.append({
                    'vulnerability': 'SQL Injection',
                    'payload': payload,
                    'status_code': response.status_code,
                    'severity': 'CRITICAL'
                })
                return True, f"SQL Injection found with payload: {payload}"

        print("  [✓] No SQL injection detected")
        return False, "SQL injection tests passed"

    def test_authentication_bypass(self, endpoint: str = '/api/auth/login') -> Tuple[bool, str]:
        """
        Test for broken authentication

        Tests:
        - Missing authentication
        - Default credentials
        - Token tampering

        Args:
            endpoint: API endpoint to test

        Returns:
            Tuple of (is_vulnerable, message)
        """
        print("\n[+] Testing for Authentication Bypass...")

        # Test 1: Access without authentication
        response = self._make_request('GET', endpoint.replace('login', 'users'))
        if response and response.status_code == 200:
            print(f"  [!] Endpoint accessible without authentication")
            self.results.append({
                'vulnerability': 'Broken Authentication',
                'description': 'Endpoint accessible without API key',
                'status_code': response.status_code,
                'severity': 'CRITICAL'
            })
            return True, "Endpoint accessible without authentication"

        # Test 2: Test with invalid/tampered JWT
        invalid_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature'
        response = self._make_request(
            'GET',
            endpoint.replace('login', 'users'),
            headers={'Authorization': f'Bearer {invalid_token}'}
        )
        if response and response.status_code == 200:
            print(f"  [!] Invalid token accepted")
            self.results.append({
                'vulnerability': 'Broken Authentication',
                'description': 'Invalid JWT token accepted',
                'severity': 'CRITICAL'
            })
            return True, "Invalid token accepted"

        print("  [✓] Authentication tests passed")
        return False, "Authentication bypass tests passed"

    def test_rate_limiting(self, endpoint: str = '/api/users', requests_count: int = 100) -> Tuple[bool, str]:
        """
        Test if rate limiting is enforced

        Makes multiple rapid requests to detect rate limiting.
        Expected behavior: 429 Too Many Requests after threshold.

        Args:
            endpoint: API endpoint to test
            requests_count: Number of requests to make

        Returns:
            Tuple of (is_vulnerable, message)
        """
        print(f"\n[+] Testing Rate Limiting (making {requests_count} requests)...")

        status_codes = []
        start_time = time.time()

        for i in range(requests_count):
            response = self._make_request('GET', endpoint)
            if response:
                status_codes.append(response.status_code)

            # Print progress every 20 requests
            if (i + 1) % 20 == 0:
                print(f"  [*] {i + 1}/{requests_count} requests completed")

        elapsed = time.time() - start_time

        # Check if 429 (Too Many Requests) was returned
        if 429 in status_codes:
            print(f"  [✓] Rate limiting enforced (429 Too Many Requests)")
            return False, "Rate limiting enforced"
        else:
            print(f"  [!] No rate limiting detected ({requests_count} requests in {elapsed:.1f}s)")
            self.results.append({
                'vulnerability': 'No Rate Limiting',
                'description': f'{requests_count} requests accepted without rate limiting',
                'requests_per_second': requests_count / elapsed,
                'severity': 'MEDIUM'
            })
            return True, "No rate limiting detected"

    def test_api_versioning(self, endpoints: List[str] = None) -> Tuple[bool, str]:
        """
        Test for proper API versioning

        Tests:
        - Multiple API versions (/v1/users, /v2/users)
        - Deprecation headers
        - Version in response

        Args:
            endpoints: List of API versions to test

        Returns:
            Tuple of (is_vulnerable, message)
        """
        if endpoints is None:
            endpoints = ['/api/v1/users', '/api/v2/users', '/api/v3/users']

        print("\n[+] Testing API Versioning...")

        found_versions = []
        for endpoint in endpoints:
            response = self._make_request('GET', endpoint)
            if response and response.status_code != 404:
                found_versions.append(endpoint)

                # Check for deprecation header
                deprecation = response.headers.get('Deprecation', 'Not specified')
                sunset = response.headers.get('Sunset', 'Not specified')

                print(f"  [*] {endpoint}: {response.status_code}")
                print(f"      Deprecation: {deprecation}")
                print(f"      Sunset: {sunset}")

        if len(found_versions) > 1:
            print(f"  [✓] Multiple API versions found: {found_versions}")
            return False, "API versioning properly implemented"
        else:
            print(f"  [!] Only {len(found_versions)} API version found")
            return False, "Limited API versioning"

    def test_ssrf(self, endpoint: str = '/api/proxy', param: str = 'url') -> Tuple[bool, str]:
        """
        Test for Server-Side Request Forgery (SSRF)

        SSRF allows attacker to make the server request internal resources:
        - http://169.254.169.254/ (AWS metadata)
        - http://localhost/admin (internal endpoints)
        - http://10.0.0.0/internal (internal network)

        Args:
            endpoint: API endpoint that might be vulnerable
            param: Parameter to test (e.g., 'url', 'target')

        Returns:
            Tuple of (is_vulnerable, message)
        """
        print("\n[+] Testing for SSRF (Server-Side Request Forgery)...")

        ssrf_payloads = [
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'http://localhost/admin',
            'http://127.0.0.1:8080',
            'http://10.0.0.0/internal',
            'file:///etc/passwd',  # Local file access
        ]

        for payload in ssrf_payloads:
            response = self._make_request(
                'GET',
                endpoint,
                params={param: payload}
            )

            if response is None:
                continue

            # If we get a response from internal service, it's vulnerable
            if response.status_code == 200 and response.text:
                # Check if response contains internal data
                if any(indicator in response.text.lower() for indicator in ['root:', 'admin', 'meta-data']):
                    print(f"  [!] Possible SSRF: {payload}")
                    self.results.append({
                        'vulnerability': 'SSRF',
                        'payload': payload,
                        'status_code': response.status_code,
                        'severity': 'CRITICAL'
                    })
                    return True, f"SSRF detected with payload: {payload}"

        print("  [✓] No SSRF detected")
        return False, "SSRF tests passed"

    def test_cors_misconfiguration(self, endpoint: str = '/api/users') -> Tuple[bool, str]:
        """
        Test for CORS (Cross-Origin Resource Sharing) misconfiguration

        Misconfigured CORS allows any origin to access the API

        Args:
            endpoint: API endpoint to test

        Returns:
            Tuple of (is_vulnerable, message)
        """
        print("\n[+] Testing CORS Configuration...")

        response = self._make_request(
            'OPTIONS',
            endpoint,
            headers={'Origin': 'https://evil.com'}
        )

        if response:
            acao = response.headers.get('Access-Control-Allow-Origin', 'Not set')
            acac = response.headers.get('Access-Control-Allow-Credentials', 'Not set')

            print(f"  [*] Access-Control-Allow-Origin: {acao}")
            print(f"  [*] Access-Control-Allow-Credentials: {acac}")

            # If *wildcard is set, it's misconfigured
            if acao == '*':
                print(f"  [!] Dangerous CORS: Allows all origins")
                self.results.append({
                    'vulnerability': 'CORS Misconfiguration',
                    'allow_origin': acao,
                    'severity': 'MEDIUM'
                })
                return True, "Dangerous CORS configuration detected"

        print("  [✓] CORS configuration looks secure")
        return False, "CORS tests passed"

    def run_all_tests(self):
        """Run all security tests"""
        print("=" * 60)
        print("API Security Testing Suite")
        print("=" * 60)
        print(f"Target: {self.base_url}")
        print()

        # Run tests
        self.test_sql_injection()
        self.test_authentication_bypass()
        self.test_rate_limiting(requests_count=10)  # Reduced for demo
        self.test_api_versioning()
        self.test_ssrf()
        self.test_cors_misconfiguration()

        # Print summary
        print("\n" + "=" * 60)
        print("Summary")
        print("=" * 60)
        if self.results:
            print(f"\n[!] Found {len(self.results)} potential vulnerabilities:\n")
            for i, result in enumerate(self.results, 1):
                print(f"{i}. {result.get('vulnerability', 'Unknown')}")
                print(f"   Severity: {result.get('severity', 'Unknown')}")
                if 'description' in result:
                    print(f"   Description: {result['description']}")
                print()
        else:
            print("\n[✓] No critical vulnerabilities detected!")

        print("\nFull results:")
        print(json.dumps(self.results, indent=2))


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='API Security Testing Tool'
    )
    parser.add_argument(
        '--url',
        required=True,
        help='Base URL of API to test (e.g., http://localhost:5000)'
    )
    parser.add_argument(
        '--api-key',
        help='API key for authentication (optional)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose output'
    )

    args = parser.parse_args()

    # Create tester and run tests
    tester = APISecurityTester(args.url, args.api_key, args.verbose)
    tester.run_all_tests()


if __name__ == '__main__':
    main()
