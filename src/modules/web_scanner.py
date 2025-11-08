"""
Web application scanning module for detecting common vulnerabilities
"""

import asyncio
import aiohttp
import re
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

from src.core.logger import get_logger


class WebScanner:
    """Web application vulnerability scanner"""

    def __init__(self, config):
        self.config = config
        self.logger = get_logger()
        self.timeout = config.get('scanning.web.timeout', 10)
        self.max_depth = config.get('scanning.web.max_depth', 3)
        self.user_agent = config.get('scanning.web.user_agent',
                                     'Mozilla/5.0 (compatible; AI-Pentest-Bot/1.0)')

        # Common vulnerability payloads
        self.xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '<img src=x onerror=alert(1)>',
            'javascript:alert(1)'
        ]

        self.sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "1' OR '1'='1",
            "' UNION SELECT NULL--"
        ]

        self.visited_urls: Set[str] = set()

    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Perform web application scan

        Args:
            target: Target URL or domain

        Returns:
            Scan results
        """
        # Normalize URL
        if not target.startswith(('http://', 'https://')):
            target = f'http://{target}'

        results = {
            'target': target,
            'scan_type': 'web',
            'success': True,
            'vulnerabilities': [],
            'urls_discovered': [],
            'forms_found': [],
            'headers': {},
            'cookies': [],
            'technologies': []
        }

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': self.user_agent}
            ) as session:

                # Initial request to get basic info
                initial_info = await self._get_initial_info(session, target)
                results.update(initial_info)

                # Crawl site
                urls = await self._crawl(session, target, depth=0)
                results['urls_discovered'] = list(urls)
                self.logger.info(f"Discovered {len(urls)} URLs")

                # Find forms
                forms = await self._find_forms(session, target)
                results['forms_found'] = forms
                self.logger.info(f"Found {len(forms)} forms")

                # Test for XSS
                xss_vulns = await self._test_xss(session, forms)
                results['vulnerabilities'].extend(xss_vulns)

                # Test for SQL injection
                sqli_vulns = await self._test_sqli(session, forms)
                results['vulnerabilities'].extend(sqli_vulns)

                # Test for CSRF
                csrf_issues = await self._test_csrf(session, forms)
                results['vulnerabilities'].extend(csrf_issues)

                # Check security headers
                header_issues = self._check_security_headers(results.get('headers', {}))
                results['vulnerabilities'].extend(header_issues)

                # Detect technologies
                technologies = self._detect_technologies(results.get('headers', {}),
                                                        initial_info.get('html', ''))
                results['technologies'] = technologies

                results['total_vulnerabilities'] = len(results['vulnerabilities'])

        except Exception as e:
            self.logger.error(f"Web scan failed: {e}", exc_info=True)
            results['success'] = False
            results['error'] = str(e)

        return results

    async def _get_initial_info(self, session: aiohttp.ClientSession,
                                url: str) -> Dict[str, Any]:
        """Get initial information about the target"""
        info = {
            'status_code': None,
            'headers': {},
            'cookies': [],
            'html': '',
            'title': ''
        }

        try:
            async with session.get(url, allow_redirects=True) as response:
                info['status_code'] = response.status
                info['headers'] = dict(response.headers)

                # Get cookies
                for cookie in session.cookie_jar:
                    info['cookies'].append({
                        'name': cookie.key,
                        'value': cookie.value,
                        'domain': cookie['domain'],
                        'secure': cookie.get('secure', False),
                        'httponly': cookie.get('httponly', False)
                    })

                # Get HTML
                if 'text/html' in response.headers.get('Content-Type', ''):
                    html = await response.text()
                    info['html'] = html

                    # Extract title
                    soup = BeautifulSoup(html, 'html.parser')
                    title_tag = soup.find('title')
                    if title_tag:
                        info['title'] = title_tag.string

        except Exception as e:
            self.logger.warning(f"Failed to get initial info: {e}")

        return info

    async def _crawl(self, session: aiohttp.ClientSession,
                    url: str, depth: int) -> Set[str]:
        """Crawl website to discover URLs"""
        if depth > self.max_depth or url in self.visited_urls:
            return set()

        self.visited_urls.add(url)
        discovered = {url}

        try:
            async with session.get(url, allow_redirects=True) as response:
                if 'text/html' not in response.headers.get('Content-Type', ''):
                    return discovered

                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')

                # Find all links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    absolute_url = urljoin(url, href)

                    # Only crawl same domain
                    if urlparse(absolute_url).netloc == urlparse(url).netloc:
                        if absolute_url not in self.visited_urls:
                            sub_urls = await self._crawl(session, absolute_url, depth + 1)
                            discovered.update(sub_urls)

        except Exception as e:
            self.logger.debug(f"Crawl error for {url}: {e}")

        return discovered

    async def _find_forms(self, session: aiohttp.ClientSession,
                         url: str) -> List[Dict[str, Any]]:
        """Find all forms on the page"""
        forms = []

        try:
            async with session.get(url, allow_redirects=True) as response:
                if 'text/html' not in response.headers.get('Content-Type', ''):
                    return forms

                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')

                for form in soup.find_all('form'):
                    form_data = {
                        'action': urljoin(url, form.get('action', '')),
                        'method': form.get('method', 'get').upper(),
                        'inputs': []
                    }

                    # Extract inputs
                    for input_tag in form.find_all(['input', 'textarea']):
                        form_data['inputs'].append({
                            'name': input_tag.get('name', ''),
                            'type': input_tag.get('type', 'text'),
                            'value': input_tag.get('value', '')
                        })

                    forms.append(form_data)

        except Exception as e:
            self.logger.debug(f"Error finding forms: {e}")

        return forms

    async def _test_xss(self, session: aiohttp.ClientSession,
                       forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for XSS vulnerabilities"""
        vulnerabilities = []

        for form in forms[:5]:  # Limit testing to first 5 forms
            for payload in self.xss_payloads[:3]:  # Test with 3 payloads
                try:
                    # Build form data
                    data = {}
                    for input_field in form['inputs']:
                        name = input_field.get('name')
                        if name:
                            data[name] = payload

                    # Submit form
                    if form['method'] == 'POST':
                        async with session.post(form['action'], data=data) as response:
                            html = await response.text()

                            # Check if payload is reflected
                            if payload in html:
                                vulnerabilities.append({
                                    'type': 'XSS',
                                    'severity': 'high',
                                    'url': form['action'],
                                    'method': form['method'],
                                    'payload': payload,
                                    'description': 'Potential Cross-Site Scripting (XSS) vulnerability detected'
                                })
                                break  # Found vuln, no need to test other payloads

                except Exception as e:
                    self.logger.debug(f"XSS test error: {e}")

        return vulnerabilities

    async def _test_sqli(self, session: aiohttp.ClientSession,
                        forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for SQL injection vulnerabilities"""
        vulnerabilities = []

        for form in forms[:5]:  # Limit testing
            for payload in self.sqli_payloads[:3]:
                try:
                    data = {}
                    for input_field in form['inputs']:
                        name = input_field.get('name')
                        if name:
                            data[name] = payload

                    if form['method'] == 'POST':
                        async with session.post(form['action'], data=data) as response:
                            html = await response.text()

                            # Look for SQL error messages
                            sql_errors = [
                                'sql syntax',
                                'mysql_fetch',
                                'syntax error',
                                'unclosed quotation',
                                'postgresql',
                                'ora-01',
                                'microsoft ole db'
                            ]

                            html_lower = html.lower()
                            for error in sql_errors:
                                if error in html_lower:
                                    vulnerabilities.append({
                                        'type': 'SQL Injection',
                                        'severity': 'critical',
                                        'url': form['action'],
                                        'method': form['method'],
                                        'payload': payload,
                                        'description': 'Potential SQL Injection vulnerability detected'
                                    })
                                    break

                except Exception as e:
                    self.logger.debug(f"SQLi test error: {e}")

        return vulnerabilities

    async def _test_csrf(self, session: aiohttp.ClientSession,
                        forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for CSRF protection"""
        issues = []

        for form in forms:
            # Check if form has CSRF token
            has_csrf_token = False
            for input_field in form['inputs']:
                name = input_field.get('name', '').lower()
                if any(token in name for token in ['csrf', 'token', '_token', 'authenticity']):
                    has_csrf_token = True
                    break

            # If it's a state-changing form without CSRF token, flag it
            if form['method'] == 'POST' and not has_csrf_token:
                issues.append({
                    'type': 'Missing CSRF Protection',
                    'severity': 'medium',
                    'url': form['action'],
                    'method': form['method'],
                    'description': 'Form lacks CSRF protection token'
                })

        return issues

    def _check_security_headers(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for security headers"""
        issues = []

        # Required security headers
        security_headers = {
            'X-Frame-Options': 'Prevents clickjacking attacks',
            'X-Content-Type-Options': 'Prevents MIME sniffing',
            'Strict-Transport-Security': 'Enforces HTTPS',
            'Content-Security-Policy': 'Prevents XSS and other injection attacks',
            'X-XSS-Protection': 'Enables browser XSS protection'
        }

        for header, description in security_headers.items():
            if header not in headers:
                issues.append({
                    'type': 'Missing Security Header',
                    'severity': 'low',
                    'header': header,
                    'description': f'Missing {header}: {description}'
                })

        # Check for insecure cookies
        # This would need access to Set-Cookie headers
        # Implementation simplified for now

        return issues

    def _detect_technologies(self, headers: Dict[str, str], html: str) -> List[str]:
        """Detect technologies used by the website"""
        technologies = []

        # Check headers
        server = headers.get('Server', '')
        if server:
            technologies.append(f"Server: {server}")

        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            technologies.append(f"Powered by: {powered_by}")

        # Check HTML for common patterns
        if 'wp-content' in html or 'wordpress' in html.lower():
            technologies.append('WordPress')

        if 'drupal' in html.lower():
            technologies.append('Drupal')

        if 'joomla' in html.lower():
            technologies.append('Joomla')

        if re.search(r'react', html, re.IGNORECASE):
            technologies.append('React')

        if re.search(r'angular', html, re.IGNORECASE):
            technologies.append('Angular')

        if re.search(r'vue\.js', html, re.IGNORECASE):
            technologies.append('Vue.js')

        return technologies
