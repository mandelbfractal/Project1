"""
Validation utilities for target verification and authorization checks
"""

import re
import socket
import ipaddress
import validators
from typing import Optional, Tuple
from urllib.parse import urlparse


class TargetValidator:
    """Validates and normalizes scan targets"""

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_cidr(cidr: str) -> bool:
        """Check if string is a valid CIDR notation"""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Check if string is a valid domain name"""
        return validators.domain(domain) is True

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Check if string is a valid URL"""
        return validators.url(url) is True

    @staticmethod
    def normalize_target(target: str) -> Tuple[str, str]:
        """
        Normalize target to standard format
        Returns: (normalized_target, target_type)
        """
        target = target.strip()

        # Check if URL
        if target.startswith(('http://', 'https://')):
            if TargetValidator.is_valid_url(target):
                return (target, 'url')
            raise ValueError(f"Invalid URL: {target}")

        # Check if CIDR
        if '/' in target:
            if TargetValidator.is_valid_cidr(target):
                return (target, 'cidr')
            raise ValueError(f"Invalid CIDR notation: {target}")

        # Check if IP
        if TargetValidator.is_valid_ip(target):
            return (target, 'ip')

        # Check if domain
        if TargetValidator.is_valid_domain(target):
            return (target, 'domain')

        raise ValueError(f"Invalid target format: {target}")

    @staticmethod
    def resolve_hostname(hostname: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False

    @staticmethod
    def extract_domain_from_url(url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url)
        return parsed.netloc or parsed.path


class AuthorizationValidator:
    """Validates scan authorization"""

    def __init__(self, authorized_targets: list, blacklist: list):
        self.authorized_targets = authorized_targets
        self.blacklist = blacklist

    def is_blacklisted(self, target: str) -> bool:
        """Check if target is in blacklist"""
        for pattern in self.blacklist:
            pattern = pattern.strip()
            if not pattern or pattern.startswith('#'):
                continue

            # Convert wildcard pattern to regex
            regex_pattern = pattern.replace('.', r'\.').replace('*', '.*')
            if re.match(regex_pattern, target, re.IGNORECASE):
                return True
        return False

    def is_authorized(self, target: str) -> Tuple[bool, Optional[dict]]:
        """
        Check if target is authorized for scanning
        Returns: (is_authorized, authorization_info)
        """
        if self.is_blacklisted(target):
            return (False, {'reason': 'Target is blacklisted'})

        # Extract base target for comparison
        if target.startswith(('http://', 'https://')):
            target = TargetValidator.extract_domain_from_url(target)

        for auth in self.authorized_targets:
            auth_target = auth.get('target', '')

            # Exact match
            if target == auth_target:
                return (True, auth)

            # CIDR match for IPs
            if '/' in auth_target:
                try:
                    network = ipaddress.ip_network(auth_target, strict=False)
                    target_ip = ipaddress.ip_address(target)
                    if target_ip in network:
                        return (True, auth)
                except (ValueError, ipaddress.AddressValueError):
                    continue

            # Domain suffix match
            if target.endswith(auth_target) or auth_target.endswith(target):
                return (True, auth)

        return (False, {'reason': 'Target not in authorized list'})
