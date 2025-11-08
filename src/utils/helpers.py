"""
Helper utilities for AI Pentest Bot
"""

import os
import json
import time
import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path


def ensure_directory(path: str) -> None:
    """Ensure directory exists, create if not"""
    Path(path).mkdir(parents=True, exist_ok=True)


def get_timestamp() -> str:
    """Get current timestamp in ISO format"""
    return datetime.now().isoformat()


def get_file_timestamp() -> str:
    """Get timestamp suitable for filenames"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def hash_string(text: str) -> str:
    """Generate SHA256 hash of string"""
    return hashlib.sha256(text.encode()).hexdigest()


def load_json(filepath: str) -> Optional[Dict]:
    """Load JSON file"""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        return None


def save_json(data: Dict, filepath: str, indent: int = 2) -> bool:
    """Save data to JSON file"""
    try:
        ensure_directory(os.path.dirname(filepath))
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=indent)
        return True
    except Exception as e:
        return False


def format_bytes(bytes: int) -> str:
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes < 1024.0:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024.0
    return f"{bytes:.2f} PB"


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human readable format"""
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.2f}h"


def truncate_string(text: str, max_length: int = 100) -> str:
    """Truncate string to max length"""
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."


class RateLimiter:
    """Simple rate limiter"""

    def __init__(self, max_calls: int, period: float = 1.0):
        self.max_calls = max_calls
        self.period = period
        self.calls = []

    def wait_if_needed(self) -> None:
        """Wait if rate limit would be exceeded"""
        now = time.time()

        # Remove old calls outside the period
        self.calls = [call_time for call_time in self.calls
                      if now - call_time < self.period]

        # If at limit, wait
        if len(self.calls) >= self.max_calls:
            sleep_time = self.period - (now - self.calls[0])
            if sleep_time > 0:
                time.sleep(sleep_time)
            self.calls = self.calls[1:]

        self.calls.append(now)


def severity_to_score(severity: str) -> int:
    """Convert severity level to numeric score"""
    severity_map = {
        'critical': 5,
        'high': 4,
        'medium': 3,
        'low': 2,
        'info': 1,
        'unknown': 0
    }
    return severity_map.get(severity.lower(), 0)


def score_to_severity(score: float) -> str:
    """Convert CVSS score to severity level"""
    if score >= 9.0:
        return 'critical'
    elif score >= 7.0:
        return 'high'
    elif score >= 4.0:
        return 'medium'
    elif score >= 0.1:
        return 'low'
    else:
        return 'info'


def merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """Recursively merge two dictionaries"""
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def extract_urls_from_text(text: str) -> List[str]:
    """Extract URLs from text"""
    import re
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    return re.findall(url_pattern, text)


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a port is open"""
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False
