"""
Configuration management for AI Pentest Bot
"""

import os
import yaml
from typing import Any, Dict, Optional
from pathlib import Path


class Config:
    """Configuration manager"""

    def __init__(self, config_file: str = "config/config.yaml"):
        self.config_file = config_file
        self.config = self._load_config()
        self._validate_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {self.config_file}")
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in configuration file: {e}")

    def _validate_config(self) -> None:
        """Validate required configuration fields"""
        required_sections = ['api', 'scanning', 'authorization', 'reporting', 'logging']
        for section in required_sections:
            if section not in self.config:
                raise ValueError(f"Missing required configuration section: {section}")

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation
        Example: config.get('api.model')
        """
        keys = key.split('.')
        value = self.config

        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default

        return value

    def set(self, key: str, value: Any) -> None:
        """Set configuration value using dot notation"""
        keys = key.split('.')
        config = self.config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value

    def get_api_key(self) -> str:
        """Get Anthropic API key from config or environment"""
        api_key = self.get('api.anthropic_api_key')
        if not api_key:
            api_key = os.getenv('ANTHROPIC_API_KEY')
        if not api_key:
            raise ValueError(
                "Anthropic API key not found. "
                "Set ANTHROPIC_API_KEY environment variable or add to config.yaml"
            )
        return api_key

    def get_model(self) -> str:
        """Get AI model name"""
        return self.get('api.model', 'claude-sonnet-4-5-20250929')

    def get_max_tokens(self) -> int:
        """Get max tokens for AI responses"""
        return self.get('api.max_tokens', 4096)

    def is_network_scan_enabled(self) -> bool:
        """Check if network scanning is enabled"""
        return self.get('scanning.network.enabled', True)

    def is_web_scan_enabled(self) -> bool:
        """Check if web scanning is enabled"""
        return self.get('scanning.web.enabled', True)

    def is_vulnerability_scan_enabled(self) -> bool:
        """Check if vulnerability scanning is enabled"""
        return self.get('scanning.vulnerability.enabled', True)

    def get_authorization_file(self) -> str:
        """Get authorization file path"""
        return self.get('authorization.authorization_file', 'config/authorization.yaml')

    def require_authorization(self) -> bool:
        """Check if authorization is required"""
        return self.get('authorization.require_authorization', True)

    def get_output_dir(self) -> str:
        """Get reports output directory"""
        return self.get('reporting.output_dir', 'reports')

    def get_log_dir(self) -> str:
        """Get logs directory"""
        return self.get('logging.log_dir', 'logs')

    def get_log_level(self) -> str:
        """Get logging level"""
        return self.get('logging.log_level', 'INFO')

    def get_max_concurrent_scans(self) -> int:
        """Get max concurrent scans"""
        return self.get('safety.max_concurrent_scans', 10)

    def get_rate_limit(self) -> int:
        """Get rate limit (requests per second)"""
        return self.get('safety.rate_limit', 100)

    def require_confirmation(self) -> bool:
        """Check if user confirmation is required"""
        return self.get('safety.require_confirmation', True)

    def to_dict(self) -> Dict[str, Any]:
        """Return configuration as dictionary"""
        return self.config.copy()


class AuthorizationConfig:
    """Authorization configuration manager"""

    def __init__(self, auth_file: str = "config/authorization.yaml"):
        self.auth_file = auth_file
        self.authorized_targets = self._load_authorized_targets()

    def _load_authorized_targets(self) -> list:
        """Load authorized targets from YAML file"""
        try:
            with open(self.auth_file, 'r') as f:
                data = yaml.safe_load(f)
                return data.get('authorized_targets', [])
        except FileNotFoundError:
            print(f"Warning: Authorization file not found: {self.auth_file}")
            return []
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in authorization file: {e}")

    def get_authorized_targets(self) -> list:
        """Get list of authorized targets"""
        return self.authorized_targets

    def add_target(self, target_info: Dict[str, str]) -> None:
        """Add authorized target"""
        self.authorized_targets.append(target_info)
        self._save_config()

    def remove_target(self, target: str) -> bool:
        """Remove authorized target"""
        original_count = len(self.authorized_targets)
        self.authorized_targets = [
            t for t in self.authorized_targets
            if t.get('target') != target
        ]
        if len(self.authorized_targets) < original_count:
            self._save_config()
            return True
        return False

    def _save_config(self) -> None:
        """Save authorization config to file"""
        data = {'authorized_targets': self.authorized_targets}
        with open(self.auth_file, 'w') as f:
            yaml.dump(data, f, default_flow_style=False)
