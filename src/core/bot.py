"""
Main bot orchestrator for AI Pentest Bot
"""

import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime

from src.core.config import Config, AuthorizationConfig
from src.core.logger import get_logger
from src.utils.validators import TargetValidator, AuthorizationValidator
from src.utils.helpers import get_timestamp, ensure_directory


class PentestBot:
    """Main orchestrator for penetration testing operations"""

    def __init__(self, config_file: str = "config/config.yaml"):
        """Initialize the bot"""
        self.config = Config(config_file)
        self.logger = get_logger(
            log_dir=self.config.get_log_dir(),
            log_level=self.config.get_log_level()
        )

        # Load authorization
        self.auth_config = AuthorizationConfig(self.config.get_authorization_file())

        # Load blacklist
        self.blacklist = self._load_blacklist()

        # Initialize validator
        self.auth_validator = AuthorizationValidator(
            self.auth_config.get_authorized_targets(),
            self.blacklist
        )

        # Scanner modules (will be initialized as needed)
        self.network_scanner = None
        self.web_scanner = None
        self.vulnerability_scanner = None
        self.ai_analyzer = None

        self.logger.info("AI Pentest Bot initialized")

    def _load_blacklist(self) -> List[str]:
        """Load blacklist from file"""
        blacklist_file = self.config.get('safety.blacklist_file', 'config/blacklist.txt')
        try:
            with open(blacklist_file, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            self.logger.warning(f"Blacklist file not found: {blacklist_file}")
            return []

    def validate_target(self, target: str) -> Dict[str, Any]:
        """
        Validate target before scanning

        Returns:
            dict with 'valid', 'reason', 'normalized_target', 'target_type', 'authorization'
        """
        result = {
            'valid': False,
            'reason': '',
            'normalized_target': '',
            'target_type': '',
            'authorization': None
        }

        try:
            # Normalize target
            normalized, target_type = TargetValidator.normalize_target(target)
            result['normalized_target'] = normalized
            result['target_type'] = target_type

            # Check authorization
            if self.config.require_authorization():
                is_authorized, auth_info = self.auth_validator.is_authorized(normalized)

                if not is_authorized:
                    result['reason'] = auth_info.get('reason', 'Not authorized')
                    self.logger.warning(
                        f"Unauthorized scan attempt: {normalized} - {result['reason']}"
                    )
                    self.logger.audit(
                        "UNAUTHORIZED_SCAN_ATTEMPT",
                        target=normalized,
                        reason=result['reason']
                    )
                    return result

                result['authorization'] = auth_info

            result['valid'] = True
            result['reason'] = 'Target validated successfully'

        except ValueError as e:
            result['reason'] = str(e)
            self.logger.error(f"Target validation failed: {e}")

        return result

    async def scan_target(self, target: str, scan_types: List[str] = None) -> Dict[str, Any]:
        """
        Perform comprehensive scan on target

        Args:
            target: Target to scan
            scan_types: List of scan types to perform (network, web, vulnerability, all)

        Returns:
            Scan results dictionary
        """
        start_time = datetime.now()

        # Validate target
        validation = self.validate_target(target)
        if not validation['valid']:
            return {
                'success': False,
                'error': validation['reason'],
                'target': target
            }

        normalized_target = validation['normalized_target']
        target_type = validation['target_type']

        self.logger.info(f"Starting scan of {normalized_target} (type: {target_type})")
        self.logger.audit(
            "SCAN_STARTED",
            target=normalized_target,
            target_type=target_type,
            scan_types=scan_types or ['all']
        )

        # Determine which scans to run
        if scan_types is None or 'all' in scan_types:
            scan_types = ['network', 'web', 'vulnerability']

        results = {
            'target': normalized_target,
            'target_type': target_type,
            'scan_types': scan_types,
            'start_time': start_time.isoformat(),
            'authorization': validation.get('authorization'),
            'results': {},
            'ai_analysis': None,
            'success': True
        }

        # Run scans
        tasks = []

        if 'network' in scan_types and self.config.is_network_scan_enabled():
            if target_type in ['ip', 'domain', 'cidr']:
                tasks.append(self._run_network_scan(normalized_target))

        if 'web' in scan_types and self.config.is_web_scan_enabled():
            if target_type in ['url', 'domain']:
                tasks.append(self._run_web_scan(normalized_target))

        if 'vulnerability' in scan_types and self.config.is_vulnerability_scan_enabled():
            tasks.append(self._run_vulnerability_scan(normalized_target))

        # Execute scans concurrently
        if tasks:
            scan_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            for i, scan_type in enumerate(['network', 'web', 'vulnerability'][:len(tasks)]):
                if isinstance(scan_results[i], Exception):
                    results['results'][scan_type] = {
                        'error': str(scan_results[i]),
                        'success': False
                    }
                else:
                    results['results'][scan_type] = scan_results[i]

        # Run AI analysis on results
        if self.ai_analyzer:
            try:
                ai_analysis = await self._run_ai_analysis(results)
                results['ai_analysis'] = ai_analysis
            except Exception as e:
                self.logger.error(f"AI analysis failed: {e}", exc_info=True)
                results['ai_analysis'] = {'error': str(e)}

        # Calculate duration
        end_time = datetime.now()
        results['end_time'] = end_time.isoformat()
        results['duration_seconds'] = (end_time - start_time).total_seconds()

        self.logger.info(
            f"Scan completed for {normalized_target} in {results['duration_seconds']:.2f}s"
        )
        self.logger.audit(
            "SCAN_COMPLETED",
            target=normalized_target,
            duration=results['duration_seconds'],
            success=results['success']
        )

        return results

    async def _run_network_scan(self, target: str) -> Dict[str, Any]:
        """Run network scan"""
        self.logger.info(f"Running network scan on {target}")

        if self.network_scanner is None:
            from src.modules.network_scanner import NetworkScanner
            self.network_scanner = NetworkScanner(self.config)

        return await self.network_scanner.scan(target)

    async def _run_web_scan(self, target: str) -> Dict[str, Any]:
        """Run web application scan"""
        self.logger.info(f"Running web scan on {target}")

        if self.web_scanner is None:
            from src.modules.web_scanner import WebScanner
            self.web_scanner = WebScanner(self.config)

        return await self.web_scanner.scan(target)

    async def _run_vulnerability_scan(self, target: str) -> Dict[str, Any]:
        """Run vulnerability scan"""
        self.logger.info(f"Running vulnerability scan on {target}")

        if self.vulnerability_scanner is None:
            from src.modules.vulnerability_scanner import VulnerabilityScanner
            self.vulnerability_scanner = VulnerabilityScanner(self.config)

        return await self.vulnerability_scanner.scan(target)

    async def _run_ai_analysis(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Run AI analysis on scan results"""
        self.logger.info("Running AI analysis on scan results")

        if self.ai_analyzer is None:
            from src.ai.analyzer import AIAnalyzer
            self.ai_analyzer = AIAnalyzer(self.config)

        return await self.ai_analyzer.analyze(scan_results)

    async def generate_report(self, scan_results: Dict[str, Any],
                            output_format: str = 'json') -> str:
        """
        Generate scan report

        Args:
            scan_results: Scan results to report on
            output_format: Report format (json, html, pdf)

        Returns:
            Path to generated report
        """
        from src.ai.report_generator import ReportGenerator

        generator = ReportGenerator(self.config)
        report_path = await generator.generate(scan_results, output_format)

        self.logger.info(f"Report generated: {report_path}")
        return report_path

    def get_status(self) -> Dict[str, Any]:
        """Get bot status"""
        return {
            'initialized': True,
            'config_loaded': self.config is not None,
            'authorization_enabled': self.config.require_authorization(),
            'authorized_targets_count': len(self.auth_config.get_authorized_targets()),
            'network_scan_enabled': self.config.is_network_scan_enabled(),
            'web_scan_enabled': self.config.is_web_scan_enabled(),
            'vulnerability_scan_enabled': self.config.is_vulnerability_scan_enabled(),
        }
