"""
AI-powered analysis engine using Claude
"""

import json
from typing import Dict, List, Any, Optional
from anthropic import Anthropic

from src.core.logger import get_logger


class AIAnalyzer:
    """AI-powered vulnerability analysis using Claude"""

    def __init__(self, config):
        self.config = config
        self.logger = get_logger()

        # Initialize Anthropic client
        try:
            api_key = config.get_api_key()
            self.client = Anthropic(api_key=api_key)
            self.model = config.get_model()
            self.max_tokens = config.get_max_tokens()
        except Exception as e:
            self.logger.error(f"Failed to initialize AI analyzer: {e}")
            raise

    async def analyze(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze scan results using AI

        Args:
            scan_results: Combined scan results from all modules

        Returns:
            AI analysis results
        """
        self.logger.info("Starting AI analysis of scan results")

        analysis = {
            'summary': '',
            'risk_assessment': '',
            'critical_findings': [],
            'recommendations': [],
            'attack_vectors': [],
            'remediation_priority': [],
            'executive_summary': ''
        }

        try:
            # Prepare data for analysis
            analysis_prompt = self._build_analysis_prompt(scan_results)

            # Call Claude API
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                messages=[{
                    "role": "user",
                    "content": analysis_prompt
                }]
            )

            # Parse AI response
            ai_response = response.content[0].text

            # Extract structured analysis
            analysis = self._parse_ai_response(ai_response)

            self.logger.info("AI analysis completed successfully")

        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}", exc_info=True)
            analysis['error'] = str(e)

        return analysis

    def _build_analysis_prompt(self, scan_results: Dict[str, Any]) -> str:
        """Build prompt for AI analysis"""

        # Extract key findings
        target = scan_results.get('target', 'Unknown')
        scan_types = scan_results.get('scan_types', [])

        # Compile vulnerabilities from all scan types
        all_vulnerabilities = []

        results = scan_results.get('results', {})

        # Network scan vulnerabilities
        if 'network' in results:
            network_results = results['network']
            hosts = network_results.get('hosts', [])
            for host in hosts:
                for port in host.get('open_ports', []):
                    all_vulnerabilities.append({
                        'type': 'Open Port',
                        'severity': 'info',
                        'details': f"Port {port['port']} ({port['service']}) is open on {host['host']}"
                    })

        # Web scan vulnerabilities
        if 'web' in results:
            web_results = results['web']
            web_vulns = web_results.get('vulnerabilities', [])
            all_vulnerabilities.extend(web_vulns)

        # Vulnerability scan results
        if 'vulnerability' in results:
            vuln_results = results['vulnerability']
            vulns = vuln_results.get('vulnerabilities', [])
            all_vulnerabilities.extend(vulns)

        # Build prompt
        prompt = f"""You are a cybersecurity expert analyzing penetration testing results.
Analyze the following scan results and provide a comprehensive security assessment.

TARGET: {target}
SCAN TYPES: {', '.join(scan_types)}

FINDINGS:
{json.dumps(all_vulnerabilities, indent=2)}

Please provide a detailed analysis in the following format:

## EXECUTIVE SUMMARY
[2-3 sentences summarizing the overall security posture]

## RISK ASSESSMENT
[Overall risk level: Critical/High/Medium/Low and justification]

## CRITICAL FINDINGS
[List the most critical security issues found, in order of severity]

## ATTACK VECTORS
[Describe potential attack vectors an adversary could use based on findings]

## REMEDIATION PRIORITY
[List fixes in order of priority with specific actions]

## RECOMMENDATIONS
[Strategic security recommendations for improving overall security posture]

Please be specific, actionable, and prioritize findings by actual risk."""

        return prompt

    def _parse_ai_response(self, ai_response: str) -> Dict[str, Any]:
        """Parse AI response into structured format"""
        analysis = {
            'summary': '',
            'risk_assessment': '',
            'critical_findings': [],
            'recommendations': [],
            'attack_vectors': [],
            'remediation_priority': [],
            'executive_summary': '',
            'raw_analysis': ai_response
        }

        # Simple parsing - extract sections
        sections = {
            'EXECUTIVE SUMMARY': 'executive_summary',
            'RISK ASSESSMENT': 'risk_assessment',
            'CRITICAL FINDINGS': 'critical_findings',
            'ATTACK VECTORS': 'attack_vectors',
            'REMEDIATION PRIORITY': 'remediation_priority',
            'RECOMMENDATIONS': 'recommendations'
        }

        current_section = None
        current_content = []

        for line in ai_response.split('\n'):
            line = line.strip()

            # Check if line is a section header
            is_header = False
            for header, key in sections.items():
                if header in line.upper() and line.startswith('#'):
                    # Save previous section
                    if current_section:
                        content = '\n'.join(current_content).strip()
                        if current_section in ['critical_findings', 'recommendations',
                                               'attack_vectors', 'remediation_priority']:
                            # Parse as list
                            items = [item.strip('- ').strip()
                                   for item in current_content
                                   if item.strip().startswith('-')]
                            analysis[current_section] = items
                        else:
                            analysis[current_section] = content

                    # Start new section
                    current_section = key
                    current_content = []
                    is_header = True
                    break

            if not is_header and line:
                current_content.append(line)

        # Save last section
        if current_section:
            content = '\n'.join(current_content).strip()
            if current_section in ['critical_findings', 'recommendations',
                                   'attack_vectors', 'remediation_priority']:
                items = [item.strip('- ').strip()
                       for item in current_content
                       if item.strip().startswith('-')]
                analysis[current_section] = items
            else:
                analysis[current_section] = content

        # Create summary from executive summary
        analysis['summary'] = analysis['executive_summary']

        return analysis

    async def analyze_vulnerability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a specific vulnerability in detail

        Args:
            vulnerability: Vulnerability data

        Returns:
            Detailed analysis
        """
        prompt = f"""Analyze this security vulnerability:

TYPE: {vulnerability.get('type', 'Unknown')}
SEVERITY: {vulnerability.get('severity', 'Unknown')}
DESCRIPTION: {vulnerability.get('description', 'No description')}

Provide:
1. Detailed explanation of the vulnerability
2. Potential impact and exploitation scenarios
3. Step-by-step remediation instructions
4. Additional security best practices

Be specific and actionable."""

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}]
            )

            return {
                'vulnerability': vulnerability,
                'analysis': response.content[0].text
            }

        except Exception as e:
            self.logger.error(f"Vulnerability analysis failed: {e}")
            return {
                'vulnerability': vulnerability,
                'error': str(e)
            }

    def get_severity_distribution(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of vulnerabilities by severity"""
        distribution = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in distribution:
                distribution[severity] += 1

        return distribution
