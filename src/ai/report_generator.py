"""
Report generation module
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path
from jinja2 import Template

from src.core.logger import get_logger
from src.utils.helpers import ensure_directory, get_file_timestamp


class ReportGenerator:
    """Generate scan reports in various formats"""

    def __init__(self, config):
        self.config = config
        self.logger = get_logger()
        self.output_dir = config.get_output_dir()
        ensure_directory(self.output_dir)

    async def generate(self, scan_results: Dict[str, Any],
                      output_format: str = 'json') -> str:
        """
        Generate report in specified format

        Args:
            scan_results: Scan results data
            output_format: Output format (json, html, pdf, all)

        Returns:
            Path to generated report(s)
        """
        timestamp = get_file_timestamp()
        target = scan_results.get('target', 'unknown').replace('/', '_').replace(':', '_')

        reports = []

        if output_format in ['json', 'all']:
            json_path = await self._generate_json(scan_results, target, timestamp)
            reports.append(json_path)

        if output_format in ['html', 'all']:
            html_path = await self._generate_html(scan_results, target, timestamp)
            reports.append(html_path)

        if output_format in ['pdf', 'all']:
            pdf_path = await self._generate_pdf(scan_results, target, timestamp)
            reports.append(pdf_path)

        return ', '.join(reports) if reports else 'No reports generated'

    async def _generate_json(self, scan_results: Dict[str, Any],
                           target: str, timestamp: str) -> str:
        """Generate JSON report"""
        filename = f"pentest_report_{target}_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)

        try:
            with open(filepath, 'w') as f:
                json.dump(scan_results, f, indent=2, default=str)

            self.logger.info(f"JSON report generated: {filepath}")
            return filepath

        except Exception as e:
            self.logger.error(f"Failed to generate JSON report: {e}")
            raise

    async def _generate_html(self, scan_results: Dict[str, Any],
                           target: str, timestamp: str) -> str:
        """Generate HTML report"""
        filename = f"pentest_report_{target}_{timestamp}.html"
        filepath = os.path.join(self.output_dir, filename)

        try:
            html_content = self._build_html_report(scan_results)

            with open(filepath, 'w') as f:
                f.write(html_content)

            self.logger.info(f"HTML report generated: {filepath}")
            return filepath

        except Exception as e:
            self.logger.error(f"Failed to generate HTML report: {e}")
            raise

    async def _generate_pdf(self, scan_results: Dict[str, Any],
                          target: str, timestamp: str) -> str:
        """Generate PDF report"""
        filename = f"pentest_report_{target}_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        try:
            # For PDF generation, we'll use reportlab
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib import colors

            doc = SimpleDocTemplate(filepath, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []

            # Title
            title = Paragraph(f"<b>Penetration Test Report</b>", styles['Title'])
            story.append(title)
            story.append(Spacer(1, 0.3*inch))

            # Target information
            target_info = f"""
            <b>Target:</b> {scan_results.get('target', 'Unknown')}<br/>
            <b>Scan Date:</b> {scan_results.get('start_time', 'Unknown')}<br/>
            <b>Duration:</b> {scan_results.get('duration_seconds', 0):.2f} seconds<br/>
            """
            story.append(Paragraph(target_info, styles['Normal']))
            story.append(Spacer(1, 0.3*inch))

            # Executive Summary
            if scan_results.get('ai_analysis'):
                ai_analysis = scan_results['ai_analysis']
                if ai_analysis.get('executive_summary'):
                    story.append(Paragraph("<b>Executive Summary</b>", styles['Heading2']))
                    story.append(Paragraph(ai_analysis['executive_summary'], styles['Normal']))
                    story.append(Spacer(1, 0.2*inch))

            # Vulnerability Summary
            all_vulns = self._collect_all_vulnerabilities(scan_results)
            if all_vulns:
                story.append(Paragraph("<b>Vulnerability Summary</b>", styles['Heading2']))

                # Create vulnerability table
                vuln_data = [['Severity', 'Type', 'Description']]
                for vuln in all_vulns[:20]:  # Limit to 20 for PDF
                    vuln_data.append([
                        vuln.get('severity', 'Unknown'),
                        vuln.get('type', 'Unknown'),
                        vuln.get('description', 'No description')[:50] + '...'
                    ])

                vuln_table = Table(vuln_data)
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))

                story.append(vuln_table)
                story.append(Spacer(1, 0.3*inch))

            # Build PDF
            doc.build(story)

            self.logger.info(f"PDF report generated: {filepath}")
            return filepath

        except Exception as e:
            self.logger.error(f"Failed to generate PDF report: {e}")
            # Return empty string if PDF generation fails (optional dependency)
            return ""

    def _build_html_report(self, scan_results: Dict[str, Any]) -> str:
        """Build HTML report content"""
        template_str = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Penetration Test Report - {{ target }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
            border-left: 4px solid #3498db;
            padding-left: 10px;
        }
        .info-box {
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .severity-critical { color: #c0392b; font-weight: bold; }
        .severity-high { color: #e74c3c; font-weight: bold; }
        .severity-medium { color: #f39c12; font-weight: bold; }
        .severity-low { color: #f1c40f; }
        .severity-info { color: #3498db; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #3498db;
            color: white;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .vulnerability {
            background-color: #fff;
            border-left: 4px solid #e74c3c;
            padding: 15px;
            margin: 10px 0;
            border-radius: 3px;
        }
        .recommendation {
            background-color: #d5f4e6;
            border-left: 4px solid #27ae60;
            padding: 15px;
            margin: 10px 0;
            border-radius: 3px;
        }
        .summary {
            background-color: #e8f6f3;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
        ul {
            line-height: 1.8;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Penetration Test Report</h1>

        <div class="info-box">
            <p><strong>Target:</strong> {{ target }}</p>
            <p><strong>Scan Date:</strong> {{ start_time }}</p>
            <p><strong>Duration:</strong> {{ duration }} seconds</p>
            <p><strong>Scan Types:</strong> {{ scan_types }}</p>
        </div>

        {% if ai_analysis %}
        <h2>📊 Executive Summary</h2>
        <div class="summary">
            {{ ai_analysis.executive_summary or 'No executive summary available' }}
        </div>

        {% if ai_analysis.risk_assessment %}
        <h2>⚠️ Risk Assessment</h2>
        <div class="info-box">
            {{ ai_analysis.risk_assessment }}
        </div>
        {% endif %}

        {% if ai_analysis.critical_findings %}
        <h2>🔴 Critical Findings</h2>
        <ul>
        {% for finding in ai_analysis.critical_findings %}
            <li>{{ finding }}</li>
        {% endfor %}
        </ul>
        {% endif %}

        {% if ai_analysis.attack_vectors %}
        <h2>⚔️ Attack Vectors</h2>
        <ul>
        {% for vector in ai_analysis.attack_vectors %}
            <li>{{ vector }}</li>
        {% endfor %}
        </ul>
        {% endif %}

        {% if ai_analysis.recommendations %}
        <h2>✅ Recommendations</h2>
        {% for rec in ai_analysis.recommendations %}
        <div class="recommendation">
            {{ rec }}
        </div>
        {% endfor %}
        {% endif %}
        {% endif %}

        <h2>🔍 Detailed Findings</h2>

        {% if vulnerabilities %}
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Description</th>
                    <th>Location</th>
                </tr>
            </thead>
            <tbody>
            {% for vuln in vulnerabilities %}
                <tr>
                    <td class="severity-{{ vuln.severity }}">{{ vuln.severity|upper }}</td>
                    <td>{{ vuln.type }}</td>
                    <td>{{ vuln.description or 'No description' }}</td>
                    <td>{{ vuln.url or vuln.service or 'N/A' }}</td>
                </tr>
            {% endfor %}
            </tbody>
        </table>
        {% else %}
        <p>No vulnerabilities detected.</p>
        {% endif %}

        <h2>📈 Statistics</h2>
        <div class="info-box">
            <p><strong>Total Vulnerabilities:</strong> {{ total_vulnerabilities }}</p>
            <p><strong>Severity Distribution:</strong></p>
            <ul>
                <li>Critical: {{ severity_dist.critical }}</li>
                <li>High: {{ severity_dist.high }}</li>
                <li>Medium: {{ severity_dist.medium }}</li>
                <li>Low: {{ severity_dist.low }}</li>
                <li>Info: {{ severity_dist.info }}</li>
            </ul>
        </div>

        <hr style="margin: 40px 0;">
        <p style="text-align: center; color: #7f8c8d; font-size: 12px;">
            Generated by AI Pentest Bot | {{ generation_time }}
        </p>
    </div>
</body>
</html>
        """

        # Prepare template data
        all_vulns = self._collect_all_vulnerabilities(scan_results)
        severity_dist = self._get_severity_distribution(all_vulns)

        template_data = {
            'target': scan_results.get('target', 'Unknown'),
            'start_time': scan_results.get('start_time', 'Unknown'),
            'duration': scan_results.get('duration_seconds', 0),
            'scan_types': ', '.join(scan_results.get('scan_types', [])),
            'ai_analysis': scan_results.get('ai_analysis', {}),
            'vulnerabilities': all_vulns,
            'total_vulnerabilities': len(all_vulns),
            'severity_dist': severity_dist,
            'generation_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        template = Template(template_str)
        return template.render(**template_data)

    def _collect_all_vulnerabilities(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Collect all vulnerabilities from scan results"""
        all_vulns = []

        results = scan_results.get('results', {})

        # Web vulnerabilities
        if 'web' in results:
            web_vulns = results['web'].get('vulnerabilities', [])
            all_vulns.extend(web_vulns)

        # Vulnerability scan results
        if 'vulnerability' in results:
            vulns = results['vulnerability'].get('vulnerabilities', [])
            all_vulns.extend(vulns)

        # Network findings (open ports as info level)
        if 'network' in results:
            hosts = results['network'].get('hosts', [])
            for host in hosts:
                for port in host.get('open_ports', []):
                    all_vulns.append({
                        'type': 'Open Port',
                        'severity': 'info',
                        'description': f"Port {port['port']} ({port['service']}) is open",
                        'service': f"{host['host']}:{port['port']}"
                    })

        return all_vulns

    def _get_severity_distribution(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
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
