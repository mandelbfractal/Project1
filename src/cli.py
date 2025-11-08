"""
Command-line interface for AI Pentest Bot
"""

import argparse
import asyncio
import sys
from typing import List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.core.bot import PentestBot
from src.core.config import AuthorizationConfig
from src.core.logger import get_logger


console = Console()


class CLI:
    """Command-line interface for the bot"""

    def __init__(self):
        self.bot: Optional[PentestBot] = None
        self.logger = get_logger()

    def run(self, args: List[str] = None):
        """Run the CLI"""
        parser = self._create_parser()
        parsed_args = parser.parse_args(args)

        if parsed_args.command is None:
            parser.print_help()
            return

        # Initialize bot
        try:
            self.bot = PentestBot(config_file=parsed_args.config)
        except Exception as e:
            console.print(f"[red]Error initializing bot: {e}[/red]")
            sys.exit(1)

        # Route to command handler
        command_handlers = {
            'scan': self._handle_scan,
            'status': self._handle_status,
            'authorize': self._handle_authorize,
            'list-targets': self._handle_list_targets,
            'remove-target': self._handle_remove_target
        }

        handler = command_handlers.get(parsed_args.command)
        if handler:
            try:
                asyncio.run(handler(parsed_args))
            except KeyboardInterrupt:
                console.print("\n[yellow]Operation cancelled by user[/yellow]")
                sys.exit(0)
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
                self.logger.error(f"Command failed: {e}", exc_info=True)
                sys.exit(1)

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            description='AI Pentest Bot - AI-powered penetration testing tool',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Scan a target
  python -m src.main scan -t example.com -s all

  # Scan with specific scan types
  python -m src.main scan -t 192.168.1.1 -s network web

  # Generate HTML report
  python -m src.main scan -t example.com -f html

  # Authorize a new target
  python -m src.main authorize -t example.com

  # Check bot status
  python -m src.main status
            """
        )

        parser.add_argument(
            '-c', '--config',
            default='config/config.yaml',
            help='Configuration file path (default: config/config.yaml)'
        )

        subparsers = parser.add_subparsers(dest='command', help='Available commands')

        # Scan command
        scan_parser = subparsers.add_parser('scan', help='Scan a target')
        scan_parser.add_argument(
            '-t', '--target',
            required=True,
            help='Target to scan (IP, domain, URL, or CIDR range)'
        )
        scan_parser.add_argument(
            '-s', '--scan-types',
            nargs='+',
            choices=['all', 'network', 'web', 'vulnerability'],
            default=['all'],
            help='Types of scans to perform (default: all)'
        )
        scan_parser.add_argument(
            '-f', '--format',
            choices=['json', 'html', 'pdf', 'all'],
            default='json',
            help='Report format (default: json)'
        )
        scan_parser.add_argument(
            '--no-ai',
            action='store_true',
            help='Skip AI analysis'
        )
        scan_parser.add_argument(
            '-y', '--yes',
            action='store_true',
            help='Skip confirmation prompt'
        )

        # Status command
        subparsers.add_parser('status', help='Show bot status')

        # Authorize command
        auth_parser = subparsers.add_parser('authorize', help='Authorize a target for scanning')
        auth_parser.add_argument('-t', '--target', required=True, help='Target to authorize')
        auth_parser.add_argument('--scope', default='full', help='Authorization scope')
        auth_parser.add_argument('--by', default='Administrator', help='Authorized by')
        auth_parser.add_argument('--notes', default='', help='Authorization notes')

        # List targets command
        subparsers.add_parser('list-targets', help='List authorized targets')

        # Remove target command
        remove_parser = subparsers.add_parser('remove-target', help='Remove authorized target')
        remove_parser.add_argument('-t', '--target', required=True, help='Target to remove')

        return parser

    async def _handle_scan(self, args):
        """Handle scan command"""
        console.print(Panel.fit(
            f"[bold cyan]AI Pentest Bot[/bold cyan]\n"
            f"Target: [yellow]{args.target}[/yellow]\n"
            f"Scan Types: [yellow]{', '.join(args.scan_types)}[/yellow]",
            border_style="cyan"
        ))

        # Validate target first
        validation = self.bot.validate_target(args.target)

        if not validation['valid']:
            console.print(f"\n[red]❌ Target validation failed: {validation['reason']}[/red]")

            if 'not in authorized list' in validation['reason'].lower():
                console.print("\n[yellow]💡 Tip: Use 'authorize' command to add this target to the authorized list[/yellow]")

            return

        console.print(f"[green]✓ Target validated successfully[/green]")

        # Confirmation
        if not args.yes and self.bot.config.require_confirmation():
            console.print("\n[yellow]⚠️  You are about to perform a penetration test.[/yellow]")
            console.print("[yellow]Ensure you have proper authorization before proceeding.[/yellow]")

            confirm = console.input("\nProceed with scan? [y/N]: ")
            if confirm.lower() != 'y':
                console.print("[yellow]Scan cancelled[/yellow]")
                return

        # Perform scan
        console.print("\n[cyan]Starting scan...[/cyan]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=None)

            # Run scan
            results = await self.bot.scan_target(
                args.target,
                scan_types=args.scan_types if 'all' not in args.scan_types else None
            )

            progress.update(task, completed=True)

        if not results.get('success'):
            console.print(f"\n[red]❌ Scan failed: {results.get('error', 'Unknown error')}[/red]")
            return

        # Display results summary
        console.print("\n[green]✓ Scan completed successfully[/green]\n")

        self._display_scan_results(results)

        # Generate report
        console.print(f"\n[cyan]Generating {args.format} report...[/cyan]")
        report_path = await self.bot.generate_report(results, args.format)
        console.print(f"[green]✓ Report saved: {report_path}[/green]")

    async def _handle_status(self, args):
        """Handle status command"""
        status = self.bot.get_status()

        table = Table(title="AI Pentest Bot Status", show_header=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="yellow")

        table.add_row("Initialized", "✓" if status['initialized'] else "✗")
        table.add_row("Configuration Loaded", "✓" if status['config_loaded'] else "✗")
        table.add_row("Authorization Enabled", "✓" if status['authorization_enabled'] else "✗")
        table.add_row("Authorized Targets", str(status['authorized_targets_count']))
        table.add_row("Network Scanning", "✓" if status['network_scan_enabled'] else "✗")
        table.add_row("Web Scanning", "✓" if status['web_scan_enabled'] else "✗")
        table.add_row("Vulnerability Scanning", "✓" if status['vulnerability_scan_enabled'] else "✗")

        console.print(table)

    async def _handle_authorize(self, args):
        """Handle authorize command"""
        auth_config = AuthorizationConfig(self.bot.config.get_authorization_file())

        from datetime import datetime, timedelta

        target_info = {
            'target': args.target,
            'scope': args.scope,
            'authorization_date': datetime.now().strftime('%Y-%m-%d'),
            'authorization_by': args.by,
            'expiry_date': (datetime.now() + timedelta(days=365)).strftime('%Y-%m-%d'),
            'notes': args.notes or f'Authorized via CLI on {datetime.now().strftime("%Y-%m-%d")}'
        }

        auth_config.add_target(target_info)

        console.print(f"[green]✓ Target authorized: {args.target}[/green]")

    async def _handle_list_targets(self, args):
        """Handle list-targets command"""
        auth_config = AuthorizationConfig(self.bot.config.get_authorization_file())
        targets = auth_config.get_authorized_targets()

        if not targets:
            console.print("[yellow]No authorized targets found[/yellow]")
            return

        table = Table(title="Authorized Targets", show_header=True)
        table.add_column("Target", style="cyan")
        table.add_column("Scope", style="yellow")
        table.add_column("Authorized By", style="green")
        table.add_column("Date", style="blue")

        for target in targets:
            table.add_row(
                target.get('target', 'Unknown'),
                target.get('scope', 'Unknown'),
                target.get('authorization_by', 'Unknown'),
                target.get('authorization_date', 'Unknown')
            )

        console.print(table)

    async def _handle_remove_target(self, args):
        """Handle remove-target command"""
        auth_config = AuthorizationConfig(self.bot.config.get_authorization_file())

        if auth_config.remove_target(args.target):
            console.print(f"[green]✓ Target removed: {args.target}[/green]")
        else:
            console.print(f"[yellow]Target not found: {args.target}[/yellow]")

    def _display_scan_results(self, results: dict):
        """Display scan results summary"""
        # Vulnerability summary
        all_vulns = []

        scan_results = results.get('results', {})

        for scan_type, scan_data in scan_results.items():
            if isinstance(scan_data, dict) and 'vulnerabilities' in scan_data:
                all_vulns.extend(scan_data['vulnerabilities'])

        if all_vulns:
            table = Table(title="Vulnerabilities Found", show_header=True)
            table.add_column("Severity", style="red")
            table.add_column("Type", style="cyan")
            table.add_column("Description", style="yellow")

            for vuln in all_vulns[:10]:  # Show first 10
                severity_color = {
                    'critical': 'red bold',
                    'high': 'red',
                    'medium': 'yellow',
                    'low': 'blue',
                    'info': 'cyan'
                }.get(vuln.get('severity', 'info').lower(), 'white')

                table.add_row(
                    f"[{severity_color}]{vuln.get('severity', 'Unknown').upper()}[/{severity_color}]",
                    vuln.get('type', 'Unknown'),
                    vuln.get('description', 'No description')[:60] + '...'
                    if len(vuln.get('description', '')) > 60
                    else vuln.get('description', 'No description')
                )

            console.print(table)

            if len(all_vulns) > 10:
                console.print(f"\n[dim]... and {len(all_vulns) - 10} more vulnerabilities[/dim]")
        else:
            console.print("[green]No vulnerabilities found[/green]")

        # AI Analysis summary
        if results.get('ai_analysis'):
            ai_analysis = results['ai_analysis']
            if ai_analysis.get('executive_summary'):
                console.print(Panel(
                    ai_analysis['executive_summary'],
                    title="[bold cyan]AI Analysis - Executive Summary[/bold cyan]",
                    border_style="cyan"
                ))
