#!/usr/bin/env python3
"""
Demo script showing how to use AI Pentest Bot programmatically
"""

import asyncio
import json
from src.core.bot import PentestBot

async def demo_scan():
    """Demonstrate bot API usage"""

    print("=" * 60)
    print("AI Pentest Bot - Programmatic Demo")
    print("=" * 60)

    # Initialize bot
    print("\n[1] Initializing bot...")
    bot = PentestBot('config/config.yaml')
    print("✓ Bot initialized")

    # Check status
    print("\n[2] Checking bot status...")
    status = bot.get_status()
    print(f"✓ Authorized targets: {status['authorized_targets_count']}")
    print(f"✓ Network scanning: {'Enabled' if status['network_scan_enabled'] else 'Disabled'}")
    print(f"✓ Web scanning: {'Enabled' if status['web_scan_enabled'] else 'Disabled'}")

    # Validate target
    print("\n[3] Validating target...")
    target = "127.0.0.1"
    validation = bot.validate_target(target)
    print(f"✓ Target: {target}")
    print(f"✓ Valid: {validation['valid']}")
    print(f"✓ Type: {validation['target_type']}")

    # Perform scan
    print("\n[4] Performing scan...")
    results = await bot.scan_target(
        target=target,
        scan_types=['network', 'vulnerability']
    )

    print(f"✓ Scan completed in {results['duration_seconds']:.3f}s")
    print(f"✓ Success: {results['success']}")

    # Show results summary
    print("\n[5] Results Summary:")
    for scan_type, scan_data in results['results'].items():
        if isinstance(scan_data, dict):
            print(f"  - {scan_type.upper()}: {scan_data.get('success', 'N/A')}")

    # Generate report
    print("\n[6] Generating report...")
    report_path = await bot.generate_report(results, 'json')
    print(f"✓ Report saved: {report_path}")

    print("\n" + "=" * 60)
    print("Demo completed successfully!")
    print("=" * 60)

    return results

if __name__ == '__main__':
    results = asyncio.run(demo_scan())

    # Print final stats
    print(f"\nTotal scan duration: {results['duration_seconds']:.3f} seconds")
    print(f"Target: {results['target']}")
    print(f"Scan types: {', '.join(results['scan_types'])}")
