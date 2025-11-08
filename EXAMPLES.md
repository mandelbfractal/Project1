# Usage Examples

This document provides real-world examples of using AI Pentest Bot.

## Basic Scanning

### Scan a Web Application

```bash
# Authorize the target first
python -m src.main authorize -t mywebapp.com \
  --by "Security Team" \
  --notes "Quarterly security assessment Q1 2025"

# Perform comprehensive scan
python -m src.main scan -t mywebapp.com -s all -f html
```

### Network Scan Only

```bash
# Authorize internal network
python -m src.main authorize -t 192.168.1.0/24 \
  --by "Network Admin" \
  --notes "Internal network audit"

# Scan the network
python -m src.main scan -t 192.168.1.0/24 -s network -y
```

### Quick Web Vulnerability Check

```bash
# Already authorized target
python -m src.main scan -t example.com -s web vulnerability -f json -y
```

## Advanced Use Cases

### Automated Scanning Script

Create a script `scan_all.sh`:

```bash
#!/bin/bash

# List of authorized targets
TARGETS=(
  "app1.company.com"
  "app2.company.com"
  "api.company.com"
)

# Scan each target
for target in "${TARGETS[@]}"; do
  echo "Scanning $target..."
  python -m src.main scan -t "$target" -s all -f all -y
  sleep 10  # Rate limiting
done

echo "All scans completed!"
```

### CI/CD Integration

Example GitHub Actions workflow:

```yaml
name: Security Scan

on:
  schedule:
    - cron: '0 2 * * 0'  # Weekly on Sunday at 2 AM

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run security scan
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          python -m src.main scan -t staging.example.com -f json -y

      - name: Upload report
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: reports/
```

## Target Management

### Bulk Authorization

Create `targets.txt`:
```
app1.example.com
app2.example.com
app3.example.com
```

Then authorize all:

```bash
while read target; do
  python -m src.main authorize -t "$target" \
    --by "Security Team" \
    --notes "Batch authorization $(date +%Y-%m-%d)"
done < targets.txt
```

### Remove Expired Authorizations

```bash
# List current targets
python -m src.main list-targets

# Remove specific target
python -m src.main remove-target -t old-app.example.com
```

## Report Generation

### Generate All Report Formats

```bash
python -m src.main scan -t example.com -f all -y
```

This creates:
- `reports/pentest_report_example.com_TIMESTAMP.json`
- `reports/pentest_report_example.com_TIMESTAMP.html`
- `reports/pentest_report_example.com_TIMESTAMP.pdf`

### Custom Report Processing

```python
import json

# Load JSON report
with open('reports/pentest_report_example.com_20250108.json', 'r') as f:
    report = json.load(f)

# Extract high-severity vulnerabilities
high_vulns = [
    v for v in report.get('results', {}).get('web', {}).get('vulnerabilities', [])
    if v.get('severity') == 'high'
]

print(f"Found {len(high_vulns)} high-severity vulnerabilities")

# Create summary
summary = {
    'target': report['target'],
    'scan_date': report['start_time'],
    'critical_count': len([v for v in high_vulns if v.get('severity') == 'critical']),
    'high_count': len(high_vulns)
}

with open('summary.json', 'w') as f:
    json.dump(summary, f, indent=2)
```

## Configuration Examples

### High-Speed Scanning

Edit `config/config.yaml`:

```yaml
scanning:
  network:
    timeout: 10  # Faster but less thorough
    max_ports: 100

  web:
    timeout: 5
    max_depth: 2  # Shallow crawl

safety:
  max_concurrent_scans: 20  # More parallel scans
  require_confirmation: false  # Skip prompts
```

### Thorough Deep Scan

```yaml
scanning:
  network:
    timeout: 60  # More patient
    max_ports: 5000  # Scan more ports

  web:
    timeout: 30
    max_depth: 5  # Deep crawl

  vulnerability:
    check_cve: true
    check_outdated: true
```

## Integration Examples

### Python API Usage

```python
import asyncio
from src.core.bot import PentestBot

async def main():
    # Initialize bot
    bot = PentestBot('config/config.yaml')

    # Scan target
    results = await bot.scan_target(
        target='example.com',
        scan_types=['web', 'vulnerability']
    )

    # Generate report
    if results['success']:
        report_path = await bot.generate_report(results, 'html')
        print(f"Report saved: {report_path}")

        # Access AI analysis
        ai_analysis = results.get('ai_analysis', {})
        print(f"Risk: {ai_analysis.get('risk_assessment')}")

if __name__ == '__main__':
    asyncio.run(main())
```

### Webhook Notifications

```python
import requests
import asyncio
from src.core.bot import PentestBot

async def scan_and_notify(target, webhook_url):
    bot = PentestBot()
    results = await bot.scan_target(target)

    # Count critical vulnerabilities
    critical_count = sum(
        1 for v in results.get('results', {}).get('web', {}).get('vulnerabilities', [])
        if v.get('severity') == 'critical'
    )

    # Send notification
    if critical_count > 0:
        requests.post(webhook_url, json={
            'text': f'⚠️ Found {critical_count} critical vulnerabilities on {target}!',
            'target': target,
            'scan_time': results.get('start_time')
        })

# Usage
asyncio.run(scan_and_notify('example.com', 'https://hooks.slack.com/...'))
```

## Troubleshooting Examples

### Debug Failed Scan

```bash
# Enable debug logging
# Edit config/config.yaml: log_level: "DEBUG"

# Run scan
python -m src.main scan -t problem-site.com -y

# Check detailed logs
tail -f logs/ai_pentest_bot.log
```

### Test Authorization

```bash
# Check if target is authorized
python -m src.main list-targets | grep example.com

# Check configuration
python -m src.main status
```

### Verify API Connection

```python
from anthropic import Anthropic
import os

api_key = os.getenv('ANTHROPIC_API_KEY')
client = Anthropic(api_key=api_key)

response = client.messages.create(
    model="claude-sonnet-4-5-20250929",
    max_tokens=100,
    messages=[{"role": "user", "content": "Hello!"}]
)

print("API connection successful!")
print(response.content[0].text)
```

## Best Practices

### Regular Scanning Schedule

```bash
# Add to crontab for weekly scans
0 2 * * 0 cd /path/to/Project1 && python -m src.main scan -t example.com -f all -y
```

### Scan Before Deployment

```bash
#!/bin/bash
# pre-deployment-scan.sh

echo "Running security scan before deployment..."
python -m src.main scan -t staging.example.com -s web -y

# Check if critical vulnerabilities found
if grep -q "critical" reports/*.json; then
  echo "❌ Critical vulnerabilities found! Blocking deployment."
  exit 1
else
  echo "✅ No critical vulnerabilities. Proceeding with deployment."
  exit 0
fi
```

### Comparison Scanning

```bash
# Scan and save baseline
python -m src.main scan -t example.com -f json -y
cp reports/latest.json reports/baseline.json

# Later, scan again and compare
python -m src.main scan -t example.com -f json -y
diff reports/baseline.json reports/latest.json
```

---

For more examples and use cases, visit the [GitHub repository](https://github.com/mandelbfractal/Project1).
