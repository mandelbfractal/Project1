# 🔒 AI Pentest Bot

An AI-powered penetration testing bot that combines traditional security scanning techniques with advanced AI analysis using Claude. This tool automates vulnerability discovery, provides intelligent analysis, and generates comprehensive security reports.

## ⚠️ Legal Disclaimer

**IMPORTANT:** This tool is designed for authorized security testing only. Unauthorized access to computer systems is illegal. Users must:

- Have explicit written permission to test all targets
- Comply with all applicable laws and regulations
- Use this tool responsibly and ethically
- Not use this tool for malicious purposes

The developers assume no liability for misuse of this tool.

## ✨ Features

### 🔍 Comprehensive Scanning
- **Network Scanning**: Port scanning, service detection, OS fingerprinting
- **Web Application Testing**: XSS, SQL injection, CSRF detection, security header analysis
- **Vulnerability Assessment**: CVE lookup, known vulnerability detection, outdated software identification

### 🤖 AI-Powered Analysis
- Intelligent vulnerability analysis using Claude AI
- Risk assessment and prioritization
- Attack vector identification
- Actionable remediation recommendations
- Executive summaries for non-technical stakeholders

### 📊 Professional Reporting
- Multiple report formats: JSON, HTML, PDF
- Severity-based vulnerability classification
- Technology stack detection
- Visual dashboards and statistics

### 🛡️ Security Features
- Target authorization system
- Blacklist for protected domains
- Comprehensive audit logging
- Rate limiting
- User confirmation prompts

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Anthropic API key

### Quick Install

```bash
# Clone the repository
git clone https://github.com/mandelbfractal/Project1.git
cd Project1

# Install dependencies
pip install -r requirements.txt

# Or install as package
pip install -e .
```

### Configuration

1. **Set up your Anthropic API key:**

```bash
export ANTHROPIC_API_KEY='your-api-key-here'
```

Or add it to `config/config.yaml`:

```yaml
api:
  anthropic_api_key: "your-api-key-here"
```

2. **Authorize targets for scanning:**

Edit `config/authorization.yaml` to add authorized targets:

```yaml
authorized_targets:
  - target: "example.com"
    scope: "full"
    authorization_date: "2025-01-15"
    authorization_by: "Security Team"
    expiry_date: "2025-12-31"
    notes: "Annual security assessment"
```

Or use the CLI:

```bash
python -m src.main authorize -t example.com --by "Security Team" --notes "Authorized for testing"
```

## 📖 Usage

### Basic Commands

**Check bot status:**
```bash
python -m src.main status
```

**List authorized targets:**
```bash
python -m src.main list-targets
```

**Scan a target:**
```bash
python -m src.main scan -t example.com
```

### Advanced Scanning

**Scan with specific scan types:**
```bash
# Network scan only
python -m src.main scan -t 192.168.1.1 -s network

# Web and vulnerability scans
python -m src.main scan -t example.com -s web vulnerability

# All scan types (default)
python -m src.main scan -t example.com -s all
```

**Generate different report formats:**
```bash
# HTML report
python -m src.main scan -t example.com -f html

# PDF report
python -m src.main scan -t example.com -f pdf

# All formats
python -m src.main scan -t example.com -f all
```

**Skip confirmation prompt:**
```bash
python -m src.main scan -t example.com -y
```

### Target Management

**Authorize a new target:**
```bash
python -m src.main authorize -t example.com \
  --scope full \
  --by "John Doe" \
  --notes "Quarterly security audit"
```

**Remove an authorized target:**
```bash
python -m src.main remove-target -t example.com
```

## 🏗️ Architecture

```
ai-pentest-bot/
├── config/              # Configuration files
│   ├── config.yaml      # Main configuration
│   ├── authorization.yaml  # Authorized targets
│   └── blacklist.txt    # Blacklisted domains
├── src/
│   ├── core/            # Core framework
│   │   ├── bot.py       # Main bot orchestrator
│   │   ├── config.py    # Configuration management
│   │   └── logger.py    # Logging system
│   ├── modules/         # Scanning modules
│   │   ├── network_scanner.py
│   │   ├── web_scanner.py
│   │   └── vulnerability_scanner.py
│   ├── ai/              # AI analysis
│   │   ├── analyzer.py
│   │   └── report_generator.py
│   ├── utils/           # Utilities
│   │   ├── validators.py
│   │   └── helpers.py
│   ├── cli.py           # Command-line interface
│   └── main.py          # Entry point
├── reports/             # Generated reports
├── logs/                # Log files
└── requirements.txt     # Dependencies
```

## 🔧 Configuration

### Main Configuration (`config/config.yaml`)

```yaml
api:
  anthropic_api_key: ""  # Set via environment variable
  model: "claude-sonnet-4-5-20250929"
  max_tokens: 4096

scanning:
  network:
    enabled: true
    timeout: 30
    common_ports: [21, 22, 23, 25, 53, 80, 443, 3306, 8080]

  web:
    enabled: true
    timeout: 10
    max_depth: 3

  vulnerability:
    enabled: true
    check_cve: true

authorization:
  require_authorization: true

reporting:
  output_dir: "reports"
  formats: ["json", "html", "pdf"]

logging:
  log_dir: "logs"
  log_level: "INFO"

safety:
  max_concurrent_scans: 10
  rate_limit: 100
  require_confirmation: true
```

## 📊 Output Examples

### Console Output

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃         AI Pentest Bot                  ┃
┃ Target: example.com                     ┃
┃ Scan Types: network, web, vulnerability ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

✓ Target validated successfully

Starting scan...

✓ Scan completed successfully

Vulnerabilities Found:
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Type          ┃ Description          ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━┩
│ HIGH     │ XSS           │ Potential XSS vuln   │
│ MEDIUM   │ Missing CSRF  │ Form lacks CSRF...   │
└──────────┴───────────────┴──────────────────────┘

✓ Report saved: reports/pentest_report_example.com_20250108.html
```

### JSON Report Structure

```json
{
  "target": "example.com",
  "scan_types": ["network", "web", "vulnerability"],
  "start_time": "2025-01-08T10:30:00",
  "duration_seconds": 45.23,
  "results": {
    "network": { ... },
    "web": { ... },
    "vulnerability": { ... }
  },
  "ai_analysis": {
    "executive_summary": "...",
    "risk_assessment": "...",
    "critical_findings": [...],
    "recommendations": [...]
  }
}
```

## 🔐 Security Best Practices

1. **Always obtain written authorization** before scanning any target
2. **Use the authorization system** to maintain records of approved targets
3. **Review the blacklist** regularly to prevent accidental scans of sensitive domains
4. **Enable audit logging** to track all scanning activities
5. **Limit concurrent scans** to avoid overwhelming targets
6. **Store API keys securely** using environment variables
7. **Review reports** before sharing with stakeholders

## 🐛 Troubleshooting

### Common Issues

**"Target not in authorized list"**
- Solution: Add target using `authorize` command or edit `config/authorization.yaml`

**"Anthropic API key not found"**
- Solution: Set `ANTHROPIC_API_KEY` environment variable or add to config

**"Permission denied" errors**
- Solution: Ensure you have proper permissions or run with appropriate privileges

**Scan timeout**
- Solution: Increase timeout values in `config/config.yaml`

### Debug Mode

Enable debug logging in `config/config.yaml`:

```yaml
logging:
  log_level: "DEBUG"
```

Check logs in the `logs/` directory:
- `ai_pentest_bot.log` - Main log file
- `audit.log` - Security audit trail

## 🤝 Contributing

Contributions are welcome! Please ensure:

1. All code follows security best practices
2. New features include tests
3. Documentation is updated
4. Commits are signed

## 📝 License

This project is provided for educational and authorized security testing purposes only.

## 🙏 Acknowledgments

- Built with [Anthropic Claude](https://www.anthropic.com/)
- Uses industry-standard security testing methodologies
- Inspired by professional penetration testing frameworks

## 📞 Support

For issues, questions, or feature requests, please open an issue on GitHub.

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**
