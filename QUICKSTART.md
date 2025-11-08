# Quick Start Guide

Get up and running with AI Pentest Bot in 5 minutes!

## 1. Install Dependencies

```bash
pip install -r requirements.txt
```

## 2. Set Your API Key

```bash
export ANTHROPIC_API_KEY='your-api-key-here'
```

## 3. Authorize a Target

```bash
python -m src.main authorize -t localhost --by "Me" --notes "Testing"
```

## 4. Run Your First Scan

```bash
python -m src.main scan -t localhost -y
```

## 5. View Your Report

Check the `reports/` directory for your generated report!

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Explore different scan types: `network`, `web`, `vulnerability`
- Try different report formats: `html`, `pdf`, `json`
- Configure advanced options in `config/config.yaml`

## Example Commands

```bash
# Check bot status
python -m src.main status

# List authorized targets
python -m src.main list-targets

# Scan with specific types
python -m src.main scan -t example.com -s web vulnerability

# Generate HTML report
python -m src.main scan -t example.com -f html
```

## Need Help?

- Check the troubleshooting section in README.md
- Review logs in the `logs/` directory
- Open an issue on GitHub

Happy testing! 🚀
