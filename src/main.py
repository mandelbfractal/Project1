"""
Main entry point for AI Pentest Bot
"""

import sys
from src.cli import CLI


def main():
    """Main entry point"""
    cli = CLI()
    cli.run()


if __name__ == '__main__':
    main()
