"""
Logging configuration for AI Pentest Bot
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional


class Logger:
    """Centralized logger for the application"""

    _instance: Optional['Logger'] = None

    def __init__(self, log_dir: str = "logs", log_level: str = "INFO",
                 max_bytes: int = 10485760, backup_count: int = 5):
        """
        Initialize logger

        Args:
            log_dir: Directory for log files
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            max_bytes: Maximum size of each log file
            backup_count: Number of backup files to keep
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        self.max_bytes = max_bytes
        self.backup_count = backup_count

        # Create loggers
        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        """Setup and configure logger"""
        logger = logging.getLogger('ai_pentest_bot')
        logger.setLevel(self.log_level)

        # Remove existing handlers
        logger.handlers = []

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(self.log_level)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

        # File handler (main log)
        main_log_file = self.log_dir / 'ai_pentest_bot.log'
        file_handler = RotatingFileHandler(
            main_log_file,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count
        )
        file_handler.setLevel(self.log_level)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        # Audit log handler (for security-relevant events)
        audit_log_file = self.log_dir / 'audit.log'
        audit_handler = RotatingFileHandler(
            audit_log_file,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count
        )
        audit_handler.setLevel(logging.INFO)
        audit_handler.setFormatter(file_formatter)

        # Create separate audit logger
        audit_logger = logging.getLogger('ai_pentest_bot.audit')
        audit_logger.setLevel(logging.INFO)
        audit_logger.addHandler(audit_handler)
        audit_logger.propagate = False

        return logger

    def debug(self, message: str) -> None:
        """Log debug message"""
        self.logger.debug(message)

    def info(self, message: str) -> None:
        """Log info message"""
        self.logger.info(message)

    def warning(self, message: str) -> None:
        """Log warning message"""
        self.logger.warning(message)

    def error(self, message: str, exc_info: bool = False) -> None:
        """Log error message"""
        self.logger.error(message, exc_info=exc_info)

    def critical(self, message: str, exc_info: bool = False) -> None:
        """Log critical message"""
        self.logger.critical(message, exc_info=exc_info)

    def audit(self, message: str, **kwargs) -> None:
        """
        Log audit event

        Args:
            message: Audit message
            **kwargs: Additional context (target, action, user, result, etc.)
        """
        audit_logger = logging.getLogger('ai_pentest_bot.audit')
        context = ' | '.join([f"{k}={v}" for k, v in kwargs.items()])
        audit_logger.info(f"{message} | {context}")

    @classmethod
    def get_instance(cls, **kwargs) -> 'Logger':
        """Get or create logger instance (singleton)"""
        if cls._instance is None:
            cls._instance = cls(**kwargs)
        return cls._instance


def get_logger() -> Logger:
    """Get the global logger instance"""
    return Logger.get_instance()
