import os
import sys
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

import pwd
import time
import shutil

from forensic.core.settings import get_settings, get_settings_manager


class ColoredFormatter(logging.Formatter):
    COLORS = {
        'RESET': '\033[0m',
        'DEBUG': '\033[36m',
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[35m',
    }
    
    def __init__(self, fmt=None, datefmt=None, use_colors=True):
        super().__init__(fmt, datefmt)
        self.use_colors = use_colors
    
    def format(self, record):
        original_levelname = record.levelname
        if self.use_colors and original_levelname in self.COLORS:
            record.levelname = f"{self.COLORS[original_levelname]}{original_levelname}{self.COLORS['RESET']}"
        result = super().format(record)
        record.levelname = original_levelname
        return result


class SessionLogger:
    LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
    DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
    
    def __init__(self, name: str = "ForensicTool"):
        self.name = name
        self.settings = get_settings()
        self.settings_manager = get_settings_manager()
        
        self.session_id = self._create_session_id()
        self.session_path = self.settings_manager.get_session_path(self.session_id)
        
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, self.settings.log_level))
        self.logger.handlers.clear()
        self._setup_handlers()
    
    def _create_session_id(self) -> str:
        now = datetime.now()
        try:
            username = pwd.getpwuid(os.getuid()).pw_name
        except:
            username = 'unknown'
        return now.strftime(f"%Y%m%d_%H%M%S_{username}")
    
    def _setup_handlers(self):
        try:
            file_formatter = logging.Formatter(fmt=self.LOG_FORMAT, datefmt=self.DATE_FORMAT)
            self._setup_file_handler(file_formatter)
            if self.settings.verbose:
                self._setup_console_handler()
        except Exception as e:
            raise RuntimeError(f"Не удалось настроить логгер: {e}")
    
    def _setup_file_handler(self, file_formatter):
        self.session_path.mkdir(parents=True, exist_ok=True)
        log_file = self.session_path / f"{self.session_id}.log"
        
        max_log_size = self.settings.max_log_size
        if isinstance(max_log_size, str):
            try:
                max_log_size = int(max_log_size)
            except ValueError:
                max_log_size = 10485760
        
        backup_count = self.settings.log_backup_count
        if isinstance(backup_count, str):
            try:
                backup_count = int(backup_count)
            except ValueError:
                backup_count = 5
        
        self.file_handler = RotatingFileHandler(
            filename=str(log_file),
            maxBytes=max_log_size,
            backupCount=backup_count,
            encoding='utf-8'
        )
        self.file_handler.setFormatter(file_formatter)
        self.file_handler.setLevel(getattr(logging, self.settings.log_level))
        self.logger.addHandler(self.file_handler)
    
    def _setup_console_handler(self):
        console_formatter = ColoredFormatter(
            fmt='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S',
            use_colors=True
        )
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(console_formatter)
        console_handler.setLevel(getattr(logging, self.settings.log_level))
        self.logger.addHandler(console_handler)
    
    def _log(self, level: str, message: str, *args, **kwargs):
        try:
            if isinstance(message, str):
                message = message.strip()
            getattr(self.logger, level.lower())(message, *args, **kwargs)
        except Exception as e:
            print(f"Ошибка логирования: {e}", file=sys.stderr)
    
    def debug(self, message, *args, **kwargs): self._log('debug', message, *args, **kwargs)
    def info(self, message, *args, **kwargs): self._log('info', message, *args, **kwargs)
    def warning(self, message, *args, **kwargs): self._log('warning', message, *args, **kwargs)
    def error(self, message, *args, **kwargs): self._log('error', message, *args, **kwargs)
    def critical(self, message, *args, **kwargs): self._log('critical', message, *args, **kwargs)
    
    def exception(self, message, *args, **kwargs):
        if sys.exc_info()[0] is not None:
            self.logger.exception(message, *args, **kwargs)
        else:
            self.logger.error(f"{message} (no active exception)", *args, **kwargs)
    
    def section(self, title: str, level: str = 'info'):
        separator = "=" * 60
        self._log(level, separator)
        self._log(level, f" {title} ".center(58, '='))
        self._log(level, separator)
    
    def get_session_path(self) -> Path:
        return self.session_path
    
    def get_log_file_path(self) -> Optional[Path]:
        if hasattr(self, 'file_handler') and self.file_handler:
            return Path(self.file_handler.baseFilename)
        return None
    
    def cleanup_old_sessions(self) -> int:
        retention_days = self.settings.session_retention_days
        if isinstance(retention_days, str):
            try:
                retention_days = int(retention_days)
            except ValueError:
                retention_days = 5
        
        if retention_days <= 0:
            return 0
        
        session_base_dir = Path(self.settings.session_dir)
        if not session_base_dir.exists():
            return 0
        
        cutoff_time = time.time() - (retention_days * 24 * 60 * 60)
        deleted = 0
        
        for session_path in session_base_dir.iterdir():
            if not session_path.is_dir():
                continue
            try:
                if session_path.stat().st_mtime < cutoff_time:
                    shutil.rmtree(session_path, ignore_errors=True)
                    deleted += 1
                    if self.logger:
                        self.logger.info(f"Удалена сессия: {session_path.name}")
            except Exception:
                pass
        
        if deleted and self.logger:
            self.logger.info(f"Очищено сессий: {deleted}")
        return deleted


_logger_instance = None

def get_logger(name: str = "ForensicTool") -> SessionLogger:
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = SessionLogger(name)
        _logger_instance.cleanup_old_sessions()
    return _logger_instance