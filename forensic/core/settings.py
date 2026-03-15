import os
import configparser
from pathlib import Path
from typing import Optional
from dataclasses import dataclass


@dataclass
class ForensicSettings:
    log_level: str = "INFO"
    verbose: bool = False
    session_dir: str = "/var/log/forensic"
    max_log_size: int = 10485760
    log_backup_count: int = 5
    session_retention_days: int = 5
    
    def __post_init__(self):
        self.session_dir = os.path.expanduser(self.session_dir)
        for attr in ['max_log_size', 'log_backup_count', 'session_retention_days']:
            val = getattr(self, attr)
            if isinstance(val, str):
                try:
                    setattr(self, attr, int(val))
                except ValueError:
                    setattr(self, attr, 10485760 if attr == 'max_log_size' else 5)


class SettingsManager:
    CONFIG_PATHS = [
        Path("/etc/forensic/forensic.conf"),
        Path.home() / ".config" / "forensic" / "forensic.conf",
        Path.cwd() / "config" / "forensic.conf",
        Path.cwd() / "forensic.conf",
    ]
    
    def __init__(self):
        self.settings = ForensicSettings()
        self.config_path = None
        self._load_settings()
    
    def _load_settings(self):
        for config_path in self.CONFIG_PATHS:
            if config_path.exists():
                try:
                    self._parse_config(config_path)
                    self.config_path = config_path
                    print(f"✓ Загружен конфиг: {config_path}")
                    return
                except Exception as e:
                    print(f"Ошибка загрузки {config_path}: {e}")
        
        try:
            etc_config = Path("/etc/forensic/forensic.conf")
            self._create_default_config(etc_config)
            self._parse_config(etc_config)
            self.config_path = etc_config
        except PermissionError:
            home_config = Path.home() / ".config" / "forensic" / "forensic.conf"
            self._create_default_config(home_config)
            self._parse_config(home_config)
            self.config_path = home_config
    
    def _create_default_config(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        config = configparser.ConfigParser()
        config['forensic'] = {
            'log_level': 'INFO',
            'verbose': 'false',
            'session_dir': '/var/log/forensic',
            'max_log_size': '10485760',
            'log_backup_count': '5',
            'session_retention_days': '5',
        }
        with open(path, 'w') as f:
            config.write(f)
        print(f"✓ Создан конфиг: {path}")
    
    def _parse_config(self, config_path: Path):
        config = configparser.ConfigParser()
        config.read(config_path)
        
        if 'forensic' in config:
            section = config['forensic']
            if 'log_level' in section:
                self.settings.log_level = section['log_level'].upper()
            if 'verbose' in section:
                self.settings.verbose = section.getboolean('verbose')
            if 'session_dir' in section:
                self.settings.session_dir = section['session_dir']
            if 'max_log_size' in section:
                self.settings.max_log_size = section['max_log_size']
            if 'log_backup_count' in section:
                self.settings.log_backup_count = section['log_backup_count']
            if 'session_retention_days' in section:
                self.settings.session_retention_days = section['session_retention_days']
    
    def get(self) -> ForensicSettings:
        return self.settings
    
    def get_config_path(self) -> Optional[Path]:
        return self.config_path
    
    def get_session_path(self, session_id: str) -> Path:
        path = Path(self.settings.session_dir) / session_id
        path.mkdir(parents=True, exist_ok=True)
        return path


_settings_manager = None

def get_settings() -> ForensicSettings:
    global _settings_manager
    if _settings_manager is None:
        _settings_manager = SettingsManager()
    return _settings_manager.get()

def get_settings_manager() -> SettingsManager:
    global _settings_manager
    if _settings_manager is None:
        _settings_manager = SettingsManager()
    return _settings_manager