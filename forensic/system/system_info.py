import os
import platform
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional


class SystemInfoCollector:
    def __init__(self, logger=None):
        self.logger = logger
        self.info = {}
        self.is_root = os.geteuid() == 0
        self._collect_basic_info()
    
    def _collect_basic_info(self):
        try:
            current_user = os.getenv('USER', 'unknown')
        except:
            current_user = 'unknown'
            
        self.info = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'hostname': platform.node(),
            'kernel': platform.release(),
            'architecture': platform.machine(),
            'is_root': self.is_root,
            'current_user': current_user,
        }
    
    def _check_file_access(self, path: str) -> Optional[str]:
        p = Path(path)
        if not p.exists() or not os.access(path, os.R_OK):
            return None
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return None
    
    def get_os_info(self) -> Dict[str, str]:
        os_info = {'name': 'unknown', 'version': 'unknown'}
        content = self._check_file_access('/etc/os-release')
        if content:
            for line in content.split('\n'):
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    k, v = line.split('=', 1)
                    v = v.strip('"\'')
                    if k == 'PRETTY_NAME':
                        os_info['name'] = v
                    elif k == 'VERSION_ID':
                        os_info['version'] = v
        self.info['os'] = os_info
        return os_info
    
    def collect_all_info(self) -> Dict[str, Any]:
        if self.logger:
            self.logger.info("Сбор информации о системе...")
        self.get_os_info()
        if self.logger:
            self.logger.info("Сбор информации завершен")
        return self.info
    
    def print_summary(self):
        if not self.logger:
            return
        os_info = self.info.get('os', {})
        self.logger.info(f"Хост: {self.info.get('hostname', 'unknown')}")
        self.logger.info(f"ОС: {os_info.get('name', 'unknown')}")
        self.logger.info(f"Ядро: {self.info.get('kernel', 'unknown')}")
        self.logger.info(f"Архитектура: {self.info.get('architecture', 'unknown')}")
        self.logger.info(f"Пользователь: {self.info.get('current_user', 'unknown')}")
        self.logger.info(f"Root права: {'Да' if self.info.get('is_root') else 'Нет'}")