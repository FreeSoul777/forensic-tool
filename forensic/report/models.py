"""
Модели данных для отчетов
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
from enum import Enum


class ArtifactType(str, Enum):
    """Типы артефактов"""
    FILE = "file"
    PROCESS = "process"
    CRON = "cron"
    TIMER = "timer"
    NETWORK = "network"
    LOG = "log"
    UNKNOWN = "unknown"


@dataclass
class SystemUser:
    """Системный пользователь (из /etc/passwd)"""
    uid: int
    username: str
    shell: str = ""
    home: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        return {
            "uid": self.uid,
            "username": self.username,
            "shell": self.shell,
            "home": self.home
        }


@dataclass
class ActiveUser:
    """Активный пользователь (из /etc/passwd, UID >= 1000)"""
    uid: int
    username: str
    shell: str = ""
    home: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        return {
            "uid": self.uid,
            "username": self.username,
            "shell": self.shell,
            "home": self.home
        }


@dataclass
class Artifact:
    """Артефакт (файл, процесс, cron задача)"""
    type: str  # file, process, cron, timer, network, log, history
    path: Optional[str] = None
    uid: Optional[int] = None
    pid: Optional[int] = None
    size: Optional[int] = None
    modified: Optional[str] = None
    permissions: Optional[str] = None
    command: Optional[str] = None
    description: Optional[str] = None
    hashes: Optional[Dict[str, str]] = None
    
    # Для network артефактов
    protocol: Optional[str] = None
    address: Optional[str] = None
    
    # Для log артефактов
    line: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        result = {}
        for key, value in asdict(self).items():
            if value is not None:
                result[key] = value
        return result


@dataclass
class DeletedUser:
    """Информация об удаленном пользователе"""
    uid: int
    found_in_processes: bool = False
    found_in_files: bool = False
    found_in_cron: bool = False
    artifacts: List[Artifact] = field(default_factory=list)
    possible_username: Optional[str] = None
    home_directory: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        return {
            "uid": self.uid,
            "found_in_processes": self.found_in_processes,
            "found_in_files": self.found_in_files,
            "found_in_cron": self.found_in_cron,
            "artifacts": [a.to_dict() for a in self.artifacts],
            "possible_username": self.possible_username,
            "home_directory": self.home_directory
        }


@dataclass
class SystemInfo:
    """Системная информация"""
    hostname: str = "unknown"
    os_name: str = "unknown"
    os_version: str = "unknown"
    kernel: str = "unknown"
    architecture: str = "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        return {
            "hostname": self.hostname,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "kernel": self.kernel,
            "architecture": self.architecture
        }


@dataclass
class ReportData:
    """Основные данные отчета"""
    
    # Метаданные
    investigation_id: str = field(default_factory=lambda: datetime.now().strftime("%Y%m%d_%H%M%S"))
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    tool_version: str = "1.0.0"
    
    # Системная информация
    system_info: SystemInfo = field(default_factory=SystemInfo)
    
    # Пользователи
    system_users: List[SystemUser] = field(default_factory=list)  # UID < 1000 (кроме root)
    active_users: List[ActiveUser] = field(default_factory=list)  # UID >= 1000
    deleted_users: List[DeletedUser] = field(default_factory=list)
    
    # Статистика
    total_users: int = 0
    active_users_count: int = 0
    system_users_count: int = 0
    deleted_users_count: int = 0
    
    # Метод сканирования
    scan_duration: float = 0.0
    
    def __post_init__(self):
        """Автоматически обновляем счетчики"""
        self.system_users_count = len(self.system_users)
        self.active_users_count = len(self.active_users)
        self.deleted_users_count = len(self.deleted_users)
        self.total_users = self.system_users_count + self.active_users_count + self.deleted_users_count
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        # Обновляем счетчики
        self.__post_init__()
        
        return {
            "metadata": {
                "investigation_id": self.investigation_id,
                "timestamp": self.timestamp,
                "tool_version": self.tool_version,
                "scan_duration": self.scan_duration
            },
            "system_info": self.system_info.to_dict(),
            "statistics": {
                "total_users": self.total_users,
                "system_users": self.system_users_count,
                "active_users": self.active_users_count,
                "deleted_users": self.deleted_users_count
            },
            "system_users": [u.to_dict() for u in self.system_users],
            "active_users": [u.to_dict() for u in self.active_users],
            "deleted_users": [u.to_dict() for u in self.deleted_users]
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReportData':
        """Создание из словаря"""
        report = cls()
        
        # Метаданные
        if "metadata" in data:
            meta = data["metadata"]
            report.investigation_id = meta.get("investigation_id", report.investigation_id)
            report.timestamp = meta.get("timestamp", report.timestamp)
            report.tool_version = meta.get("tool_version", report.tool_version)
            report.scan_duration = meta.get("scan_duration", report.scan_duration)
        elif "investigation_id" in data:  # Старый формат
            report.investigation_id = data.get("investigation_id", report.investigation_id)
            report.timestamp = data.get("timestamp", report.timestamp)
            report.tool_version = data.get("tool_version", report.tool_version)
            report.scan_duration = data.get("scan_duration", report.scan_duration)
        
        # Системная информация - берем только нужные поля
        if "system_info" in data:
            sys_info = data["system_info"]
            report.system_info = SystemInfo(
                hostname=sys_info.get("hostname", "unknown"),
                os_name=sys_info.get("os_name", "unknown"),
                os_version=sys_info.get("os_version", "unknown"),
                kernel=sys_info.get("kernel", "unknown"),
                architecture=sys_info.get("architecture", "unknown")
            )
        elif "hostname" in data:  # Старый формат
            report.system_info = SystemInfo(
                hostname=data.get("hostname", "unknown"),
                os_name=data.get("os_name", "unknown"),
                os_version=data.get("os_version", "unknown"),
                kernel=data.get("kernel", "unknown"),
                architecture=data.get("architecture", "unknown")
            )
        
        # Статистика
        if "statistics" in data:
            stats = data["statistics"]
            report.total_users = stats.get("total_users", 0)
            report.active_users_count = stats.get("active_users", 0)
            report.system_users_count = stats.get("system_users", 0)
            report.deleted_users_count = stats.get("deleted_users", 0)
        else:
            # Для обратной совместимости
            report.total_users = data.get("total_users", 0)
            report.active_users_count = data.get("active_users", 0)
            report.system_users_count = data.get("system_users", 0)
            report.deleted_users_count = data.get("deleted_users", 0)
        
        # Системные пользователи
        if "system_users" in data:
            for user_data in data["system_users"]:
                report.system_users.append(SystemUser(
                    uid=user_data.get("uid", 0),
                    username=user_data.get("username", ""),
                    shell=user_data.get("shell", ""),
                    home=user_data.get("home", "")
                ))
        
        # Активные пользователи
        if "active_users" in data:
            for user_data in data["active_users"]:
                report.active_users.append(ActiveUser(
                    uid=user_data.get("uid", 0),
                    username=user_data.get("username", ""),
                    shell=user_data.get("shell", ""),
                    home=user_data.get("home", "")
                ))
        
        # Удаленные пользователи
        if "deleted_users" in data:
            for user_data in data["deleted_users"]:
                user = DeletedUser(
                    uid=user_data.get("uid", 0),
                    found_in_processes=user_data.get("found_in_processes", False),
                    found_in_files=user_data.get("found_in_files", False),
                    found_in_cron=user_data.get("found_in_cron", False),
                    possible_username=user_data.get("possible_username"),
                    home_directory=user_data.get("home_directory")
                )
                
                # Артефакты
                for art_data in user_data.get("artifacts", []):
                    artifact = Artifact(
                        type=art_data.get("type", "unknown"),
                        path=art_data.get("path"),
                        uid=art_data.get("uid"),
                        pid=art_data.get("pid"),
                        size=art_data.get("size"),
                        modified=art_data.get("modified"),
                        permissions=art_data.get("permissions"),
                        command=art_data.get("command"),
                        description=art_data.get("description")
                    )
                    user.artifacts.append(artifact)
                
                report.deleted_users.append(user)
        
        # Обновляем счетчики
        report.__post_init__()
        
        return report
