"""
Модели данных для отчетов
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Any, Optional


@dataclass
class Artifact:
    type: str  # file, process, cron, log, network, socket
    path: Optional[str] = None
    uid: Optional[int] = None
    pid: Optional[int] = None
    size: Optional[int] = None
    modified: Optional[str] = None
    permissions: Optional[str] = None
    command: Optional[str] = None
    protocol: Optional[str] = None
    address: Optional[str] = None
    line: Optional[str] = None
    hashes: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        result = {}
        for key, value in asdict(self).items():
            if value is not None and value != {}:
                result[key] = value
        return result


@dataclass
class SystemUser:
    uid: int
    username: str
    shell: str
    home: str
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ActiveUser:
    uid: int
    username: str
    shell: str
    home: str
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DeletedUser:
    uid: int
    found_in_processes: bool = False
    found_in_files: bool = False
    found_in_cron: bool = False
    artifacts: List[Artifact] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "uid": self.uid,
            "found_in_processes": self.found_in_processes,
            "found_in_files": self.found_in_files,
            "found_in_cron": self.found_in_cron,
            "artifacts": [a.to_dict() for a in self.artifacts]
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
        return asdict(self)


@dataclass
class ReportData:
    investigation_id: str = field(default_factory=lambda: datetime.now().strftime("%Y%m%d_%H%M%S"))
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    tool_version: str = "1.0.0"
    
    system_info: SystemInfo = field(default_factory=SystemInfo)
    
    system_users: List[SystemUser] = field(default_factory=list)
    active_users: List[ActiveUser] = field(default_factory=list)
    deleted_users: List[DeletedUser] = field(default_factory=list)
    
    total_users: int = 0
    system_users_count: int = 0
    active_users_count: int = 0
    deleted_users_count: int = 0
    
    scan_duration: float = 0.0
    
    def __post_init__(self):
        self.system_users_count = len(self.system_users)
        self.active_users_count = len(self.active_users)
        self.deleted_users_count = len(self.deleted_users)
        self.total_users = self.system_users_count + self.active_users_count
    
    def to_dict(self) -> Dict[str, Any]:
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
        report = cls()
        
        if "metadata" in data:
            meta = data["metadata"]
            report.investigation_id = meta.get("investigation_id", report.investigation_id)
            report.timestamp = meta.get("timestamp", report.timestamp)
            report.tool_version = meta.get("tool_version", report.tool_version)
            report.scan_duration = meta.get("scan_duration", report.scan_duration)
        
        if "system_info" in data:
            sys_info = data["system_info"]
            report.system_info = SystemInfo(
                hostname=sys_info.get("hostname", "unknown"),
                os_name=sys_info.get("os_name", "unknown"),
                os_version=sys_info.get("os_version", "unknown"),
                kernel=sys_info.get("kernel", "unknown"),
                architecture=sys_info.get("architecture", "unknown")
            )
            
        if "system_users" in data:
            for u in data["system_users"]:
                report.system_users.append(SystemUser(
                    uid=u.get("uid", 0),
                    username=u.get("username", "unknown"),
                    shell=u.get("shell", "unknown"),
                    home=u.get("home", "unknown")
                ))
        
        if "active_users" in data:
            for u in data["active_users"]:
                report.active_users.append(ActiveUser(
                    uid=u.get("uid", 0),
                    username=u.get("username", "unknown"),
                    shell=u.get("shell", "unknown"),
                    home=u.get("home", "unknown")
                ))
        
        if "deleted_users" in data:
            for user_data in data["deleted_users"]:
                user = DeletedUser(
                    uid=user_data.get("uid", 0),
                    found_in_processes=user_data.get("found_in_processes", False),
                    found_in_files=user_data.get("found_in_files", False),
                    found_in_cron=user_data.get("found_in_cron", False)
                )
                
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
                        protocol=art_data.get("protocol"),
                        address=art_data.get("address"),
                        line=art_data.get("line"),
                        hashes=art_data.get("hashes", {})
                    )
                    user.artifacts.append(artifact)
                
                report.deleted_users.append(user)
        
        report.__post_init__()
        return report