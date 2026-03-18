import subprocess
import json
import os
import time
import select
import fcntl
import re
from pathlib import Path
from datetime import datetime

from forensic.report.models import ReportData, DeletedUser, Artifact, ArtifactType


class BashScanner:
    def __init__(self, logger=None):
        self.logger = logger
        self.results = {'users': {'system': [], 'active': []}, 'deleted_users': {}}
        self.scan_start_time = None
        
    def scan(self) -> ReportData:
        if self.logger:
            self.logger.info("🚀 Запуск сканирования...")
        
        self.scan_start_time = time.time()
        script_path = Path(__file__).parent / "find_user_artifacts.sh"
        
        if not script_path.exists():
            raise RuntimeError(f"Bash-скрипт не найден: {script_path}")
        
        try:
            proc = subprocess.Popen(
                ["bash", str(script_path)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1, env=os.environ.copy()
            )
            self._process_output(proc)
            proc.wait()
            return self._generate_report()
        except Exception as e:
            if self.logger:
                self.logger.error(f"Ошибка: {e}")
            raise
    
    def _process_output(self, proc):
        for fd in [proc.stdout.fileno(), proc.stderr.fileno()]:
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        
        while True:
            if proc.poll() is not None:
                for line in proc.stdout: self._handle_stdout(line.strip())
                for line in proc.stderr: self._handle_stderr(line.strip())
                break
            
            rlist, _, _ = select.select([proc.stdout, proc.stderr], [], [], 0.1)
            for fd in rlist:
                if fd == proc.stdout:
                    line = proc.stdout.readline()
                    if line: self._handle_stdout(line.strip())
                elif fd == proc.stderr:
                    line = proc.stderr.readline()
                    if line: self._handle_stderr(line.strip())
            time.sleep(0.01)
    
    def _handle_stdout(self, line: str):
        if not line:
            return
        if line.startswith('PROGRESS:'):
            self._handle_progress(line)
            return
        if not line.startswith('{'):
            return
        
        try:
            ev = json.loads(line)
            t = ev.get('event')
            uid = ev.get('uid')
            
            if t == 'users':
                self.results['users']['system'] = ev.get('system', [])
                self.results['users']['active'] = ev.get('active', [])
            elif t in ['ports', 'sockets', 'processes', 'services', 'cron', 'timers', 'logs', 'history']:
                if uid:
                    self.results['deleted_users'].setdefault(uid, {'uid': uid}).setdefault(t, []).append(ev.get('data', ''))
            elif t == 'files':
                if uid:
                    self.results['deleted_users'].setdefault(uid, {'uid': uid}).setdefault('files', []).append({
                        'count': ev.get('count', 0), 'data': ev.get('data', '')
                    })
            elif t == 'scan_complete':
                self.results['duration'] = ev.get('duration', 0)
                self.results['deleted_uids'] = ev.get('deleted_users', [])
                self.results['deleted_count'] = ev.get('deleted_count', 0)
        except json.JSONDecodeError:
            if self.logger:
                self.logger.debug(f"JSON err: {line[:100]}")
    
    def _handle_progress(self, line: str):
        try:
            parts = line.replace('PROGRESS:', '').split('/')
            if len(parts) == 3:
                cur, tot, found = map(int, parts)
                pct = (cur * 100) // tot if tot else 0
                print(f"\r    Прогресс: {cur}/{tot} ({pct}%) | Найдено: {found}", end='', flush=True)
                if cur == tot:
                    print()
        except: pass
    
    def _handle_stderr(self, line: str):
        if not line:
            return
        if line.startswith('[INFO]'):
            clean = line.replace('[INFO]', '').strip()
            print(f"  {clean}")
            if self.logger: self.logger.info(clean)
        elif line.startswith('[ERROR]'):
            clean = line.replace('[ERROR]', '').strip()
            print(f"  ⚠ {clean}")
            if self.logger: self.logger.error(clean)
        elif line.startswith('[DEBUG]') and self.logger:
            self.logger.debug(line.replace('[DEBUG]', '').strip())
        else:
            print(f"  {line}")
            if self.logger: self.logger.info(line)
    
    def _generate_report(self) -> ReportData:
        report = ReportData()
        report.timestamp = datetime.now().isoformat()
        report.scan_duration = time.time() - self.scan_start_time
        
        for u in self.results['users']['system']:
            from forensic.report.models import SystemUser
            report.system_users.append(SystemUser(**u))
        for u in self.results['users']['active']:
            from forensic.report.models import ActiveUser
            report.active_users.append(ActiveUser(**u))
        
        for uid_str, data in self.results['deleted_users'].items():
            uid = int(uid_str)
            user = DeletedUser(uid=uid)
            
            if 'processes' in data: user.found_in_processes = True
            if 'files' in data: user.found_in_files = True
            if 'cron' in data: user.found_in_cron = True
            
            # Процессы
            for p in data.get('processes', []):
                parts = p.strip().split(None, 4)
                if len(parts) >= 5:
                    try:
                        user.artifacts.append(Artifact(type="process", pid=int(parts[1]), command=parts[4]))
                    except: pass
            
            # Сеть
            for p in data.get('ports', []):
                parts = p.strip().split()
                if len(parts) >= 5:
                    pid = None
                    if m := re.search(r'pid=(\d+)', p):
                        pid = int(m.group(1))
                    user.artifacts.append(Artifact(
                        type="network", protocol=parts[0], address=parts[4], pid=pid,
                        path=f"{parts[0]}:{parts[4]}"
                    ))
            
            # Сокеты
            for s in data.get('sockets', []):
                user.artifacts.append(Artifact(type="socket", path=s.strip()))
            
            # Cron
            for c in data.get('cron', []):
                lines = c.strip().split('\n')
                if lines:
                    path = lines[0].replace('===', '').strip()
                    for cmd in lines[1:]:
                        if cmd.strip():
                            user.artifacts.append(Artifact(type="cron", path=path, command=cmd.strip()))
            
            # Файлы с хэшами
            if 'files' in data:
                for f in data.get('files', []):
                    if isinstance(f, dict):
                        if f.get('path'):  # Проверяем что путь существует
                            user.artifacts.append(Artifact(
                                type="file", path=f.get('path'), size=f.get('size'),
                                permissions=f.get('permissions'), modified=str(f.get('mtime', '')),
                                hashes=f.get('hashes', {})
                            ))
                    else:
                        try:
                            fd = json.loads(f)
                            if fd.get('path'):  # Проверяем что путь существует
                                user.artifacts.append(Artifact(
                                    type="file", path=fd.get('path'), size=fd.get('size'),
                                    permissions=fd.get('permissions'), modified=str(fd.get('mtime', '')),
                                    hashes=fd.get('hashes', {})
                                ))
                        except:
                            if f and f.strip():  # Проверяем что строка не пустая
                                user.artifacts.append(Artifact(type="file", path=str(f)))
            
            # Логи
            for log in data.get('logs', []):
                if ']' in log:
                    parts = log.split(']', 1)
                    user.artifacts.append(Artifact(type="log", path=parts[0].strip('['), line=parts[1].strip()))
                else:
                    user.artifacts.append(Artifact(type="log", line=log))
            
            # История
            for h in data.get('history', []):
                lines = h.strip().split('\n')
                if lines:
                    header = lines[0].replace('===', '').strip()
                    for cmd in lines[1:]:
                        if cmd.strip():
                            cmd = cmd.strip().lstrip()
                            user.artifacts.append(Artifact(type="history", path=header, command=cmd))
            
            report.deleted_users.append(user)
        
        report.__post_init__()
        if self.logger:
            self.logger.info(f"Найдено удаленных: {report.deleted_users_count}")
        return report