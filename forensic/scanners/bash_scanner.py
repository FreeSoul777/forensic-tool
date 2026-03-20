import subprocess
import json
import os
import time
import select
import sys
import fcntl
import re
from pathlib import Path
from datetime import datetime

from forensic.report.models import ReportData, DeletedUser, Artifact, SystemUser, ActiveUser, SystemInfo


class BashScanner:
    def __init__(self, logger=None):
        self.logger = logger
        self.results = {
            'system_users': [],
            'active_users': [],
            'deleted_users': {}
        }
        self.scan_start_time = None
        self._progress_line = ""
        
    def scan(self) -> ReportData:
        if self.logger:
            self.logger.info("Запуск сканирования...")
        
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
                for line in proc.stdout:
                    self._handle_stdout(line.strip())
                for line in proc.stderr:
                    self._handle_stderr(line.strip())
                break
            
            rlist, _, _ = select.select([proc.stdout, proc.stderr], [], [], 0.1)
            for fd in rlist:
                if fd == proc.stdout:
                    line = proc.stdout.readline()
                    if line:
                        self._handle_stdout(line.strip())
                elif fd == proc.stderr:
                    line = proc.stderr.readline()
                    if line:
                        self._handle_stderr(line.strip())
            time.sleep(0.01)
        
        if self._progress_line:
            sys.stderr.write("\n")
            sys.stderr.flush()
    
    def _handle_stdout(self, line: str):
        if not line:
            return
        
        if line.startswith('PROGRESS:'):
            self._handle_progress(line)
            return
        
        if line.startswith('{'):
            try:
                ev = json.loads(line)
                t = ev.get('event')
                uid = ev.get('uid')
                
                if t == 'users':
                    for u in ev.get('system', []):
                        self.results['system_users'].append({
                            'uid': u.get('uid'),
                            'username': u.get('username'),
                            'shell': u.get('shell'),
                            'home': u.get('home')
                        })
                    for u in ev.get('active', []):
                        self.results['active_users'].append({
                            'uid': u.get('uid'),
                            'username': u.get('username'),
                            'shell': u.get('shell'),
                            'home': u.get('home')
                        })
                elif t == 'files':
                    if uid:
                        self.results['deleted_users'].setdefault(uid, {'uid': uid})
                        self.results['deleted_users'][uid]['files'] = ev.get('files', [])
                elif t in ['ports', 'sockets', 'processes', 'services', 'cron', 'timers', 'logs', 'history']:
                    if uid:
                        self.results['deleted_users'].setdefault(uid, {'uid': uid})
                        self.results['deleted_users'][uid].setdefault(t, []).append(ev.get('data', ''))
                elif t == 'scan_complete':
                    self.results['duration'] = ev.get('duration', 0)
                    self.results['deleted_uids'] = ev.get('deleted_users', [])
                    self.results['deleted_count'] = ev.get('deleted_count', 0)
            except json.JSONDecodeError:
                pass

    def _handle_progress(self, line: str):
        try:
            parts = line.replace('PROGRESS:', '').split(':')
            if len(parts) == 3:
                current = int(parts[0])
                total = int(parts[1])
                found = int(parts[2])
                
                if total > 0:
                    percent = (current * 100) // total
                    progress = f"    Прогресс: {current}/{total} ({percent}%) | Найдено: {found}"
                    
                    if self._progress_line:
                        sys.stderr.write("\r" + " " * len(self._progress_line) + "\r")
                    
                    sys.stderr.write(progress)
                    sys.stderr.flush()
                    self._progress_line = progress
                    
                    if current == total:
                        sys.stderr.write("\n")
                        sys.stderr.flush()
                        self._progress_line = ""
        except Exception:
            pass

    def _handle_stderr(self, line: str):
        if not line:
            return
        
        if line.startswith('PROGRESS:'):
            return
        
        if self._progress_line:
            sys.stderr.write("\r" + " " * len(self._progress_line) + "\r")
            self._progress_line = ""
        
        if line.startswith('[INFO]'):
            clean = line.replace('[INFO]', '').strip()
            if clean:
                print(f"  {clean}")
                if self.logger:
                    self.logger.info(clean)
        elif line.startswith('[ERROR]'):
            clean = line.replace('[ERROR]', '').strip()
            if clean:
                print(f"  {clean}")
                if self.logger:
                    self.logger.error(clean)
        elif line.startswith('[DEBUG]'):
            if self.logger:
                self.logger.debug(line.replace('[DEBUG]', '').strip())
        else:
            if line.strip():
                print(f"  {line}")
                if self.logger:
                    self.logger.info(line)
    
    def _generate_report(self) -> ReportData:
        report = ReportData()
        report.timestamp = datetime.now().isoformat()
        report.scan_duration = time.time() - self.scan_start_time
        
        for u in self.results['system_users']:
            report.system_users.append(SystemUser(
                uid=u['uid'],
                username=u['username'],
                shell=u['shell'],
                home=u['home']
            ))
        
        for u in self.results['active_users']:
            report.active_users.append(ActiveUser(
                uid=u['uid'],
                username=u['username'],
                shell=u['shell'],
                home=u['home']
            ))
        
        for uid_str, data in self.results['deleted_users'].items():
            uid = int(uid_str)
            user = DeletedUser(uid=uid)
            
            if 'processes' in data:
                user.found_in_processes = True
            if 'files' in data:
                user.found_in_files = True
            if 'cron' in data:
                user.found_in_cron = True
            
            for p in data.get('processes', []):
                parts = p.strip().split(None, 4)
                if len(parts) >= 5:
                    try:
                        user.artifacts.append(Artifact(
                            type="process",
                            pid=int(parts[1]),
                            command=parts[4]
                        ))
                    except:
                        pass
            
            if 'files' in data:
                for f in data['files']:
                    if isinstance(f, dict):
                        if f.get('path'):
                            user.artifacts.append(Artifact(
                                type="file",
                                path=f.get('path'),
                                size=f.get('size'),
                                permissions=f.get('permissions'),
                                modified=datetime.fromtimestamp(f['mtime']).strftime('%Y-%m-%d %H:%M:%S'),
                                hashes=f.get('hashes', {})
                            ))
                    else:
                        try:
                            fd = json.loads(f)
                            if fd.get('path'):
                                user.artifacts.append(Artifact(
                                    type="file",
                                    path=fd.get('path'),
                                    size=fd.get('size'),
                                    permissions=fd.get('permissions'),
                                    modified=datetime.fromtimestamp(fd['mtime']).strftime('%Y-%m-%d %H:%M:%S'),
                                    hashes=fd.get('hashes', {})
                                ))
                        except:
                            if f and f.strip():
                                user.artifacts.append(Artifact(
                                    type="file",
                                    path=str(f)
                                ))
            
            for c in data.get('cron', []):
                lines = c.strip().split('\n')
                if lines:
                    path = lines[0].replace('===', '').strip()
                    for cmd in lines[1:]:
                        if cmd.strip():
                            user.artifacts.append(Artifact(
                                type="cron",
                                path=path,
                                command=cmd.strip()
                            ))
            
            for log in data.get('logs', []):
                if ']' in log:
                    parts = log.split(']', 1)
                    user.artifacts.append(Artifact(
                        type="log",
                        path=parts[0].strip('['),
                        line=parts[1].strip()
                    ))
                else:
                    user.artifacts.append(Artifact(
                        type="log",
                        line=log
                    ))
            
            for h in data.get('history', []):
                lines = h.strip().split('\n')
                if lines:
                    header = lines[0].replace('===', '').strip()
                    for cmd in lines[1:]:
                        if cmd.strip():
                            user.artifacts.append(Artifact(
                                type="history",
                                path=header,
                                command=cmd.strip().lstrip()
                            ))
            
            report.deleted_users.append(user)
        
        report.__post_init__()
        
        if self.logger:
            self.logger.info(f"Найдено удаленных: {report.deleted_users_count}")
            self.logger.info(f"Системных пользователей: {report.system_users_count}")
            self.logger.info(f"Активных пользователей: {report.active_users_count}")
        
        return report