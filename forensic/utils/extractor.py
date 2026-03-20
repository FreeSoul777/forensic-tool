import json
import shutil
import zipfile
from pathlib import Path
from datetime import datetime
from typing import List, Set
from forensic.report.models import ReportData


class ArtifactExtractor:
    def __init__(self, logger=None):
        self.logger = logger
        self.source_report = None
        self.dest_dir = None
        self.parsed_time = None
        self._used_paths: Set[str] = set()
    
    def _get_unique_zip_path(self, src_path: Path) -> str:
        if str(src_path).startswith('/'):
            zip_path = str(src_path)[1:]
        else:
            zip_path = str(src_path)
        
        if zip_path not in self._used_paths:
            self._used_paths.add(zip_path)
            return zip_path
        
        parts = zip_path.split('/')
        name = parts[-1]
        dir_path = '/'.join(parts[:-1]) if len(parts) > 1 else ''
        
        counter = 1
        while True:
            new_name = f"{name}_{counter}"
            if dir_path:
                new_path = f"{dir_path}/{new_name}"
            else:
                new_path = new_name
            
            if new_path not in self._used_paths:
                self._used_paths.add(new_path)
                return new_path
            counter += 1
    
    def parse_report(self, report_path: Path, dest_dir: Path) -> bool:
        self.source_report = report_path
        self.dest_dir = dest_dir
        self.parsed_time = datetime.now()
        
        if self.logger:
            self.logger.info(f"Распарсивание: {report_path}")
        
        try:
            with open(report_path) as f:
                report_data = ReportData.from_dict(json.load(f))
        except Exception as e:
            if self.logger:
                self.logger.error(f"Ошибка загрузки: {e}")
            return False
        
        if not report_data.deleted_users:
            if self.logger:
                self.logger.warning("Нет удаленных пользователей")
            return False
        
        dest_dir.mkdir(parents=True, exist_ok=True)
        
        processed = 0
        for user in report_data.deleted_users:
            if self._process_user(report_data, user, dest_dir):
                processed += 1
        
        if self.logger:
            self.logger.info(f"Готово: {dest_dir} ({processed} пользователей)")
        return processed > 0
    
    def _process_user(self, report_data: ReportData, user, base_dir: Path) -> bool:
        user_dir = base_dir / f"uid_{user.uid}"
        user_dir.mkdir(exist_ok=True)
        
        self._used_paths.clear()
        
        temp_dir = user_dir / "_temp_files"
        temp_dir.mkdir(exist_ok=True)
        
        copied = []
        user_dict = user.to_dict()
        user_dict.update({
            "investigation_id": report_data.investigation_id,
            "source_report": str(self.source_report.absolute()),
            "parsed_at": self.parsed_time.isoformat(),
            "system_info": report_data.system_info.to_dict()
        })
        
        file_cnt = 0
        for art in user_dict.get("artifacts", []):
            if art.get("type") == "file" and art.get("path"):
                src = Path(art["path"])
                if src.exists() and src.is_file():
                    zip_path = self._get_unique_zip_path(src)
                    dst = temp_dir / Path(zip_path).name
                    
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    
                    try:
                        shutil.copy2(src, dst)
                        copied.append((dst, zip_path))
                        art["copied_to"] = f"artifacts.zip/{zip_path}"
                        file_cnt += 1
                        if self.logger:
                            self.logger.debug(f"  {zip_path}")
                    except Exception as e:
                        art["copy_error"] = str(e)
                else:
                    art["copy_error"] = "File does not exist or is not a file"
        
        with open(user_dir / "personal_report.json", 'w') as f:
            json.dump(user_dict, f, indent=2)
        
        if copied:
            zip_path = user_dir / "artifacts.zip"
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as z:
                for local_file, arcname in copied:
                    z.write(local_file, arcname)
            
            size_kb = zip_path.stat().st_size / 1024
            if self.logger:
                self.logger.info(f"  UID {user.uid}: {file_cnt} файлов ({size_kb:.1f} KB)")
            
            shutil.rmtree(temp_dir)
        elif temp_dir.exists():
            shutil.rmtree(temp_dir)
            if self.logger:
                self.logger.info(f"  UID {user.uid}: файлов не найдено")
        
        return True