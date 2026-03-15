import json
import shutil
import zipfile
from pathlib import Path
from datetime import datetime
from typing import List

from forensic.utils.hasher import FileHasher
from forensic.report.models import ReportData


class ArtifactExtractor:
    def __init__(self, logger=None):
        self.logger = logger
        self.source_report = None
        self.dest_dir = None
        self.parsed_time = None
    
    def parse_report(self, report_path: Path, dest_dir: Path) -> bool:
        self.source_report = report_path
        self.dest_dir = dest_dir
        self.parsed_time = datetime.now()
        
        if self.logger:
            self.logger.info(f"📦 Распарсивание: {report_path}")
        
        try:
            with open(report_path) as f:
                report_data = ReportData.from_dict(json.load(f))
        except Exception as e:
            if self.logger: self.logger.error(f"Ошибка загрузки: {e}")
            return False
        
        if not report_data.deleted_users:
            if self.logger: self.logger.warning("Нет удаленных пользователей")
            return False
        
        dest_dir.mkdir(parents=True, exist_ok=True)
        
        processed = 0
        for user in report_data.deleted_users:
            if self._process_user(report_data, user, dest_dir):
                processed += 1
        
        if self.logger:
            self.logger.info(f"✅ Готово: {dest_dir} ({processed} пользователей)")
        return processed > 0
    
    def _process_user(self, report_data: ReportData, user, base_dir: Path) -> bool:
        user_dir = base_dir / f"uid_{user.uid}"
        user_dir.mkdir(exist_ok=True)
        
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
                if src.exists():
                    dst = temp_dir / src.name
                    try:
                        shutil.copy2(src, dst)
                        copied.append(dst)
                        art["copied_to"] = f"artifacts.zip/{src.name}"
                        file_cnt += 1
                        if self.logger:
                            self.logger.debug(f"  📄 {src.name}")
                    except Exception as e:
                        art["copy_error"] = str(e)
                else:
                    art["copy_error"] = "File does not exist"
        
        with open(user_dir / "personal_report.json", 'w') as f:
            json.dump(user_dict, f, indent=2)
        
        if copied:
            with zipfile.ZipFile(user_dir / "artifacts.zip", 'w', zipfile.ZIP_DEFLATED) as z:
                for f in copied:
                    z.write(f, f.name)
            shutil.rmtree(temp_dir)
        elif temp_dir.exists():
            shutil.rmtree(temp_dir)
        
        if self.logger:
            self.logger.info(f"  👤 UID {user.uid}: {file_cnt} файлов")
        return True