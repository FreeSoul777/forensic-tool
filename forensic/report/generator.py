import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List, Union

from forensic.report.models import ReportData
from forensic.report.templates.html_template import (
    HTML_TEMPLATE, generate_user_card,
    generate_system_user_card, generate_active_user_card
)

try:
    from fpdf import FPDF
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False
    logging.warning("PDF недоступен, установите: pip install fpdf2")

logger = logging.getLogger(__name__)


class PDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        for style, path in [("regular", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
                            ("bold", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")]:
            if Path(path).exists():
                self.add_font("DejaVu", "B" if style == "bold" else "", path, uni=True)
        self.set_font("DejaVu", size=10)
    
    def header(self):
        self.set_font('DejaVu', 'B', 14)
        self.set_text_color(44, 62, 80)
        self.cell(0, 10, 'Forensic Investigation Report', ln=True, align='C')
        self.ln(5)
    
    def footer(self):
        self.set_y(-15)
        self.set_font('DejaVu', '', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Стр. {self.page_no()}', align='C')
    
    def section_title(self, title):
        self.set_font('DejaVu', 'B', 12)
        self.set_text_color(52, 73, 94)
        self.cell(0, 10, title, ln=True)
        self.ln(4)


class ReportGenerator:
    FORMATS = ['json', 'html']
    if PDF_SUPPORT:
        FORMATS.append('pdf')
    
    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or Path.cwd()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.data: Optional[ReportData] = None
    
    def load_data(self, data: Union[ReportData, Dict[str, Any], Path]) -> bool:
        try:
            if isinstance(data, ReportData):
                self.data = data
            elif isinstance(data, dict):
                self.data = ReportData.from_dict(data)
            elif isinstance(data, (Path, str)):
                with open(Path(data)) as f:
                    self.data = ReportData.from_dict(json.load(f))
            return True
        except Exception as e:
            logger.error(f"Ошибка загрузки: {e}")
            return False
    
    def generate_json(self, output_file: Optional[Path] = None) -> Optional[Path]:
        if not self.data:
            return None
        out = output_file or self.output_dir / f"report_{self.data.investigation_id}.json"
        with open(out, 'w') as f:
            json.dump(self.data.to_dict(), f, indent=2, default=str)
        logger.info(f"JSON: {out}")
        return out
    
    def generate_html(self, output_file: Optional[Path] = None) -> Optional[Path]:
        if not self.data:
            return None
        out = output_file or self.output_dir / f"report_{self.data.investigation_id}.html"
        d = self.data.to_dict()
        meta, sys_info, stats = d.get('metadata', {}), d.get('system_info', {}), d.get('statistics', {})
        
        total_artifacts = 0
        user_cards = sys_cards = act_cards = ""
        for u in d.get('deleted_users', []):
            total_artifacts += len(u.get('artifacts', []))
            user_cards += generate_user_card(u)
        for u in d.get('system_users', []):
            sys_cards += generate_system_user_card(u)
        for u in d.get('active_users', []):
            act_cards += generate_active_user_card(u)
        
        html = HTML_TEMPLATE.format(
            investigation_id=meta.get('investigation_id', 'unknown'),
            timestamp=meta.get('timestamp', 'unknown'),
            tool_version=meta.get('tool_version', '1.0.0'),
            scan_duration=meta.get('scan_duration', 0.0),
            total_users=stats.get('total_users', 0),
            active_users=stats.get('active_users', 0),
            deleted_users=stats.get('deleted_users', 0),
            system_users_count=stats.get('system_users', 0),
            active_users_count=stats.get('active_users', 0),
            total_artifacts=total_artifacts,
            hostname=sys_info.get('hostname', 'unknown'),
            os_name=sys_info.get('os_name', 'unknown'),
            os_version=sys_info.get('os_version', 'unknown'),
            kernel=sys_info.get('kernel', 'unknown'),
            architecture=sys_info.get('architecture', 'unknown'),
            system_user_cards=sys_cards,
            active_user_cards=act_cards,
            user_cards=user_cards
        )
        out.write_text(html, encoding='utf-8')
        logger.info(f"HTML: {out}")
        return out
    
    def generate_pdf(self, output_file: Optional[Path] = None) -> Optional[Path]:
        if not PDF_SUPPORT or not self.data:
            return None
        out = output_file or self.output_dir / f"report_{self.data.investigation_id}.pdf"
        pdf = PDF()
        pdf.add_page()
        
        pdf.set_font('DejaVu', 'B', 16)
        pdf.cell(0, 15, 'ОТЧЕТ ПО АРТЕФАКТАМ', ln=True, align='C')
        pdf.ln(5)
        
        pdf.set_font('DejaVu', '', 10)
        pdf.cell(0, 6, f"ID: {self.data.investigation_id}", ln=True)
        pdf.cell(0, 6, f"Дата: {self.data.timestamp}", ln=True)
        pdf.cell(0, 6, f"Версия: v{self.data.tool_version}", ln=True)
        pdf.cell(0, 6, f"Длительность: {self.data.scan_duration:.2f} сек", ln=True)
        pdf.ln(10)
        
        pdf.section_title("СТАТИСТИКА")
        for s in [f"Всего: {self.data.total_users}", f"Системных: {self.data.system_users_count}",
                  f"Активных: {self.data.active_users_count}", f"Удаленных: {self.data.deleted_users_count}"]:
            pdf.cell(0, 6, s, ln=True)
        pdf.ln(5)
        
        pdf.section_title("СИСТЕМА")
        for i in [f"Хост: {self.data.system_info.hostname}",
                  f"ОС: {self.data.system_info.os_name} {self.data.system_info.os_version}",
                  f"Ядро: {self.data.system_info.kernel}",
                  f"Архитектура: {self.data.system_info.architecture}"]:
            pdf.cell(0, 6, i, ln=True)
        pdf.ln(5)
        
        icon_map = {'file': '📄', 'process': '⚙️', 'network': '🌐', 'socket': '🔌',
                    'cron': '⏰', 'log': '📋', 'history': '📜', 'timer': '⏱️'}
        
        for user in self.data.deleted_users:
            pdf.set_font('DejaVu', 'B', 11)
            pdf.set_text_color(52, 73, 94)
            name = f" ({user.possible_username})" if user.possible_username else ""
            pdf.cell(0, 8, f"UID: {user.uid}{name}", ln=True)
            
            pdf.set_font('DejaVu', '', 10)
            pdf.set_text_color(0, 0, 0)
            if user.home_directory:
                pdf.cell(0, 5, f"  Home: {user.home_directory}", ln=True)
            
            found = []
            if user.found_in_processes: found.append("processes")
            if user.found_in_files: found.append("files")
            if user.found_in_cron: found.append("cron")
            if found:
                pdf.cell(0, 5, f"  Found in: {', '.join(found)}", ln=True)
            
            if user.artifacts:
                pdf.set_font('DejaVu', 'B', 10)
                pdf.cell(0, 5, f"  Артефакты ({len(user.artifacts)}):", ln=True)
                pdf.set_font('DejaVu', '', 9)
                
                for a in user.artifacts:
                    icon = icon_map.get(a.type, '📁')
                    if a.type == 'file':
                        line = f"    {icon} {a.path}"
                        if a.size: line += f" ({a.size} bytes)"
                        if a.permissions: line += f" [{a.permissions}]"
                        pdf.cell(0, 4, line, ln=True)
                        if a.hashes:
                            pdf.cell(5)
                            pdf.cell(0, 4, f"MD5: {a.hashes.get('md5', 'N/A')}", ln=True)
                            pdf.cell(5)
                            pdf.cell(0, 4, f"SHA256: {a.hashes.get('sha256', 'N/A')}", ln=True)
                    elif a.type == 'process':
                        pdf.cell(0, 4, f"    {icon} PID {a.pid}: {a.command}", ln=True)
                    elif a.type == 'network':
                        path = a.path or f"{a.protocol}:{a.address}" if a.protocol and a.address else ""
                        pdf.cell(0, 4, f"    {icon} {path}" + (f" (PID: {a.pid})" if a.pid else ""), ln=True)
                    elif a.type == 'socket':
                        pdf.cell(0, 4, f"    {icon} {a.path}" + (f" (PID: {a.pid})" if a.pid else ""), ln=True)
                    elif a.type == 'cron':
                        cmd = f"[{a.path}] {a.command}" if a.path else a.command
                        pdf.cell(0, 4, f"    {icon} {cmd}", ln=True)
                    elif a.type == 'log':
                        line = f"{a.path}: {a.line[:100]}" + ("..." if a.line and len(a.line) > 100 else "")
                        pdf.cell(0, 4, f"    {icon} {line}", ln=True)
                    elif a.type == 'history':
                        pdf.cell(0, 4, f"    {icon} {a.command}", ln=True)
                    else:
                        pdf.cell(0, 4, f"    {icon} {a.path or a.command or 'N/A'}", ln=True)
                pdf.ln(2)
            pdf.ln(3)
        
        pdf.output(str(out))
        logger.info(f"PDF: {out}")
        return out
    
    def generate_all(self, formats: Optional[List[str]] = None) -> Dict[str, Optional[Path]]:
        return {f: getattr(self, f'generate_{f}')() for f in (formats or self.FORMATS) if f in self.FORMATS}