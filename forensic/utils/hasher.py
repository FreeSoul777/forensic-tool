import hashlib
import subprocess
from pathlib import Path
from typing import Optional, Dict


class FileHasher:
    ALGORITHMS = ['md5', 'sha1', 'sha256']
    
    @staticmethod
    def get_hash(file_path: Path, algorithm: str = 'sha256') -> Optional[str]:
        if not file_path.is_file():
            return None
        try:
            h = getattr(hashlib, algorithm)()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            return h.hexdigest()
        except:
            return None
    
    @staticmethod
    def get_hash_fast(file_path: Path, algorithm: str = 'sha256') -> Optional[str]:
        if not file_path.is_file():
            return None
        
        cmds = {
            'md5': ['md5sum', 'md5'],
            'sha1': ['sha1sum', 'shasum', '-a', '1'],
            'sha256': ['sha256sum', 'shasum', '-a', '256']
        }
        if algorithm not in cmds:
            return None
        
        for cmd in [cmds[algorithm]]:
            try:
                if isinstance(cmd, list):
                    res = subprocess.run(cmd + [str(file_path)], capture_output=True, text=True, timeout=5)
                else:
                    res = subprocess.run([cmd, str(file_path)], capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    return res.stdout.strip().split()[0]
            except:
                continue
        return FileHasher.get_hash(file_path, algorithm)
    
    @staticmethod
    def get_all_hashes(file_path: Path) -> Dict[str, str]:
        return {a: FileHasher.get_hash_fast(file_path, a) for a in FileHasher.ALGORITHMS if FileHasher.get_hash_fast(file_path, a)}
    
    @staticmethod
    def verify_hash(file_path: Path, expected: str, algorithm: str = 'sha256') -> bool:
        actual = FileHasher.get_hash_fast(file_path, algorithm)
        return actual == expected if actual else False