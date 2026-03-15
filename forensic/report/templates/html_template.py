"""
HTML шаблон для отчетов
"""

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Report - Investigation {investigation_id}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f7fa;
            padding: 30px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        /* Header */
        .header {{
            background: linear-gradient(135deg, #2c3e50, #3498db);
            color: white;
            padding: 40px;
        }}
        
        .header h1 {{
            font-size: 32px;
            margin-bottom: 10px;
            font-weight: 500;
        }}
        
        .header .subtitle {{
            font-size: 16px;
            opacity: 0.9;
            margin-bottom: 20px;
        }}
        
        .metadata-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 12px;
            margin-top: 20px;
        }}
        
        .metadata-item {{
            display: flex;
            flex-direction: column;
        }}
        
        .metadata-label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            opacity: 0.7;
            margin-bottom: 5px;
        }}
        
        .metadata-value {{
            font-size: 18px;
            font-weight: 600;
        }}
        
        /* Stats Cards */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 25px;
            padding: 40px;
            background: #f8fafc;
        }}
        
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            text-align: center;
            transition: transform 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }}
        
        .stat-icon {{
            font-size: 40px;
            margin-bottom: 15px;
        }}
        
        .stat-value {{
            font-size: 36px;
            font-weight: 700;
            color: #2c3e50;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            font-size: 14px;
            color: #7f8c8d;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        /* Sections */
        .section {{
            padding: 40px;
            border-bottom: 1px solid #ecf0f1;
        }}
        
        .section-title {{
            font-size: 24px;
            color: #2c3e50;
            margin-bottom: 25px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .section-title:after {{
            content: '';
            flex: 1;
            height: 2px;
            background: linear-gradient(90deg, #3498db, transparent);
            margin-left: 20px;
        }}
        
        /* System Info Grid */
        .system-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
        }}
        
        .system-item {{
            background: #f8fafc;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }}
        
        .system-label {{
            font-size: 12px;
            color: #7f8c8d;
            text-transform: uppercase;
            margin-bottom: 5px;
        }}
        
        .system-value {{
            font-size: 16px;
            font-weight: 600;
            color: #2c3e50;
        }}
        
        /* User Cards */
        .user-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 25px;
        }}
        
        .user-card {{
            background: white;
            border: 1px solid #e1e8ed;
            border-radius: 12px;
            overflow: hidden;
            transition: all 0.3s;
        }}
        
        .user-card:hover {{
            box-shadow: 0 5px 25px rgba(0,0,0,0.1);
            border-color: #3498db;
        }}
        
        .user-header {{
            background: linear-gradient(135deg, #34495e, #2c3e50);
            color: white;
            padding: 20px;
        }}
        
        .user-uid {{
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 5px;
        }}
        
        .user-meta {{
            font-size: 14px;
            opacity: 0.8;
        }}
        
        .user-body {{
            padding: 20px;
        }}
        
        .info-row {{
            display: flex;
            margin-bottom: 12px;
            padding-bottom: 12px;
            border-bottom: 1px dashed #ecf0f1;
        }}
        
        .info-row:last-child {{
            border-bottom: none;
        }}
        
        .info-label {{
            width: 120px;
            color: #7f8c8d;
            font-size: 14px;
        }}
        
        .info-value {{
            flex: 1;
            font-weight: 500;
            color: #2c3e50;
        }}
        
        /* Artifacts Table */
        .artifacts-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            font-size: 14px;
        }}
        
        .artifacts-table th {{
            background: #34495e;
            color: white;
            font-weight: 500;
            padding: 12px;
            text-align: left;
        }}
        
        .artifacts-table td {{
            padding: 10px 12px;
            border-bottom: 1px solid #ecf0f1;
            vertical-align: top;
        }}
        
        .artifacts-table tr:hover {{
            background: #f8fafc;
        }}
        
        .hash-info {{
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 11px;
            color: #7f8c8d;
            margin-top: 4px;
        }}

        .hash-info {{
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 11px;
            color: #7f8c8d;
            margin-top: 6px;
            padding: 4px 8px;
            background: #f8f9fa;
            border-radius: 4px;
            border-left: 3px solid #3498db;
        }}

        .hash-md5, .hash-sha256 {{
            display: inline-block;
            word-break: break-all;
        }}
                
        /* Command Block */
        .command-block {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 13px;
            margin: 10px 0;
            overflow-x: auto;
        }}
        
        /* Footer */
        .footer {{
            background: #2c3e50;
            color: white;
            padding: 30px 40px;
            text-align: center;
        }}
        
        .footer small {{
            opacity: 0.7;
            font-size: 12px;
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            
            .container {{
                box-shadow: none;
            }}
            
            .stat-card {{
                box-shadow: none;
                border: 1px solid #ecf0f1;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🔍 Forensic Investigation Report</h1>
            <div class="subtitle">Detailed analysis of deleted users and system artifacts</div>
            
            <div class="metadata-grid">
                <div class="metadata-item">
                    <span class="metadata-label">Investigation ID</span>
                    <span class="metadata-value">{investigation_id}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Generated</span>
                    <span class="metadata-value">{timestamp}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Tool Version</span>
                    <span class="metadata-value">v{tool_version}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Scan Duration</span>
                    <span class="metadata-value">{scan_duration:.2f}s</span>
                </div>
            </div>
        </div>
        
        <!-- Statistics -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon">👥</div>
                <div class="stat-value">{total_users}</div>
                <div class="stat-label">Total Users</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">✅</div>
                <div class="stat-value">{active_users}</div>
                <div class="stat-label">Active Users</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">🗑️</div>
                <div class="stat-value">{deleted_users}</div>
                <div class="stat-label">Deleted Users</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">📊</div>
                <div class="stat-value">{total_artifacts}</div>
                <div class="stat-label">Total Artifacts</div>
            </div>
        </div>
        
        <!-- System Information -->
        <div class="section">
            <div class="section-title">
                <span>💻 System Information</span>
            </div>
            <div class="system-grid">
                <div class="system-item">
                    <div class="system-label">Hostname</div>
                    <div class="system-value">{hostname}</div>
                </div>
                <div class="system-item">
                    <div class="system-label">Operating System</div>
                    <div class="system-value">{os_name} {os_version}</div>
                </div>
                <div class="system-item">
                    <div class="system-label">Kernel</div>
                    <div class="system-value">{kernel}</div>
                </div>
                <div class="system-item">
                    <div class="system-label">Architecture</div>
                    <div class="system-value">{architecture}</div>
                </div>
            </div>
        </div>
        
        <!-- System Users -->
        <div class="section">
            <div class="section-title">
                <span>👤 System Users ({system_users_count})</span>
            </div>
            <div class="system-grid">
                {system_user_cards}
            </div>
        </div>
        
        <!-- Active Users -->
        <div class="section">
            <div class="section-title">
                <span>🟢 Active Users ({active_users_count})</span>
            </div>
            <div class="system-grid">
                {active_user_cards}
            </div>
        </div>
        
        <!-- Deleted Users -->
        <div class="section">
            <div class="section-title">
                <span>🗑️ Deleted Users ({deleted_users})</span>
            </div>
            
            <div class="user-grid">
                {user_cards}
            </div>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <small>
                Forensic Investigation Tool v{tool_version} | 
                Report ID: {investigation_id} | 
                Generated: {timestamp}
            </small>
        </div>
    </div>
</body>
</html>"""

ARTIFACT_TYPES = {
    "file": "📄",
    "process": "⚙️",
    "cron": "⏰",
    "timer": "⏱️",
    "network": "🌐",
    "socket": "🔌",
    "log": "📋",
    "history": "📜",
    "unknown": "❓"
}

def generate_user_card(user: dict) -> str:
    """Генерирует HTML для карточки пользователя"""
    
    artifacts = user.get('artifacts', [])
    
    # Формируем таблицу артефактов (ВСЕ артефакты)
    artifacts_rows = ""
    for artifact in artifacts:
        artifact_type = artifact.get('type', 'unknown')
        icon = ARTIFACT_TYPES.get(artifact_type, '📁')
        
        # Формируем описание в зависимости от типа
        if artifact_type == 'file':
            description = artifact.get('path', 'N/A')
            if 'size' in artifact and artifact['size']:
                description += f" ({artifact['size']} bytes)"
            if 'permissions' in artifact and artifact['permissions']:
                description += f" [{artifact['permissions']}]"
            
            # Добавляем хэши если есть
            hash_html = ""
            if artifact.get('hashes'):
                hashes = artifact['hashes']
                md5 = hashes.get('md5', '')
                sha256 = hashes.get('sha256', '')
                if md5 or sha256:
                    hash_html = '<div class="hash-info">'
                    if md5:
                        hash_html += f'<span class="hash-md5">MD5: {md5}</span><br>'
                    if sha256:
                        hash_html += f'<span class="hash-sha256">SHA256: {sha256}</span>'
                    hash_html += '</div>'
            else:
                hash_html = ""
            
        elif artifact_type == 'process':
            icon = '⚙️'  # Явно указываем иконку для процесса
            description = f"PID {artifact.get('pid')}: {artifact.get('command', '')}"
            hash_html = ""
            
        elif artifact_type == 'network':
            icon = '🌐'  # Явно указываем иконку для сети
            path = artifact.get('path', '')
            if not path and 'protocol' in artifact and 'address' in artifact:
                path = f"{artifact['protocol']}:{artifact['address']}"
            description = path
            if 'pid' in artifact and artifact['pid']:
                description += f" (PID: {artifact['pid']})"
            hash_html = ""
            
        elif artifact_type == 'socket':
            icon = '🔌'  # Явно указываем иконку для сокета
            description = artifact.get('path', 'N/A')
            if 'pid' in artifact and artifact['pid']:
                description += f" (PID: {artifact['pid']})"
            hash_html = ""
            
        elif artifact_type == 'cron':
            icon = '⏰'  # Явно указываем иконку для cron
            description = artifact.get('command', '')
            if artifact.get('path'):
                description = f"[{artifact['path']}] {description}"
            hash_html = ""
            
        elif artifact_type == 'log':
            icon = '📋'  # Явно указываем иконку для лога
            description = f"{artifact.get('path', '')}: {artifact.get('line', '')[:100]}"
            if artifact.get('line') and len(artifact['line']) > 100:
                description += "..."
            hash_html = ""
            
        elif artifact_type == 'history':
            icon = '📜'  # Явно указываем иконку для истории
            description = artifact.get('command', '')
            hash_html = ""
            
        else:
            description = str(artifact.get('path', artifact.get('command', 'N/A')))
            hash_html = ""
        
        artifacts_rows += f"""
        <tr>
            <td>{icon} {artifact_type}</td>
            <td>{description}{hash_html}</td>
        </tr>
        """
    
    return f"""
    <div class="user-card">
        <div class="user-header">
            <div class="user-uid">UID: {user.get('uid', 'unknown')}</div>
            <div class="user-meta">
                {user.get('possible_username', '')}
            </div>
        </div>
        <div class="user-body">
            <div class="info-row">
                <span class="info-label">Home Dir:</span>
                <span class="info-value">{user.get('home_directory', 'N/A')}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Found in:</span>
                <span class="info-value">
                    { '✓ processes ' if user.get('found_in_processes', False) else ''}
                    { '✓ files ' if user.get('found_in_files', False) else ''}
                    { '✓ cron ' if user.get('found_in_cron', False) else ''}
                </span>
            </div>
            
            <h4 style="margin: 15px 0 10px 0;">Artifacts ({len(artifacts)})</h4>
            <table class="artifacts-table">
                <tr>
                    <th>Type</th>
                    <th>Description</th>
                </tr>
                {artifacts_rows}
            </table>
        </div>
    </div>
    """

def generate_system_user_card(user: dict) -> str:
    """Генерирует HTML для карточки системного пользователя"""
    return f"""
    <div class="system-item">
        <div class="system-label">{user.get('username', 'unknown')} (UID: {user.get('uid', '?')})</div>
        <div class="system-value">Shell: {user.get('shell', 'N/A')}<br>Home: {user.get('home', 'N/A')}</div>
    </div>
    """

def generate_active_user_card(user: dict) -> str:
    """Генерирует HTML для карточки активного пользователя"""
    return f"""
    <div class="system-item">
        <div class="system-label">{user.get('username', 'unknown')} (UID: {user.get('uid', '?')})</div>
        <div class="system-value">Shell: {user.get('shell', 'N/A')}<br>Home: {user.get('home', 'N/A')}</div>
    </div>
    """