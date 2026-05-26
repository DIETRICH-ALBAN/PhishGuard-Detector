#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LogIDS Detector — Log Analyzer for Intrusion Detection
Auteur : Jamein N. Dietrich A.
Projet personnel de cybersécurité

Analyse les logs système pour détecter des patterns d'intrusion :
- Tentatives de brute force SSH
- Scans de ports
- Injections SQL et XSS dans les requêtes HTTP
- Accès suspects (heures inhabituelles, volumes anormaux)
"""

import argparse
import re
import os
import sys
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional
from urllib.parse import unquote

# ============================================================
# COULEURS TERMINAL
# ============================================================
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


def print_banner():
    """Affiche la bannière."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
  ╔═══════════════════════════════════════════════════════╗
  ║           🛡️ LogIDS Detector v1.0                    ║
  ║     Log Analyzer for Intrusion Detection             ║
  ║     by Jamein N. Dietrich A.                         ║
  ╚═══════════════════════════════════════════════════════╝
{Colors.END}"""
    print(banner)


# ============================================================
# PARSERS DE LOGS
# ============================================================
class LogParser:
    """Parseur de logs multi-format."""
    
    # Regex pour Apache/Nginx Combined Log Format
    APACHE_PATTERN = re.compile(
        r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'
        r'(?P<ident>-|\S+)\s+'
        r'(?P<user>-|\S+)\s+'
        r'\[(?P<date>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d{3})\s+'
        r'(?P<size>\d+|-)\s*'
        r'(?:"(?P<referrer>[^"]*)")?\s*'
        r'(?:"(?P<user_agent>[^"]*)")?'
    )
    
    # Regex pour les logs SSH / auth.log
    SSH_PATTERNS = [
        re.compile(r'(?P<date>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
                   r'(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+'
                   r'Failed password for (?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'),
        re.compile(r'(?P<date>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
                   r'(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+'
                   r'Accepted password for (?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'),
        re.compile(r'(?P<date>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
                   r'(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+'
                   r'Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'),
    ]
    
    @staticmethod
    def parse_apache_line(line: str) -> Optional[Dict]:
        """Parse une ligne de log Apache/Nginx."""
        match = LogParser.APACHE_PATTERN.match(line)
        if not match:
            return None
        
        data = match.groupdict()
        try:
            data['status'] = int(data['status'])
        except (ValueError, TypeError):
            data['status'] = 0
        
        return data
    
    @staticmethod
    def parse_ssh_line(line: str) -> Optional[Dict]:
        """Parse une ligne de log SSH/auth.log."""
        for pattern in LogParser.SSH_PATTERNS:
            match = pattern.search(line)
            if match:
                data = match.groupdict()
                data['type'] = 'ssh'
                if 'Failed' in line:
                    data['action'] = 'failed'
                elif 'Accepted' in line:
                    data['action'] = 'accepted'
                elif 'Invalid' in line:
                    data['action'] = 'invalid_user'
                return data
        
        return None
    
    @staticmethod
    def parse_file(filepath: str, log_type: str) -> List[Dict]:
        """
        Parse un fichier de logs complet.
        
        Args:
            filepath: Chemin du fichier de log
            log_type: Type de log ('apache', 'nginx', 'ssh')
        
        Returns:
            Liste des entrées parsées
        """
        entries = []
        
        if not os.path.exists(filepath):
            print(f"{Colors.RED}[!] Fichier non trouvé : {filepath}{Colors.END}")
            return entries
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                if log_type in ('apache', 'nginx'):
                    entry = LogParser.parse_apache_line(line)
                elif log_type == 'ssh':
                    entry = LogParser.parse_ssh_line(line)
                else:
                    continue
                
                if entry:
                    entry['line_num'] = line_num
                    entry['raw'] = line
                    entries.append(entry)
        
        return entries


# ============================================================
# RÈGLES DE DÉTECTION
# ============================================================
class DetectionRules:
    """Règles de détection d'intrusion."""
    
    # Patterns d'injection SQL
    SQL_INJECTION_PATTERNS = [
        (r"(\b(union\s+select|select\s+.+\s+from|insert\s+into|delete\s+from|drop\s+table|alter\s+table)\b)", 'SQL Injection — Commande SQL détectée'),
        (r"(\b(or\s+1\s*=\s*1|or\s+true\s*--|'\s*or\s*'\s*=\s*')\b)", 'SQL Injection — Condition toujours vraie'),
        (r"(;\s*(drop|delete|truncate|alter|create)\b)", 'SQL Injection — Commande dangereuse après point-virgule'),
        (r"(\b(waitfor\s+delay|benchmark\s*\(|sleep\s*\()\b)", 'SQL Injection — Time-based blind'),
        (r"(--\s*$|#\s*$|/\*)", 'SQL Injection — Commentaire SQL'),
        (r"(\b(exec\s*\(|execute\s+|xp_cmdshell)\b)", 'SQL Injection — Exécution de commande'),
    ]
    
    # Patterns XSS
    XSS_PATTERNS = [
        (r"(<script[\s>])", 'XSS — Balise <script> détectée'),
        (r"(javascript\s*:)", 'XSS — Protocol javascript: détecté'),
        (r"(\bon\w+\s*=\s*)", 'XSS — Event handler inline détecté'),
        (r"(document\.(cookie|location|write))", 'XSS — Accès DOM détecté'),
        (r"(eval\s*\(|alert\s*\()", 'XSS — Fonction JS dangereuse'),
        (r"(<img[^>]+onerror)", 'XSS — Image onerror détectée'),
    ]
    
    # Patterns de path traversal
    PATH_TRAVERSAL_PATTERNS = [
        (r"(\.\./|\.\.\\)", 'Path Traversal — Directory traversal détecté'),
        (r"(/etc/(passwd|shadow|hosts))", 'Path Traversal — Accès fichier système'),
        (r"(/proc/self/)", 'Path Traversal — Accès /proc/self'),
        (r"(\\windows\\system32)", 'Path Traversal — Accès System32'),
    ]
    
    # Patterns de commande injection
    COMMAND_INJECTION_PATTERNS = [
        (r"(;\s*(ls|cat|wget|curl|nc|bash|sh|python|perl)\b)", 'Command Injection — Commande système après point-virgule'),
        (r"(\|{1,2}\s*(ls|cat|wget|curl|nc|bash|sh))", 'Command Injection — Pipe vers commande système'),
        (r"(`[^`]+`)", 'Command Injection — Backtick execution'),
        (r"(\$\([^)]+\))", 'Command Injection — Subshell execution'),
    ]
    
    # User-agents suspects
    SUSPICIOUS_USER_AGENTS = [
        'sqlmap', 'nikto', 'nmap', 'dirbuster', 'gobuster',
        'wfuzz', 'burpsuite', 'hydra', 'metasploit',
        'masscan', 'zgrab', 'python-requests', 'wget',
    ]
    
    @classmethod
    def all_web_attack_patterns(cls) -> List[Tuple[str, str]]:
        """Retourne tous les patterns d'attaque web."""
        return ([(p, f'WEB-{d}') for p, d in cls.SQL_INJECTION_PATTERNS] +
                [(p, f'WEB-{d}') for p, d in cls.XSS_PATTERNS] +
                [(p, f'WEB-{d}') for p, d in cls.PATH_TRAVERSAL_PATTERNS] +
                [(p, f'WEB-{d}') for p, d in cls.COMMAND_INJECTION_PATTERNS])


# ============================================================
# DÉTECTEUR D'INTRUSION
# ============================================================
class IntrusionDetector:
    """Moteur de détection d'intrusion basé sur l'analyse de logs."""
    
    def __init__(self, 
                 brute_force_threshold: int = 5,
                 port_scan_threshold: int = 10,
                 time_window_minutes: int = 5):
        self.brute_force_threshold = brute_force_threshold
        self.port_scan_threshold = port_scan_threshold
        self.time_window = timedelta(minutes=time_window_minutes)
        self.alerts: List[Dict] = []
    
    def detect_brute_force_ssh(self, entries: List[Dict]) -> List[Dict]:
        """
        Détecte les tentatives de brute force SSH.
        
        Logique : Plus de N tentatives échouées depuis la même IP
        dans une fenêtre de temps donnée.
        """
        alerts = []
        failed_attempts = defaultdict(list)  # {ip: [timestamps]}
        
        for entry in entries:
            if entry.get('action') in ('failed', 'invalid_user'):
                ip = entry.get('ip', '')
                # Note: le timestamp exact nécessiterait un parsing plus avancé
                failed_attempts[ip].append(entry)
        
        for ip, attempts in failed_attempts.items():
            if len(attempts) >= self.brute_force_threshold:
                users_targeted = set(a.get('user', '') for a in attempts)
                alert = {
                    'type': 'BRUTE_FORCE_SSH',
                    'severity': 'Critical' if len(attempts) >= 20 else 'High',
                    'source_ip': ip,
                    'attempt_count': len(attempts),
                    'users_targeted': list(users_targeted),
                    'description': (f'Brute force SSH détecté depuis {ip} : '
                                   f'{len(attempts)} tentatives échouées '
                                   f'ciblant {len(users_targeted)} utilisateur(s)'),
                    'recommendation': (f'Bloquer l\'IP {ip} via iptables/firewall, '
                                      f'désactiver les comptes ciblés, '
                                      f'activer fail2ban'),
                    'entries': attempts[:5],  # Limiter pour le rapport
                }
                alerts.append(alert)
        
        return alerts
    
    def detect_port_scan(self, entries: List[Dict]) -> List[Dict]:
        """
        Détecte les scans de ports basés sur les logs Apache/Nginx.
        
        Logique : Une IP qui accède à de nombreuses URL/ports différentes
        en un temps court est probablement un scanner.
        """
        alerts = []
        ip_requests = defaultdict(lambda: {'paths': set(), 'count': 0, 'status_codes': Counter()})
        
        for entry in entries:
            if 'ip' in entry:
                ip = entry['ip']
                ip_requests[ip]['paths'].add(entry.get('path', ''))
                ip_requests[ip]['count'] += 1
                ip_requests[ip]['status_codes'][entry.get('status', 0)] += 1
        
        for ip, data in ip_requests.items():
            unique_paths = len(data['paths'])
            error_count = sum(data['status_codes'].get(s, 0) for s in [400, 403, 404, 444, 503])
            error_ratio = error_count / max(data['count'], 1)
            
            # Un scanner a beaucoup de chemins uniques et un ratio d'erreurs élevé
            if unique_paths >= self.port_scan_threshold and error_ratio > 0.5:
                alert = {
                    'type': 'PORT_SCAN',
                    'severity': 'High' if unique_paths >= 50 else 'Medium',
                    'source_ip': ip,
                    'unique_paths': unique_paths,
                    'total_requests': data['count'],
                    'error_ratio': f'{error_ratio:.1%}',
                    'description': (f'Scan de port/web détecté depuis {ip} : '
                                   f'{unique_paths} chemins uniques, '
                                   f'{data["count"]} requêtes, '
                                   f'ratio d\'erreur {error_ratio:.1%}'),
                    'recommendation': f'Bloquer l\'IP {ip}, vérifier les règles du WAF',
                    'top_paths': list(data['paths'])[:10],
                }
                alerts.append(alert)
        
        return alerts
    
    def detect_web_attacks(self, entries: List[Dict]) -> List[Dict]:
        """
        Détecte les attaques web (SQLi, XSS, path traversal, command injection)
        dans les logs Apache/Nginx.
        """
        alerts = []
        attack_patterns = DetectionRules.all_web_attack_patterns()
        
        for entry in entries:
            path = unquote(entry.get('path', ''))  # Décoder les URL encodées
            user_agent = entry.get('user_agent', '')
            ip = entry.get('ip', '')
            
            for pattern, rule_name in attack_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    # Déterminer la sévérité
                    if 'SQL Injection' in rule_name:
                        severity = 'Critical'
                    elif 'XSS' in rule_name:
                        severity = 'High'
                    elif 'Path Traversal' in rule_name:
                        severity = 'High'
                    else:
                        severity = 'Medium'
                    
                    alert = {
                        'type': 'WEB_ATTACK',
                        'severity': severity,
                        'rule': rule_name,
                        'source_ip': ip,
                        'path': entry.get('path', '')[:100],
                        'decoded_path': path[:100],
                        'status': entry.get('status', 0),
                        'description': (f'{rule_name} détecté depuis {ip} : '
                                       f'{path[:80]}'),
                        'recommendation': 'Analyser la requête, renforcer les règles WAF',
                        'line_num': entry.get('line_num', 0),
                    }
                    alerts.append(alert)
                    break  # Un seul match par entrée
            
            # Vérification des user-agents suspects
            for suspicious_ua in DetectionRules.SUSPICIOUS_USER_AGENTS:
                if suspicious_ua.lower() in user_agent.lower():
                    alert = {
                        'type': 'SUSPICIOUS_UA',
                        'severity': 'Medium',
                        'rule': f'User-Agent suspect : {suspicious_ua}',
                        'source_ip': ip,
                        'user_agent': user_agent[:80],
                        'description': (f'User-Agent suspect détecté depuis {ip} : '
                                       f'{suspicious_ua}'),
                        'recommendation': 'Vérifier si cet outil est légitime, bloquer si nécessaire',
                        'line_num': entry.get('line_num', 0),
                    }
                    alerts.append(alert)
                    break
        
        return alerts
    
    def detect_suspicious_access(self, entries: List[Dict]) -> List[Dict]:
        """
        Détecte les accès suspects : volumes anormaux, status codes inhabituels.
        """
        alerts = []
        ip_stats = defaultdict(lambda: {'requests': 0, 'errors': 0, 'paths': set()})
        
        for entry in entries:
            if 'ip' in entry:
                ip = entry['ip']
                ip_stats[ip]['requests'] += 1
                ip_stats[ip]['paths'].add(entry.get('path', ''))
                if entry.get('status', 0) >= 400:
                    ip_stats[ip]['errors'] += 1
        
        for ip, stats in ip_stats.items():
            # Volume anormalement élevé
            if stats['requests'] > 500:
                alert = {
                    'type': 'HIGH_VOLUME',
                    'severity': 'Medium',
                    'source_ip': ip,
                    'request_count': stats['requests'],
                    'error_count': stats['errors'],
                    'description': (f'Volume de requêtes élevé depuis {ip} : '
                                   f'{stats["requests"]} requêtes'),
                    'recommendation': 'Vérifier si le trafic est légitime, envisager un rate limiting',
                }
                alerts.append(alert)
        
        return alerts
    
    def run_all_detections(self, entries: List[Dict], log_type: str) -> List[Dict]:
        """Exécute toutes les détections sur les entrées parsées."""
        all_alerts = []
        
        if log_type == 'ssh':
            all_alerts.extend(self.detect_brute_force_ssh(entries))
        elif log_type in ('apache', 'nginx'):
            all_alerts.extend(self.detect_port_scan(entries))
            all_alerts.extend(self.detect_web_attacks(entries))
            all_alerts.extend(self.detect_suspicious_access(entries))
        
        # Trier par sévérité
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        all_alerts.sort(key=lambda a: severity_order.get(a.get('severity', 'Low'), 99))
        
        self.alerts = all_alerts
        return all_alerts


# ============================================================
# GÉNÉRATEUR DE RAPPORT HTML
# ============================================================
def generate_html_report(alerts: List[Dict], log_file: str, log_type: str, 
                         total_entries: int, output_file: str) -> None:
    """Génère un rapport HTML des alertes détectées."""
    
    severity_stats = Counter(a.get('severity', 'Low') for a in alerts)
    type_stats = Counter(a.get('type', 'Unknown') for a in alerts)
    
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport LogIDS — {log_file}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
        .container {{ max-width: 1100px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1e293b, #0f172a); border: 1px solid #334155; border-radius: 12px; padding: 30px; margin-bottom: 20px; text-align: center; }}
        .header h1 {{ color: #38bdf8; font-size: 28px; }}
        .header .meta {{ color: #94a3b8; font-size: 14px; margin-top: 10px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; text-align: center; }}
        .card .number {{ font-size: 36px; font-weight: bold; }}
        .card .label {{ color: #94a3b8; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; }}
        .section {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 25px; margin-bottom: 20px; }}
        .section h2 {{ color: #38bdf8; font-size: 20px; margin-bottom: 15px; border-bottom: 1px solid #334155; padding-bottom: 10px; }}
        .alert {{ background: #0f172a; border-radius: 6px; padding: 15px; margin-bottom: 10px; border-left: 4px solid; }}
        .alert-critical {{ border-left-color: #ef4444; }}
        .alert-high {{ border-left-color: #f97316; }}
        .alert-medium {{ border-left-color: #eab308; }}
        .alert-low {{ border-left-color: #22c55e; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: bold; text-transform: uppercase; }}
        .badge-critical {{ background: #7f1d1d; color: #fca5a5; }}
        .badge-high {{ background: #7c2d12; color: #fdba74; }}
        .badge-medium {{ background: #713f12; color: #fde047; }}
        .badge-low {{ background: #14532d; color: #86efac; }}
        .footer {{ text-align: center; color: #64748b; font-size: 12px; padding: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Rapport LogIDS Detector</h1>
            <div class="meta">
                Fichier : <strong>{log_file}</strong> | 
                Type : <strong>{log_type.upper()}</strong> | 
                Entrées analysées : <strong>{total_entries}</strong> |
                Date : <strong>{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</strong>
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <div class="number" style="color: #38bdf8;">{total_entries}</div>
                <div class="label">Entrées Analysées</div>
            </div>
            <div class="card">
                <div class="number" style="color: #ef4444;">{len(alerts)}</div>
                <div class="label">Alertes Totales</div>
            </div>
            <div class="card">
                <div class="number" style="color: #ef4444;">{severity_stats.get('Critical', 0)}</div>
                <div class="label">Critiques</div>
            </div>
            <div class="card">
                <div class="number" style="color: #f97316;">{severity_stats.get('High', 0)}</div>
                <div class="label">Élevées</div>
            </div>
            <div class="card">
                <div class="number" style="color: #eab308;">{severity_stats.get('Medium', 0)}</div>
                <div class="label">Moyennes</div>
            </div>
        </div>
        
        <div class="section">
            <h2>🚨 Alertes Détectées</h2>
"""
    
    for alert in alerts:
        severity = alert.get('severity', 'Low').lower()
        html += f"""            <div class="alert alert-{severity}">
                <span class="badge badge-{severity}">{alert.get('severity', 'Low')}</span>
                <strong>{alert.get('type', 'Unknown')}</strong> — {alert.get('description', '')}<br>
                <span style="color: #22c55e; font-size: 13px;">💡 Recommandation : {alert.get('recommendation', '')}</span>
            </div>
"""
    
    html += """        </div>
        <div class="footer">
            Rapport généré par LogIDS Detector v1.0 — Outil éducatif de cybersécurité
        </div>
    </div>
</body>
</html>
"""
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"\n{Colors.GREEN}[✓] Rapport HTML généré : {output_file}{Colors.END}")


# ============================================================
# DONNÉES DE DÉMONSTRATION
# ============================================================
def run_demo():
    """Lance une démonstration avec des logs simulés."""
    print(f"\n{Colors.YELLOW}[*] Mode démonstration — Analyse de logs simulés{Colors.END}\n")
    
    # Logs SSH simulés
    ssh_logs = [
        "Mar 15 10:23:01 server sshd[1234]: Failed password for root from 192.168.1.100 port 22",
        "Mar 15 10:23:03 server sshd[1235]: Failed password for root from 192.168.1.100 port 22",
        "Mar 15 10:23:05 server sshd[1236]: Failed password for admin from 192.168.1.100 port 22",
        "Mar 15 10:23:07 server sshd[1237]: Failed password for root from 192.168.1.100 port 22",
        "Mar 15 10:23:09 server sshd[1238]: Failed password for admin from 192.168.1.100 port 22",
        "Mar 15 10:23:11 server sshd[1239]: Failed password for test from 192.168.1.100 port 22",
        "Mar 15 10:23:13 server sshd[1240]: Invalid user oracle from 192.168.1.100 port 22",
        "Mar 15 10:23:15 server sshd[1241]: Failed password for root from 192.168.1.100 port 22",
        "Mar 15 10:23:17 server sshd[1242]: Failed password for ubuntu from 192.168.1.100 port 22",
        "Mar 15 10:23:19 server sshd[1243]: Failed password for root from 192.168.1.100 port 22",
        "Mar 15 10:23:21 server sshd[1244]: Failed password for postgres from 192.168.1.100 port 22",
        "Mar 15 10:30:01 server sshd[1245]: Accepted password for jamein from 10.0.0.5 port 22",
    ]
    
    # Logs Apache simulés
    apache_logs = [
        '192.168.1.50 - - [15/Mar/2025:10:15:01 +0100] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        '10.0.0.100 - - [15/Mar/2025:10:15:02 +0100] "GET /admin HTTP/1.1" 403 512 "-" "sqlmap/1.7"',
        '10.0.0.100 - - [15/Mar/2025:10:15:03 +0100] "GET /?id=1%27%20OR%201=1-- HTTP/1.1" 200 2048 "-" "sqlmap/1.7"',
        '10.0.0.100 - - [15/Mar/2025:10:15:04 +0100] "GET /?user=admin%27-- HTTP/1.1" 200 1024 "-" "sqlmap/1.7"',
        '10.0.0.200 - - [15/Mar/2025:10:15:05 +0100] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
        '10.0.0.200 - - [15/Mar/2025:10:15:06 +0100] "GET /page?cmd=;cat%20/etc/passwd HTTP/1.1" 200 256 "-" "curl/7.88"',
        '10.0.0.150 - - [15/Mar/2025:10:15:07 +0100] "GET /../../../etc/passwd HTTP/1.1" 403 128 "-" "dirbuster"',
        '10.0.0.150 - - [15/Mar/2025:10:15:08 +0100] "GET /admin HTTP/1.1" 404 64 "-" "nikto"',
        '10.0.0.150 - - [15/Mar/2025:10:15:09 +0100] "GET /backup HTTP/1.1" 404 64 "-" "nikto"',
        '10.0.0.150 - - [15/Mar/2025:10:15:10 +0100] "GET /config HTTP/1.1" 404 64 "-" "nikto"',
        '10.0.0.150 - - [15/Mar/2025:10:15:11 +0100] "GET /db HTTP/1.1" 404 64 "-" "nikto"',
        '10.0.0.150 - - [15/Mar/2025:10:15:12 +0100] "GET /shell HTTP/1.1" 404 64 "-" "nikto"',
        '10.0.0.150 - - [15/Mar/2025:10:15:13 +0100] "GET /debug HTTP/1.1" 404 64 "-" "nikto"',
        '10.0.0.150 - - [15/Mar/2025:10:15:14 +0100] "GET /test HTTP/1.1" 404 64 "-" "nikto"',
        '10.0.0.150 - - [15/Mar/2025:10:15:15 +0100] "GET /wp-admin HTTP/1.1" 404 64 "-" "nikto"',
        '10.0.0.150 - - [15/Mar/2025:10:15:16 +0100] "GET /phpmyadmin HTTP/1.1" 404 64 "-" "nikto"',
        '10.0.0.150 - - [15/Mar/2025:10:15:17 +0100] "GET /console HTTP/1.1" 404 64 "-" "nikto"',
        '10.0.0.150 - - [15/Mar/2025:10:15:18 +0100] "GET /server-status HTTP/1.1" 404 64 "-" "nikto"',
        '10.0.0.150 - - [15/Mar/2025:10:15:19 +0100] "GET /actuator HTTP/1.1" 404 64 "-" "nikto"',
        '10.0.0.150 - - [15/Mar/2025:10:15:20 +0100] "GET /env HTTP/1.1" 404 64 "-" "nikto"',
    ]
    
    # Analyse SSH
    print(f"{Colors.BLUE}{'='*60}")
    print(f"  🔒 Analyse des logs SSH")
    print(f"{'='*60}{Colors.END}\n")
    
    ssh_entries = []
    for line in ssh_logs:
        entry = LogParser.parse_ssh_line(line)
        if entry:
            ssh_entries.append(entry)
    
    detector = IntrusionDetector(brute_force_threshold=5)
    ssh_alerts = detector.detect_brute_force_ssh(ssh_entries)
    
    for alert in ssh_alerts:
        severity = alert['severity']
        color = Colors.RED if severity == 'Critical' else Colors.YELLOW
        print(f"  {color}[{severity}] {alert['type']}{Colors.END}")
        print(f"       → {alert['description']}")
        print(f"       💡 {alert['recommendation']}\n")
    
    # Analyse Apache
    print(f"{Colors.BLUE}{'='*60}")
    print(f"  🌐 Analyse des logs Apache")
    print(f"{'='*60}{Colors.END}\n")
    
    apache_entries = []
    for line in apache_logs:
        entry = LogParser.parse_apache_line(line)
        if entry:
            entry['raw'] = line
            apache_entries.append(entry)
    
    apache_alerts = []
    apache_alerts.extend(detector.detect_port_scan(apache_entries))
    apache_alerts.extend(detector.detect_web_attacks(apache_entries))
    apache_alerts.extend(detector.detect_suspicious_access(apache_entries))
    
    # Trier par sévérité
    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
    apache_alerts.sort(key=lambda a: severity_order.get(a.get('severity', 'Low'), 99))
    
    for alert in apache_alerts:
        severity = alert['severity']
        color = Colors.RED if severity in ('Critical', 'High') else Colors.YELLOW
        print(f"  {color}[{severity}] {alert.get('type', 'Unknown')}{Colors.END}")
        print(f"       → {alert['description']}")
        if alert.get('recommendation'):
            print(f"       💡 {alert['recommendation']}")
        print()
    
    # Résumé
    all_alerts = ssh_alerts + apache_alerts
    total_alerts = len(all_alerts)
    critical_count = sum(1 for a in all_alerts if a.get('severity') == 'Critical')
    high_count = sum(1 for a in all_alerts if a.get('severity') == 'High')
    
    print(f"{Colors.CYAN}{'='*60}")
    print(f"  📊 Résumé de la démo")
    print(f"{'='*60}")
    print(f"  Entrées SSH analysées   : {len(ssh_entries)}")
    print(f"  Entrées Apache analysées : {len(apache_entries)}")
    print(f"  Alertes totales          : {total_alerts}")
    print(f"  — Critiques              : {critical_count}")
    print(f"  — Élevées                : {high_count}")
    print(f"  — Moyennes               : {total_alerts - critical_count - high_count}")
    print(f"{'='*60}{Colors.END}")


# ============================================================
# AFFICHAGE DES RÈGLES
# ============================================================
def show_rules():
    """Affiche toutes les règles de détection actives."""
    print(f"\n{Colors.CYAN}{'='*60}")
    print(f"  📋 Règles de Détection Actives")
    print(f"{'='*60}{Colors.END}\n")
    
    print(f"  {Colors.BOLD}🔒 Brute Force SSH{Colors.END}")
    print(f"     Seuil : 5 tentatives échouées par IP")
    print(f"     Types : Failed password, Invalid user\n")
    
    print(f"  {Colors.BOLD}🔍 Scans de Ports/Web{Colors.END}")
    print(f"     Seuil : 10 chemins uniques + ratio d'erreurs > 50%\n")
    
    print(f"  {Colors.BOLD}💉 SQL Injection{Colors.END}")
    for pattern, desc in DetectionRules.SQL_INJECTION_PATTERNS:
        print(f"     → {desc}")
    print()
    
    print(f"  {Colors.BOLD}🎭 XSS (Cross-Site Scripting){Colors.END}")
    for pattern, desc in DetectionRules.XSS_PATTERNS:
        print(f"     → {desc}")
    print()
    
    print(f"  {Colors.BOLD}📁 Path Traversal{Colors.END}")
    for pattern, desc in DetectionRules.PATH_TRAVERSAL_PATTERNS:
        print(f"     → {desc}")
    print()
    
    print(f"  {Colors.BOLD}💻 Command Injection{Colors.END}")
    for pattern, desc in DetectionRules.COMMAND_INJECTION_PATTERNS:
        print(f"     → {desc}")
    print()
    
    print(f"  {Colors.BOLD}🤖 User-Agents Suspects{Colors.END}")
    print(f"     → {', '.join(DetectionRules.SUSPICIOUS_USER_AGENTS)}\n")


# ============================================================
# FONCTION PRINCIPALE
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description='LogIDS Detector — Log Analyzer for Intrusion Detection',
        epilog='Exemple : python logids.py analyze --log /var/log/auth.log --type ssh'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commandes')
    
    # analyze
    analyze_parser = subparsers.add_parser('analyze', help='Analyser un fichier de log')
    analyze_parser.add_argument('--log', '-l', type=str, required=True, help='Fichier de log')
    analyze_parser.add_argument('--type', '-t', type=str, required=True,
                               choices=['apache', 'nginx', 'ssh'], help='Type de log')
    analyze_parser.add_argument('--brute-force-threshold', type=int, default=5,
                               help='Seuil de brute force (défaut: 5)')
    analyze_parser.add_argument('--port-scan-threshold', type=int, default=10,
                               help='Seuil de scan de ports (défaut: 10)')
    analyze_parser.add_argument('--report', '-r', type=str, default=None,
                               help='Fichier de rapport HTML')
    
    # demo
    subparsers.add_parser('demo', help='Lancer la démonstration')
    
    # rules
    subparsers.add_parser('rules', help='Afficher les règles de détection')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    print_banner()
    
    if args.command == 'demo':
        run_demo()
    
    elif args.command == 'rules':
        show_rules()
    
    elif args.command == 'analyze':
        print(f"{Colors.BLUE}[*] Analyse du fichier : {args.log}{Colors.END}")
        print(f"    Type de log : {args.type.upper()}\n")
        
        # Parsing
        entries = LogParser.parse_file(args.log, args.type)
        total = len(entries)
        
        if total == 0:
            print(f"{Colors.YELLOW}[!] Aucune entrée valide trouvée dans le fichier.{Colors.END}")
            return
        
        print(f"{Colors.GREEN}[✓] {total} entrée(s) parsée(s).{Colors.END}")
        
        # Détection
        detector = IntrusionDetector(
            brute_force_threshold=args.brute_force_threshold,
            port_scan_threshold=args.port_scan_threshold
        )
        alerts = detector.run_all_detections(entries, args.type)
        
        # Affichage des alertes
        if not alerts:
            print(f"\n{Colors.GREEN}[✓] Aucune alerte détectée. Le système semble sûr.{Colors.END}")
        else:
            print(f"\n{Colors.RED}[!] {len(alerts)} alerte(s) détectée(s) :{Colors.END}\n")
            
            for alert in alerts:
                severity = alert.get('severity', 'Low')
                color = {
                    'Critical': Colors.RED + Colors.BOLD,
                    'High': Colors.RED,
                    'Medium': Colors.YELLOW,
                    'Low': Colors.CYAN
                }.get(severity, Colors.END)
                
                print(f"  {color}[{severity.upper()}] {alert.get('type', 'Unknown')}{Colors.END}")
                print(f"       → {alert.get('description', '')}")
                if alert.get('recommendation'):
                    print(f"       💡 {alert['recommendation']}")
                print()
            
            # Rapport HTML
            if args.report:
                generate_html_report(alerts, args.log, args.type, total, args.report)


if __name__ == '__main__':
    main()
