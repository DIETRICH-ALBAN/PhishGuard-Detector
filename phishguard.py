#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PhishGuard Detector — Détecteur d'URLs de phishing
Auteur : Jamein N. Dietrich A.
Projet personnel de cybersécurité

Analyse les URLs pour détecter les tentatives de phishing
basées sur des heuristiques et des patterns connus.
"""

import re
import argparse
from urllib.parse import urlparse, unquote
from typing import Dict, List, Tuple


class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


# ============================================================
# BASE DE DOMAINES LÉGITIMES
# ============================================================
LEGITIMATE_DOMAINS = {
    'google.com', 'gmail.com', 'youtube.com', 'facebook.com', 'instagram.com',
    'twitter.com', 'x.com', 'linkedin.com', 'amazon.com', 'apple.com',
    'microsoft.com', 'paypal.com', 'netflix.com', 'spotify.com',
    'github.com', 'stackoverflow.com', 'wikipedia.org', 'yahoo.com',
    'outlook.com', 'hotmail.com', 'live.com', 'orange.fr', 'sfr.fr',
    'free.fr', 'bouyguestelecom.fr', 'bnpparibas.com', 'creditagricole.fr',
    'societegenerale.com', 'labanquepostale.fr', 'ameli.fr', 'impots.gouv.fr',
}

# Mots-clés suspects dans les URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
    'password', 'credential', 'banking', 'wallet', 'authenticate',
    'suspend', 'unlock', 'restore', 'validate', 'alert',
    'connexion', 'verification', 'securite', 'compte', 'motdepasse',
]

# Extensions de domaine à risque
RISKY_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.buzz']

# Marques couramment usurpées
SPOOFED_BRANDS = [
    'paypal', 'google', 'apple', 'microsoft', 'amazon', 'facebook',
    'netflix', 'spotify', 'instagram', 'twitter', 'linkedin',
    'credit-agricole', 'bnpparibas', 'societe-generale', 'labanquepostale',
]


class PhishGuard:
    """Détecteur d'URLs de phishing par analyse heuristique."""
    
    def __init__(self):
        self.scores = {
            'domain_mismatch': 30,
            'suspicious_subdomain': 20,
            'risky_tld': 25,
            'ip_address': 35,
            'suspicious_keywords': 15,
            'brand_spoofing': 30,
            'excessive_subdomains': 20,
            'homograph_attack': 25,
            'url_shortener': 10,
            'special_chars': 10,
            'long_url': 10,
            'port_in_url': 15,
            'at_symbol': 35,
        }
    
    def analyze(self, url: str) -> Dict:
        """Analyse complète d'une URL."""
        result = {
            'url': url,
            'risk_score': 0,
            'risk_level': 'Low',
            'indicators': [],
            'parsed': None,
            'recommendation': '',
        }
        
        try:
            parsed = urlparse(url)
            result['parsed'] = {
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'path': parsed.path,
                'hostname': parsed.hostname or '',
            }
        except Exception:
            result['indicators'].append(('URL invalide', 50))
            result['risk_score'] = 100
            result['risk_level'] = 'Critical'
            return result
        
        hostname = parsed.hostname or ''
        
        # 1. Domain mismatch (marque dans le chemin mais pas dans le domaine)
        for brand in SPOOFED_BRANDS:
            if brand in hostname.lower() and brand not in self._get_root_domain(hostname).lower():
                if self._get_root_domain(hostname) not in LEGITIMATE_DOMAINS:
                    result['indicators'].append((f'Marque usurpée : {brand}', self.scores['brand_spoofing']))
                    result['risk_score'] += self.scores['brand_spoofing']
        
        # 2. Sous-domaine suspect (marque en sous-domaine, domaine différent)
        for brand in SPOOFED_BRANDS:
            if brand in hostname.split('.')[0].lower():
                root = self._get_root_domain(hostname)
                if root not in LEGITIMATE_DOMAINS:
                    result['indicators'].append((f'Sous-domaine suspect : {brand}.{root}', self.scores['suspicious_subdomain']))
                    result['risk_score'] += self.scores['suspicious_subdomain']
        
        # 3. Extension à risque
        for tld in RISKY_TLDS:
            if hostname.endswith(tld):
                result['indicators'].append((f'Extension à risque : {tld}', self.scores['risky_tld']))
                result['risk_score'] += self.scores['risky_tld']
                break
        
        # 4. Adresse IP au lieu d'un nom de domaine
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
            result['indicators'].append(('Adresse IP utilisée au lieu d\'un domaine', self.scores['ip_address']))
            result['risk_score'] += self.scores['ip_address']
        
        # 5. Mots-clés suspects dans l'URL
        url_lower = url.lower()
        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
        if found_keywords:
            result['indicators'].append((f'Mots-clés suspects : {", ".join(found_keywords)}', self.scores['suspicious_keywords']))
            result['risk_score'] += self.scores['suspicious_keywords']
        
        # 6. Sous-domaines excessifs
        subdomain_count = len(hostname.split('.')) - 2
        if subdomain_count > 3:
            result['indicators'].append((f'Sous-domaines excessifs ({subdomain_count})', self.scores['excessive_subdomains']))
            result['risk_score'] += self.scores['excessive_subdomains']
        
        # 7. Attaque par homoglyphe (caractères similaires)
        homoglyphs = {'0': 'o', '1': 'l', 'rn': 'm', 'vv': 'w', 'l1': 'll'}
        for fake, real in homoglyphs.items():
            if fake in hostname.lower():
                # Vérifier si en remplaçant on obtient un domaine légitime
                test_domain = hostname.lower().replace(fake, real)
                if self._get_root_domain(test_domain) in LEGITIMATE_DOMAINS:
                    result['indicators'].append((f'Homoglyphe détecté : "{fake}" → "{real}" (imitation de domaine légitime)', self.scores['homograph_attack']))
                    result['risk_score'] += self.scores['homograph_attack']
                    break
        
        # 8. Symbole @ dans l'URL (redirection cachée)
        if '@' in url:
            result['indicators'].append(('Symbole @ détecté (redirection cachée)', self.scores['at_symbol']))
            result['risk_score'] += self.scores['at_symbol']
        
        # 9. URL très longue
        if len(url) > 150:
            result['indicators'].append((f'URL très longue ({len(url)} caractères)', self.scores['long_url']))
            result['risk_score'] += self.scores['long_url']
        
        # 10. Port non standard
        if parsed.port and parsed.port not in (80, 443, 8080, 8443):
            result['indicators'].append((f'Port non standard : {parsed.port}', self.scores['port_in_url']))
            result['risk_score'] += self.scores['port_in_url']
        
        # 11. Caractères encodés suspects
        decoded = unquote(url)
        if decoded != url:
            if any(c in decoded for c in ['@', '//', '..', ';']):
                result['indicators'].append(('Caractères encodés suspects dans l\'URL', self.scores['special_chars']))
                result['risk_score'] += self.scores['special_chars']
        
        # Niveau de risque
        score = min(result['risk_score'], 100)
        result['risk_score'] = score
        if score >= 60:
            result['risk_level'] = 'Critical'
            result['recommendation'] = 'NE PAS cliquer — Probable phishing'
        elif score >= 35:
            result['risk_level'] = 'High'
            result['recommendation'] = 'Fortement suspect — Éviter'
        elif score >= 15:
            result['risk_level'] = 'Medium'
            result['recommendation'] = 'Suspicion modérée — Vérifier manuellement'
        else:
            result['risk_level'] = 'Low'
            result['recommendation'] = 'Semble légitime — Toujours vérifier le certificat SSL'
        
        return result
    
    def _get_root_domain(self, hostname: str) -> str:
        """Extrait le domaine racine."""
        parts = hostname.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return hostname
    
    def analyze_batch(self, urls: List[str]) -> List[Dict]:
        """Analyse un lot d'URLs."""
        results = []
        for url in urls:
            results.append(self.analyze(url))
        return sorted(results, key=lambda x: x['risk_score'], reverse=True)


def print_banner():
    print(f"""
{Colors.CYAN}{Colors.BOLD}
  ╔═══════════════════════════════════════════════════════╗
  ║       🛡️ PhishGuard Detector v1.0                    ║
  ║     Phishing URL Detection Tool                      ║
  ║     by Jamein N. Dietrich A.                         ║
  ╚═══════════════════════════════════════════════════════╝
{Colors.END}""")


def main():
    parser = argparse.ArgumentParser(description='PhishGuard Detector')
    subparsers = parser.add_subparsers(dest='command')
    
    check = subparsers.add_parser('check', help='Analyser une URL')
    check.add_argument('--url', '-u', type=str, required=True)
    
    batch = subparsers.add_parser('batch', help='Analyser un fichier d\'URLs')
    batch.add_argument('--file', '-f', type=str, required=True)
    
    subparsers.add_parser('demo', help='Démonstration')
    
    args = parser.parse_args()
    print_banner()
    
    guard = PhishGuard()
    
    if args.command == 'check':
        result = guard.analyze(args.url)
        level = result['risk_level']
        color = {'Critical': Colors.RED, 'High': Colors.RED, 'Medium': Colors.YELLOW, 'Low': Colors.GREEN}.get(level, '')
        print(f"  URL     : {result['url']}")
        print(f"  Risque  : {color}[{level}] ({result['risk_score']}/100){Colors.END}")
        for indicator, score in result['indicators']:
            print(f"    → {indicator} (+{score})")
        print(f"  {Colors.GREEN}💡 {result['recommendation']}{Colors.END}")
    
    elif args.command == 'batch':
        import os
        if not os.path.exists(args.file):
            print(f"{Colors.RED}[!] Fichier non trouvé{Colors.END}")
            return
        with open(args.file) as f:
            urls = [l.strip() for l in f if l.strip()]
        results = guard.analyze_batch(urls)
        for r in results:
            level = r['risk_level']
            color = {'Critical': Colors.RED, 'High': Colors.RED, 'Medium': Colors.YELLOW, 'Low': Colors.GREEN}.get(level, '')
            print(f"  {color}[{level}] ({r['risk_score']:3d}/100){Colors.END} {r['url'][:80]}")
    
    elif args.command == 'demo':
        test_urls = [
            'https://www.google.com/search?q=test',
            'https://paypal-login.secure-verify.xyz/account/signin',
            'http://192.168.1.1/admin/login',
            'https://g00gle.com/search',
            'https://www.credit-agricole.fr/connexion',
            'https://amazon.update-account.security-check.tk/verify',
            'https://user@evil.com/https://paypal.com',
        ]
        results = guard.analyze_batch(test_urls)
        for r in results:
            level = r['risk_level']
            color = {'Critical': Colors.RED, 'High': Colors.RED, 'Medium': Colors.YELLOW, 'Low': Colors.GREEN}.get(level, '')
            print(f"  {color}[{level:>8}] ({r['risk_score']:3d}/100){Colors.END} {r['url'][:70]}")
            for indicator, score in r['indicators'][:2]:
                print(f"           → {indicator}")
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
