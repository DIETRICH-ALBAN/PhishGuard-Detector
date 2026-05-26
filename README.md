# 🛡️ LogIDS Detector — Log Analyzer for Intrusion Detection

> **Auteur** : Jamein N. Dietrich A.  
> **Contexte** : Projet personnel en cybersécurité — Analyse de logs et détection d'intrusions

## 📋 Description

LogIDS Detector est un outil Python d'analyse de logs système qui permet de :

- **Parser les logs** Apache, Nginx, SSH, et auth.log (Linux)
- **Détecter les tentatives de brute force** (multiples échecs de connexion depuis une même IP)
- **Identifier les scans de ports** (tentatives de connexion sur de nombreux ports)
- **Repérer les injections SQL et XSS** dans les requêtes HTTP
- **Détecter les accès suspects** (heures inhabituelles, géolocalisation anormale)
- **Générer des alertes** et des rapports de sécurité structurés
- **Visualiser les tendances temporelles** des événements de sécurité

## 🎯 Compétences cybersécurité démontrées

| Compétence | Mise en œuvre |
|-----------|---------------|
| SIEM & monitoring | Analyse de logs centralisée |
| Détection d'intrusion (IDS) | Règles de détection de patterns d'attaque |
| Forensique numérique | Analyse post-incident des traces |
| Brute force detection | Seuil de tentatives échouées par IP |
| Web Application Security | Détection d'injections SQL/XSS dans les logs |
| Threat Intelligence | Corrélation IP/patterns d'attaque connus |
| Reporting de sécurité | Génération de rapports d'incidents |

## ⚙️ Installation

```bash
git clone https://github.com/<votre-username>/logids-detector.git
cd logids-detector
pip install -r requirements.txt
```

## 🚀 Utilisation

```bash
# Analyser un log Apache/Nginx
python logids.py analyze --log /var/log/apache2/access.log --type apache

# Analyser un log SSH
python logids.py analyze --log /var/log/auth.log --type ssh

# Analyser avec seuils personnalisés
python logids.py analyze --log access.log --type apache --brute-force-threshold 10 --port-scan-threshold 15

# Générer un rapport complet
python logids.py analyze --log access.log --type apache --report rapport_securite.html

# Analyser avec les logs de démo intégrés
python logids.py demo

# Lister les règles de détection actives
python logids.py rules
```

## ⚠️ Avertissement éthique

Cet outil est conçu pour l'analyse de **vos propres logs** ou de logs que vous êtes autorisé à analyser. La surveillance non autorisée de systèmes est illégale.

## 📜 Licence

MIT License — Libre d'utilisation à des fins éducatives.
