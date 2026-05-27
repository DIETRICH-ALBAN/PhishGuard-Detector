# PhishGuard Detector - Detecteur d'URL de phishing par heuristiques

Auteur : Jamein N. Dietrich A.
Contexte : Projet personnel en cyberscurite - Detection de phishing par analyse heuristique des URLs

## Description

PhishGuard Detector est un outil educatif qui analyse les URLs pour detecter les tentatives de phishing. Il utilise un ensemble d'heuristiques pour evaluee le niveau de risque de chaque URL et identifier les techniques classiques utilisees par les attaquants.

Fonctionnalites principales :
- Detection d'usurpation de domaine (domain mismatch)
- Identification des TLD a risque eleve
- Detection d'usurpation de marques connues
- Detection d'attaques par homoglyphes (caracteres Unicode trompeurs)
- Analyse des mots cles suspects dans les URLs
- Detection des sous-domaines suspects
- Identification des URLs raccourcies et adresses IP
- Analyse par lot depuis un fichier
- Systeme de score de risque (0-100)
- Mode demonstration avec URLs de test

## Competences cyberscurite demontrees

| Competence | Description |
|---|---|
| Analyse de phishing | Identification des URLs malveillantes |
| Heuristiques | Mise en place de regles de detection |
| Usurpation de marque | Detection d'imitation de domaines connus |
| Attaques homoglyphes | Detection de caracteres Unicode trompeurs |
| Scoring de risque | Evaluation quantitative du danger |
| OSINT | Analyse de metadonnees d'URLs |

## Installation

```bash
git clone <url-du-depot>
cd phishguard-detector
```

Aucune dependance externe necessaire - utilise uniquement la bibliotheque standard Python.

## Utilisation

Analyser une URL :
```bash
python3 phishguard.py -u "https://paypal-secure.verify-account.com/login"
```

Analyser un fichier d'URLs :
```bash
python3 phishguard.py -f urls_a_analyser.txt
```

Mode demonstration :
```bash
python3 phishguard.py --demo
```

## Structure du projet

```
phishguard-detector/
  |-- phishguard.py    # Script principal avec toutes les fonctionnalites
  |-- README.md        # Documentation du projet
```

## Avertissement ethique

Cet outil est strictement destine a un usage educatif. Les heuristiques utilisees sont simplifiees a des fins pedagogiques et ne remplacent pas un systeme de detection professionnel. Ne pas utiliser cet outil pour creer des URLs de phishing. L'auteur decline toute responsabilite quant a l'utilisation abusive de cet outil.

## Licence

MIT License
