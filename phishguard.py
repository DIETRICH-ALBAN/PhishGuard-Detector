#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PhishGuard Detector - Detecteur d'URL de phishing par heuristiques
Auteur : Jamein N. Dietrich A.

Outil educatif pour :
- Analyser des URLs et detecter les tentatives de phishing
- Detecter les usurpations de domaine (domain mismatch)
- Identifier les TLD a risque
- Detecter l'usurpation de marques connues
- Detecter les attaques par homoglyphes
- Analyser des fichiers d'URLs en lot
- Scorer le risque de chaque URL (0-100)
- Mode demonstration avec URLs de test
"""

import argparse
import re
import sys
import os
import unicodedata
from urllib.parse import urlparse, unquote


# ============================================================
# SECTION : Donnees de reference
# ============================================================

# Domaines legitimes des marques connues
MARQUES_CONNUES = {
    "google": ["google.com", "google.fr", "google.ca"],
    "paypal": ["paypal.com", "paypal.fr"],
    "amazon": ["amazon.com", "amazon.fr", "amazon.ca"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com", "hotmail.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "netflix": ["netflix.com"],
    "bankofamerica": ["bankofamerica.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "societe_generale": ["societegenerale.com", "societegenerale.fr"],
    "bnpparibas": ["bnpparibas.com", "bnpparibas.fr"],
    "credit_agricole": ["credit-agricole.fr", "creditagricole.fr"],
    "banque_populaire": ["banquepopulaire.fr"],
    "labanquepostale": ["labanquepostale.fr"],
    "ameli": ["ameli.fr"],
    "impots": ["impots.gouv.fr"],
    "laposte": ["laposte.fr", "laposte.net"],
    "orange": ["orange.fr"],
    "sfr": ["sfr.fr"],
    "free": ["free.fr"],
    "bouyguestelecom": ["bouyguestelecom.fr"],
}

# TLD a risque eleve (souvent utilises pour le phishing)
TLDS_RISQUE = {
    ".tk": 15, ".ml": 15, ".ga": 15, ".cf": 15, ".gq": 15,
    ".xyz": 10, ".top": 10, ".club": 10, ".work": 10, ".bid": 10,
    ".loan": 10, ".click": 10, ".link": 10, ".pw": 10, ".cc": 8,
    ".ru": 5, ".cn": 5, ".br": 5, ".in": 5, ".info": 5,
    ".biz": 5, ".online": 5, ".site": 5, ".website": 5, ".space": 5,
}

# Caracteres homoglyphes (caracteres qui se ressemblent mais sont differents)
HOMOGLYPHES = {
    "a": ["\u0430", "\u00e0", "\u00e1", "\u00e2", "\u00e3"],  # a cyrillique, a accent
    "c": ["\u0441", "\u00e7"],  # c cyrillique
    "e": ["\u0435", "\u00e8", "\u00e9", "\u00ea", "\u00eb"],  # e cyrillique
    "i": ["\u0456", "\u00ec", "\u00ed", "\u00ee", "\u00ef", "l", "1"],  # i cyrillique
    "o": ["\u043e", "\u00f2", "\u00f3", "\u00f4", "\u00f5", "0"],  # o cyrillique
    "p": ["\u0440"],  # p cyrillique
    "s": ["\u0455"],  # s cyrillique
    "x": ["\u0445"],  # x cyrillique
    "y": ["\u0443"],  # y cyrillique
    "n": ["\u043d"],  # n cyrillique
    "d": ["\u0501"],  # d cyrillique
    "h": ["\u043d"],  # h lookalike
    "m": ["\u043c", "rn"],  # m cyrillique
    "w": ["vv"],  # w lookalike
    "l": ["1", "i", "|"],  # l lookalike
}

# Mots cles suspects dans les URLs
MOTS_CLES_SUSPECTS = [
    "secure", "login", "signin", "verify", "account", "update",
    "confirm", "validate", "wallet", "suspend", "unlock",
    "restore", "recover", "alert", "notification", "service",
    "support", "helpdesk", "security", "authenticate",
    "connexion", "verification", "securite", "compte",
    "mise-a-jour", "confirmer", "valider", "alerte",
]


# ============================================================
# SECTION : Fonctions d'analyse
# ============================================================

def extraire_domaine(url):
    """
    Extrait le domaine principal d'une URL.

    Args:
        url (str): URL a analyser

    Returns:
        str: Domaine extrait
    """
    # Ajouter un schema si absent
    if not url.startswith(("http://", "https://", "ftp://")):
        url = "http://" + url

    parse = urlparse(url)
    domaine = parse.netloc

    # Retirer le port si present
    if ":" in domaine:
        domaine = domaine.split(":")[0]

    # Retirer www.
    if domaine.startswith("www."):
        domaine = domaine[4:]

    return domaine.lower()


def verifier_tld_risque(domaine):
    """
    Verifie si le domaine utilise un TLD a risque.

    Args:
        domaine (str): Domaine a verifier

    Returns:
        tuple: (risque_detecte: bool, score: int, tld: str)
    """
    for tld, score in TLDS_RISQUE.items():
        if domaine.endswith(tld):
            return True, score, tld
    return False, 0, ""


def verifier_usurpation_marque(domaine):
    """
    Verifie si le domaine tente d'usurper une marque connue.

    Args:
        domaine (str): Domaine a verifier

    Returns:
        list: Liste des marques potentiellement usurpees avec details
    """
    usurpations = []

    for marque, domaines_legitimes in MARQUES_CONNUES.items():
        # Verifier si le nom de la marque apparait dans le domaine
        # mais le domaine n'est pas un domaine legitime
        if marque in domaine:
            est_legitime = any(
                domaine == dl or domaine.endswith("." + dl)
                for dl in domaines_legitimes
            )
            if not est_legitime:
                # Verifier les patterns suspects : marque + suffixe/mot suspect
                for dl in domaines_legitimes:
                    if marque in domaine and dl not in domaine:
                        # La marque est presente mais pas le domaine legitime
                        usurpations.append({
                            "marque": marque,
                            "domaine_legitime": dl,
                            "type": "marque_incluse_domaine_inconnu"
                        })
                        break

    return usurpations


def verifier_homoglyphes(domaine):
    """
    Detecte les attaques par homoglyphes dans un domaine.
    Les homoglyphes sont des caracteres qui se ressemblent visuellement
    mais ont des codes Unicode differents.

    Args:
        domaine (str): Domaine a verifier

    Returns:
        list: Liste des homoglyphes detectes
    """
    homoglyphes_detectes = []

    for i, caractere in enumerate(domaine):
        # Verifier si le caractere est un caractere non-ASCII
        if ord(caractere) > 127:
            # Trouver le caractere ASCII correspondant
            for ascii_char, homoglyphes_list in HOMOGLYPHES.items():
                if caractere in homoglyphes_list:
                    homoglyphes_detectes.append({
                        "position": i,
                        "caractere_original": caractere,
                        "caractere_remplacement": ascii_char,
                        "unicode": f"U+{ord(caractere):04X}",
                        "description": f"Caractere '{caractere}' (U+{ord(caractere):04X}) "
                                       f"ressemble a '{ascii_char}'"
                    })

    return homoglyphes_detectes


def verifier_mots_cles_suspects(url):
    """
    Verifie la presence de mots cles suspects dans l'URL.

    Args:
        url (str): URL a verifier

    Returns:
        list: Mots cles suspects trouves
    """
    url_lower = url.lower()
    mots_trouves = []

    for mot in MOTS_CLES_SUSPECTS:
        # Recherche dans le chemin et les parametres
        if mot in url_lower:
            mots_trouves.append(mot)

    return mots_trouves


def verifier_sous_domaines_suspects(domaine):
    """
    Verifie les sous-domaines suspects (ex: paypal.evil.com).

    Args:
        domaine (str): Domaine a verifier

    Returns:
        list: Sous-domaines suspects detectes
    """
    suspects = []
    parties = domaine.split(".")

    if len(parties) > 2:
        # Verifier si un sous-domaine contient le nom d'une marque
        for marque in MARQUES_CONNUES:
            if marque in parties[0]:
                # Le sous-domaine contient une marque mais le domaine principal est different
                domaine_principal = ".".join(parties[-2:])
                est_legitime = any(
                    domaine_principal == dl for dl in MARQUES_CONNUES[marque]
                )
                if not est_legitime:
                    suspects.append({
                        "sous_domaine": parties[0],
                        "marque": marque,
                        "domaine_principal": domaine_principal,
                        "description": f"Sous-domaine '{parties[0]}' contient la marque "
                                       f"'{marque}' sur un domaine non legitime"
                    })

    return suspects


def verifier_url_courte(url):
    """
    Verifie si l'URL utilise un service de raccourcissement.

    Args:
        url (str): URL a verifier

    Returns:
        bool: True si c'est une URL raccourcie
    """
    services_raccourcissement = [
        "bit.ly", "t.co", "tinyurl.com", "goo.gl",
        "ow.ly", "is.gd", "buff.ly", "adf.ly",
        "shorte.st", "tiny.cc", "bit.do"
    ]

    domaine = extraire_domaine(url)
    return domaine in services_raccourcissement


def verifier_adresse_ip(url):
    """
    Verifie si l'URL utilise une adresse IP au lieu d'un nom de domaine.

    Args:
        url (str): URL a verifier

    Returns:
        bool: True si c'est une adresse IP
    """
    domaine = extraire_domaine(url)
    pattern_ip = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    return bool(re.match(pattern_ip, domaine))


def calculer_score_risque(url):
    """
    Calcule le score de risque d'une URL (0-100).
    Plus le score est eleve, plus l'URL est suspecte.

    Args:
        url (str): URL a analyser

    Returns:
        dict: Analyse complete avec score et details
    """
    score = 0
    details = []

    # 1. Verification du TLD
    domaine = extraire_domaine(url)
    risque_tld, score_tld, tld = verifier_tld_risque(domaine)
    if risque_tld:
        score += score_tld
        details.append(f"TLD a risque detecte : {tld} (+{score_tld})")

    # 2. Verification d'usurpation de marque
    usurpations = verifier_usurpation_marque(domaine)
    if usurpations:
        score += 25
        for usp in usurpations:
            details.append(
                f"Usurpation de marque '{usp['marque']}' detectee "
                f"(domaine legitime : {usp['domaine_legitime']}) (+25)"
            )

    # 3. Verification des homoglyphes
    homoglyphes = verifier_homoglyphes(domaine)
    if homoglyphes:
        score += 20
        for hg in homoglyphes:
            details.append(f"Homoglyphe detecte : {hg['description']} (+20)")

    # 4. Verification des sous-domaines suspects
    sous_domaines = verifier_sous_domaines_suspects(domaine)
    if sous_domaines:
        score += 20
        for sd in sous_domaines:
            details.append(f"Sous-domaine suspect : {sd['description']} (+20)")

    # 5. Verification des mots cles suspects
    mots_suspects = verifier_mots_cles_suspects(url)
    if mots_suspects:
        score += min(len(mots_suspects) * 5, 15)
        details.append(
            f"Mots cles suspects : {', '.join(mots_suspects)} "
            f"(+{min(len(mots_suspects) * 5, 15)})"
        )

    # 6. Verification des URLs raccourcies
    if verifier_url_courte(url):
        score += 10
        details.append("URL raccourcie detectee (+10)")

    # 7. Verification d'adresse IP
    if verifier_adresse_ip(url):
        score += 15
        details.append("Adresse IP utilisee au lieu d'un domaine (+15)")

    # 8. Longueur suspecte de l'URL
    if len(url) > 100:
        score += 5
        details.append("URL anormalement longue (+5)")

    # 9. Nombre de sous-domaines
    parties = domaine.split(".")
    if len(parties) > 3:
        score += 5
        details.append(f"Nombreux sous-domaines ({len(parties)}) (+5)")

    # 10. Parametres suspects
    parse = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)
    if parse.query:
        if "redirect" in parse.query.lower() or "url=" in parse.query.lower():
            score += 10
            details.append("Parametre de redirection detecte (+10)")

    # Limitation du score
    score = min(score, 100)

    # Classification du risque
    if score >= 75:
        niveau_risque = "CRITIQUE"
    elif score >= 50:
        niveau_risque = "ELEVE"
    elif score >= 25:
        niveau_risque = "MOYEN"
    else:
        niveau_risque = "FAIBLE"

    return {
        "url": url,
        "domaine": domaine,
        "score": score,
        "niveau_risque": niveau_risque,
        "details": details,
        "usurpations": usurpations,
        "homoglyphes": homoglyphes,
        "sous_domaines_suspects": sous_domaines,
        "mots_cles_suspects": mots_suspects,
        "tld_risque": tld if risque_tld else None,
        "url_raccourcie": verifier_url_courte(url),
        "utilise_ip": verifier_adresse_ip(url),
    }


def afficher_analyse_url(resultat):
    """
    Affiche le resultat d'une analyse d'URL.

    Args:
        resultat (dict): Resultat de l'analyse
    """
    url = resultat["url"]
    print(f"\n{'='*65}")
    print(f"  Analyse de l'URL : {url}")
    print(f"{'='*65}")
    print(f"  Domaine           : {resultat['domaine']}")
    print(f"  Score de risque   : {resultat['score']}/100")
    print(f"  Niveau de risque  : {resultat['niveau_risque']}")

    if resultat["details"]:
        print(f"\n  --- Details de l'analyse ---")
        for detail in resultat["details"]:
            print(f"  [!] {detail}")

    if resultat["usurpations"]:
        print(f"\n  --- Usurpations de marque ---")
        for usp in resultat["usurpations"]:
            print(f"  [-] Marque : {usp['marque']} "
                  f"| Domaine legitime : {usp['domaine_legitime']}")

    if resultat["homoglyphes"]:
        print(f"\n  --- Homoglyphes detectes ---")
        for hg in resultat["homoglyphes"]:
            print(f"  [-] {hg['description']}")

    if resultat["sous_domaines_suspects"]:
        print(f"\n  --- Sous-domaines suspects ---")
        for sd in resultat["sous_domaines_suspects"]:
            print(f"  [-] {sd['description']}")

    if resultat["mots_cles_suspects"]:
        print(f"\n  --- Mots cles suspects ---")
        for mot in resultat["mots_cles_suspects"]:
            print(f"  [-] {mot}")

    if resultat["tld_risque"]:
        print(f"\n  [!] TLD a risque : {resultat['tld_risque']}")

    if resultat["url_raccourcie"]:
        print(f"  [!] URL raccourcie detectee")

    if resultat["utilise_ip"]:
        print(f"  [!] Adresse IP utilisee au lieu d'un domaine")

    if not resultat["details"]:
        print(f"\n  Aucun indicateur de phishing detecte.")

    print(f"{'='*65}")


# ============================================================
# SECTION : Mode demonstration
# ============================================================

def generer_urls_demo():
    """
    Genere une liste d'URLs de test pour la demonstration.

    Returns:
        list: Liste d'URLs avec leur categorie
    """
    urls_test = [
        # URLs legitimes
        {"url": "https://www.google.com/search?q=test", "categorie": "legitime"},
        {"url": "https://www.amazon.fr/produit/12345", "categorie": "legitime"},
        {"url": "https://paypal.com/signin", "categorie": "legitime"},
        {"url": "https://www.societegenerale.fr/particuliers", "categorie": "legitime"},

        # URLs de phishing - usurpation de marque
        {"url": "https://paypal-secure.verify-account.com/login", "categorie": "phishing"},
        {"url": "https://amazon.update-info.xyz/confirm", "categorie": "phishing"},
        {"url": "http://apple-id-verify.apple.security-check.net/auth", "categorie": "phishing"},
        {"url": "https://microsoft-login.secure-account.tk/signin", "categorie": "phishing"},

        # URLs de phishing - sous-domaine suspect
        {"url": "https://paypal.evil-website.com/verify", "categorie": "phishing"},
        {"url": "https://google.malicious-site.ru/login", "categorie": "phishing"},

        # URLs de phishing - TLD a risque
        {"url": "https://secure-bank.xyz/login", "categorie": "phishing"},
        {"url": "https://myaccount-update.top/verify", "categorie": "phishing"},

        # URLs de phishing - adresse IP
        {"url": "http://192.168.1.100/bankofamerica/login", "categorie": "phishing"},

        # URLs de phishing - mots cles suspects
        {"url": "https://random-site.com/secure/login/verify-account", "categorie": "phishing"},
        {"url": "https://example.com/wallet/suspend/restore", "categorie": "phishing"},

        # URLs raccourcies
        {"url": "https://bit.ly/3xYz123", "categorie": "suspect"},
        {"url": "https://tinyurl.com/abc123def", "categorie": "suspect"},
    ]

    return urls_test


def executer_demo():
    """Execute le mode demonstration avec des URLs de test."""
    print("\n" + "=" * 65)
    print("  PhishGuard Detector - Mode Demonstration")
    print("  Auteur : Jamein N. Dietrich A.")
    print("=" * 65)
    print("\n  Analyse d'URLs de test...\n")

    urls_test = generer_urls_demo()

    resultats = []
    for item in urls_test:
        resultat = calculer_score_risque(item["url"])
        resultat["categorie_attendue"] = item["categorie"]
        resultats.append(resultat)

    # Affichage synthetique
    print(f"  {'URL':<55} {'Score':>5} {'Niveau':<10} {'Attendu':<10}")
    print(f"  {'-'*55} {'-'*5} {'-'*10} {'-'*10}")

    for r in resultats:
        url_affiche = r["url"][:52] + "..." if len(r["url"]) > 55 else r["url"]
        print(f"  {url_affiche:<55} {r['score']:>5} {r['niveau_risque']:<10} "
              f"{r['categorie_attendue']:<10}")

    # Statistiques
    print(f"\n  --- Statistiques ---")
    phishing_detecte = sum(
        1 for r in resultats
        if r["categorie_attendue"] == "phishing" and r["score"] >= 50
    )
    phishing_total = sum(
        1 for r in resultats if r["categorie_attendue"] == "phishing"
    )
    faux_positifs = sum(
        1 for r in resultats
        if r["categorie_attendue"] == "legitime" and r["score"] >= 50
    )
    legitime_total = sum(
        1 for r in resultats if r["categorie_attendue"] == "legitime"
    )

    print(f"  Phishing detecte (score >= 50) : {phishing_detecte}/{phishing_total}")
    print(f"  Faux positifs (legitime >= 50) : {faux_positifs}/{legitime_total}")

    # Analyse detaillee de quelques URLs
    print(f"\n  --- Analyses detaillees ---")
    for r in resultats[:5]:
        afficher_analyse_url(r)


# ============================================================
# SECTION : Analyse par lot
# ============================================================

def analyser_fichier_urls(chemin_fichier):
    """
    Analyse un fichier contenant une URL par ligne.

    Args:
        chemin_fichier (str): Chemin du fichier d'URLs
    """
    if not os.path.isfile(chemin_fichier):
        print(f"[!] Fichier non trouve : {chemin_fichier}")
        return

    with open(chemin_fichier, "r", encoding="utf-8", errors="ignore") as f:
        lignes = f.readlines()

    urls = [ligne.strip() for ligne in lignes if ligne.strip() and not ligne.startswith("#")]

    if not urls:
        print("[!] Aucune URL valide trouvee dans le fichier.")
        return

    print(f"\n[*] Analyse de {len(urls)} URLs depuis {chemin_fichier}...\n")

    resultats = []
    for url in urls:
        resultat = calculer_score_risque(url)
        resultats.append(resultat)

    # Affichage synthetique
    print(f"  {'URL':<55} {'Score':>5} {'Niveau':<10}")
    print(f"  {'-'*55} {'-'*5} {'-'*10}")

    for r in resultats:
        url_affiche = r["url"][:52] + "..." if len(r["url"]) > 55 else r["url"]
        print(f"  {url_affiche:<55} {r['score']:>5} {r['niveau_risque']:<10}")

    # Resume
    niveaux = {"CRITIQUE": 0, "ELEVE": 0, "MOYEN": 0, "FAIBLE": 0}
    for r in resultats:
        niveaux[r["niveau_risque"]] += 1

    print(f"\n  --- Resume ---")
    print(f"  Total analysees : {len(resultats)}")
    for niveau, count in niveaux.items():
        print(f"  {niveau:<10} : {count}")

    # URLs les plus dangereuses
    resultats_tries = sorted(resultats, key=lambda x: -x["score"])
    if resultats_tries and resultats_tries[0]["score"] >= 50:
        print(f"\n  --- URLs les plus dangereuses ---")
        for r in resultats_tries[:5]:
            if r["score"] >= 50:
                print(f"  [!] {r['url']} (Score: {r['score']}/100 - {r['niveau_risque']})")


# ============================================================
# SECTION : Interface CLI
# ============================================================

def main():
    """Point d'entree principal du programme."""
    parser = argparse.ArgumentParser(
        description="PhishGuard Detector - Detecteur d'URL de phishing par heuristiques",
        epilog="Auteur : Jamein N. Dietrich A. | Usage educatif uniquement"
    )

    parser.add_argument(
        "-u", "--url",
        type=str,
        default=None,
        help="URL a analyser"
    )

    parser.add_argument(
        "-f", "--fichier",
        type=str,
        default=None,
        help="Fichier contenant des URLs a analyser (une par ligne)"
    )

    parser.add_argument(
        "-d", "--demo",
        action="store_true",
        help="Executer en mode demonstration avec URLs de test"
    )

    args = parser.parse_args()

    if args.demo:
        executer_demo()
    elif args.url:
        resultat = calculer_score_risque(args.url)
        afficher_analyse_url(resultat)
    elif args.fichier:
        analyser_fichier_urls(args.fichier)
    else:
        parser.print_help()
        print("\n[!] Specifiez une URL (-u), un fichier (-f) ou le mode demo (-d)")


if __name__ == "__main__":
    main()
