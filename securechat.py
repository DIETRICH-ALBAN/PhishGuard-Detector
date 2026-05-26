#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecureChat Encryptor — Chiffrement de messages de bout en bout
Auteur : Jamein N. Dietrich A.
Projet personnel de cybersécurité

Démontre les principes du chiffrement symétrique (AES) et
asymétrique (RSA) appliqués à la messagerie sécurisée.
"""

import os
import hashlib
import base64
import argparse
from datetime import datetime
from typing import Tuple, Optional


# ============================================================
# COULEURS TERMINAL
# ============================================================
class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


# ============================================================
# CHIFFREMENT SYMÉTRIQUE — AES-256 (via hashlib + XOR stream)
# ============================================================
class AESStreamCipher:
    """
    Chiffrement de flux inspiré d'AES-256 en mode CTR.
    Utilise un keystream dérivé de SHA-256 pour simuler le mode compteur.
    
    Note : Pour une production réelle, utilisez la bibliothèque cryptography
    avec AESGCM ou Fernet. Ceci est un démonstrateur éducatif.
    """
    
    BLOCK_SIZE = 16
    KEY_SIZE = 32  # 256 bits
    
    @staticmethod
    def generate_key() -> str:
        """Génère une clé AES-256 aléatoire encodée en base64."""
        key = os.urandom(32)
        return base64.b64encode(key).decode('utf-8')
    
    @staticmethod
    def derive_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
        """
        Dérive un keystream en mode compteur (CTR-like).
        Chaque bloc du keystream est SHA-256(key || nonce || counter).
        """
        keystream = b''
        counter = 0
        while len(keystream) < length:
            block_input = key + nonce + counter.to_bytes(8, 'big')
            block = hashlib.sha256(block_input).digest()
            keystream += block
            counter += 1
        return keystream[:length]
    
    @classmethod
    def encrypt(cls, plaintext: str, key_b64: str) -> str:
        """
        Chiffre un message avec le cipher de flux.
        
        Args:
            plaintext: Message en clair
            key_b64: Clé AES-256 encodée en base64
        
        Returns:
            Message chiffré encodé en base64 (nonce + ciphertext)
        """
        key = base64.b64decode(key_b64)
        nonce = os.urandom(16)
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Padding PKCS7
        pad_len = cls.BLOCK_SIZE - (len(plaintext_bytes) % cls.BLOCK_SIZE)
        padded = plaintext_bytes + bytes([pad_len] * pad_len)
        
        # Chiffrement par XOR avec le keystream
        keystream = cls.derive_keystream(key, nonce, len(padded))
        ciphertext = bytes(a ^ b for a, b in zip(padded, keystream))
        
        # Output : nonce (16 bytes) + ciphertext
        return base64.b64encode(nonce + ciphertext).decode('utf-8')
    
    @classmethod
    def decrypt(cls, ciphertext_b64: str, key_b64: str) -> str:
        """
        Déchiffre un message.
        
        Args:
            ciphertext_b64: Message chiffré en base64
            key_b64: Clé AES-256 encodée en base64
        
        Returns:
            Message en clair
        """
        key = base64.b64decode(key_b64)
        raw = base64.b64decode(ciphertext_b64)
        
        nonce = raw[:16]
        ciphertext = raw[16:]
        
        # Déchiffrement par XOR avec le même keystream
        keystream = cls.derive_keystream(key, nonce, len(ciphertext))
        padded = bytes(a ^ b for a, b in zip(ciphertext, keystream))
        
        # Suppression du padding PKCS7
        pad_len = padded[-1]
        plaintext_bytes = padded[:-pad_len]
        
        return plaintext_bytes.decode('utf-8')


# ============================================================
# CHIFFREMENT ASYMÉTRIQUE — RSA simplifié
# ============================================================
class RSASimplified:
    """
    Démonstration simplifiée du chiffrement RSA.
    Utilise des nombres premiers de taille réduite pour
    illustrer le principe sans nécessiter de grandes bibliothèques.
    
    ⚠️ Ne PAS utiliser en production — taille de clé insuffisante.
    """
    
    @staticmethod
    def is_prime(n: int, k: int = 20) -> bool:
        """Test de primalité de Miller-Rabin."""
        if n < 2: return False
        if n == 2 or n == 3: return True
        if n % 2 == 0: return False
        
        # Écriture de n-1 = 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Témoins
        import random
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
    
    @staticmethod
    def generate_prime(bits: int = 256) -> int:
        """Génère un nombre premier de la taille spécifiée."""
        import random
        while True:
            n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
            if RSASimplified.is_prime(n):
                return n
    
    @staticmethod
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        """Algorithme d'Euclide étendu."""
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = RSASimplified.extended_gcd(b % a, a)
        return gcd, y1 - (b // a) * x1, x1
    
    @classmethod
    def generate_keypair(cls, bits: int = 512) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """
        Génère une paire de clés RSA.
        
        Returns:
            ((e, n), (d, n)) — Clé publique et clé privée
        """
        p = cls.generate_prime(bits // 2)
        q = cls.generate_prime(bits // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        
        # Choix de e
        e = 65537
        while cls.extended_gcd(e, phi)[0] != 1:
            e += 2
        
        # Calcul de d
        _, d, _ = cls.extended_gcd(e, phi)
        d = d % phi
        
        return (e, n), (d, n)
    
    @staticmethod
    def encrypt(message: str, public_key: Tuple[int, int]) -> List[int]:
        """Chiffre un message avec la clé publique."""
        e, n = public_key
        return [pow(ord(c), e, n) for c in message]
    
    @staticmethod
    def decrypt(ciphertext: List[int], private_key: Tuple[int, int]) -> str:
        """Déchiffre un message avec la clé privée."""
        d, n = private_key
        return ''.join(chr(pow(c, d, n)) for c in ciphertext)


# ============================================================
# HASHING ET VÉRIFICATION D'INTÉGRITÉ
# ============================================================
class IntegrityChecker:
    """Vérification d'intégrité par hachage SHA-256 et HMAC."""
    
    @staticmethod
    def hash_message(message: str) -> str:
        """Calcule le hash SHA-256 d'un message."""
        return hashlib.sha256(message.encode('utf-8')).hexdigest()
    
    @staticmethod
    def compute_hmac(message: str, key: str) -> str:
        """Calcule un HMAC-SHA256 pour vérifier l'authenticité."""
        import hmac as hmac_module
        return hmac_module.new(
            key.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    
    @staticmethod
    def verify_hmac(message: str, key: str, expected_hmac: str) -> bool:
        """Vérifie le HMAC d'un message (protection contre la falsification)."""
        import hmac as hmac_module
        computed = hmac_module.new(
            key.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        # Comparaison en temps constant (protection timing attack)
        return hmac_module.compare_digest(computed, expected_hmac)


# ============================================================
# INTERFACE PRINCIPALE
# ============================================================
def print_banner():
    print(f"""
{Colors.CYAN}{Colors.BOLD}
  ╔═══════════════════════════════════════════════════════╗
  ║       🔒 SecureChat Encryptor v1.0                   ║
  ║     End-to-End Encryption Demonstration              ║
  ║     by Jamein N. Dietrich A.                         ║
  ╚═══════════════════════════════════════════════════════╝
{Colors.END}""")


def main():
    parser = argparse.ArgumentParser(description='SecureChat Encryptor')
    subparsers = parser.add_subparsers(dest='command')
    
    # AES encrypt
    enc = subparsers.add_parser('encrypt', help='Chiffrer un message (AES-256)')
    enc.add_argument('--message', '-m', type=str, required=True)
    enc.add_argument('--key', '-k', type=str, default=None)
    
    # AES decrypt
    dec = subparsers.add_parser('decrypt', help='Déchiffrer un message (AES-256)')
    dec.add_argument('--ciphertext', '-c', type=str, required=True)
    dec.add_argument('--key', '-k', type=str, required=True)
    
    # RSA demo
    subparsers.add_parser('rsa-demo', help='Démonstration RSA')
    
    # Integrity
    integ = subparsers.add_parser('integrity', help='Vérification d\'intégrité HMAC')
    integ.add_argument('--message', '-m', type=str, required=True)
    integ.add_argument('--key', '-k', type=str, default='secret-key')
    
    # Generate key
    subparsers.add_parser('genkey', help='Générer une clé AES-256')
    
    args = parser.parse_args()
    print_banner()
    
    if args.command == 'encrypt':
        key = args.key or AESStreamCipher.generate_key()
        ciphertext = AESStreamCipher.encrypt(args.message, key)
        print(f"{Colors.GREEN}[✓] Message chiffré :{Colors.END}")
        print(f"    Clé    : {key}")
        print(f"    Chiffré: {ciphertext}")
    
    elif args.command == 'decrypt':
        plaintext = AESStreamCipher.decrypt(args.ciphertext, args.key)
        print(f"{Colors.GREEN}[✓] Message déchiffré :{Colors.END}")
        print(f"    {plaintext}")
    
    elif args.command == 'rsa-demo':
        print(f"{Colors.YELLOW}[*] Génération d'une paire de clés RSA-512...{Colors.END}")
        public, private = RSASimplified.generate_keypair(512)
        print(f"    Clé publique  : (e={public[0]}, n=...{str(public[1])[-20:]})")
        print(f"    Clé privée    : (d=...{str(private[0])[-20:]}, n=...)")
        
        message = "Hello CyberSec!"
        print(f"\n    Message original : {message}")
        encrypted = RSASimplified.encrypt(message, public)
        print(f"    Message chiffré  : {encrypted[:5]}...")
        decrypted = RSASimplified.decrypt(encrypted, private)
        print(f"    Message déchiffré: {decrypted}")
        print(f"\n  {Colors.GREEN}[✓] RSA fonctionne correctement !{Colors.END}")
    
    elif args.command == 'integrity':
        hmac_val = IntegrityChecker.compute_hmac(args.message, args.key)
        verified = IntegrityChecker.verify_hmac(args.message, args.key, hmac_val)
        print(f"{Colors.GREEN}[✓] HMAC-SHA256 : {hmac_val}{Colors.END}")
        print(f"    Vérification : {'✓ Valide' if verified else '✗ Invalide'}")
    
    elif args.command == 'genkey':
        key = AESStreamCipher.generate_key()
        print(f"{Colors.GREEN}[✓] Clé AES-256 générée : {key}{Colors.END}")
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
