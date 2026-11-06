#!/usr/bin/env python3
"""CBOM ground-truth corpus - Python implementation.

Runs scenarios S01-S24. The Java, Go, TypeScript and C# implementations in the
sibling directories perform the same operations in the same order and print the
same lines, so their standard output can be diffed byte for byte.

All hard-coded keys, IVs, salts and passwords below are published test vectors.
They exist so that scanners have something to find - never reuse them.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import ssl
from datetime import datetime, timedelta, timezone
from typing import Callable

from argon2.low_level import Type, hash_secret_raw
import bcrypt
from Crypto.Cipher import AES, DES3, ChaCha20_Poly1305
from Crypto.Hash import SHA3_256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, mlkem, rsa, x25519
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.x509.oid import NameOID
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

MESSAGE = b"The quick brown fox jumps over the lazy dog"

# --- Hard-coded material (public test vectors only) ---------------------------
HMAC_KEY = b"key"  # Wikipedia HMAC example key
HKDF_IKM = bytes.fromhex("0b" * 22)  # RFC 5869 A.1
HKDF_SALT = bytes.fromhex("000102030405060708090a0b0c")
HKDF_INFO = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
PBKDF2_PASSWORD = b"Password"  # RFC 7914 section 11
PBKDF2_SALT = b"NaCl"
SCRYPT_PASSWORD = b"pleaseletmein"  # RFC 7914 section 12
SCRYPT_SALT = b"SodiumChloride"
PASSWORD = b"correct horse battery staple"
ARGON2_SALT = b"cbom-corpus-salt"
GCM_KEY = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
GCM_IV = bytes.fromhex("cafebabefacedbaddecaf888")
GCM_AAD = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
GCM_PLAINTEXT = bytes.fromhex(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
)
ECB_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")  # FIPS 197 appendix C.1
ECB_PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")
ED25519_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
SESSION_INFO = b"cbom-corpus session key v1"
TLS_SERVER_NAME = "cbom-corpus.example"


def emit(scenario: str, label: str, value: str) -> None:
    print(f"[{scenario}] {label:<18} {value}")


def flag(ok: bool) -> str:
    return "true" if ok else "false"


def verifies(check: Callable[[], object]) -> bool:
    try:
        check()
    except (InvalidSignature, BadSignatureError):
        return False
    return True


# S01: SHA-256 (FIPS 180-4)
def s01_sha256() -> None:
    emit("S01", "SHA-256", hashlib.sha256(MESSAGE).hexdigest())


# S02: SHA-512, SHA3-256, BLAKE2b-512
def s02_sha2_sha3_blake2() -> None:
    emit("S02", "SHA-512", hashlib.sha512(MESSAGE).hexdigest())
    emit("S02", "SHA3-256", SHA3_256.new(MESSAGE).hexdigest())
    blake = hashes.Hash(hashes.BLAKE2b(64))
    blake.update(MESSAGE)
    emit("S02", "BLAKE2b-512", blake.finalize().hex())


# S03: legacy digests - deliberately weak
def s03_legacy_hashes() -> None:
    md5 = hashlib.md5(MESSAGE, usedforsecurity=False)
    emit("S03", "MD5", md5.hexdigest())
    sha1 = hashes.Hash(hashes.SHA1())
    sha1.update(MESSAGE)
    emit("S03", "SHA-1", sha1.finalize().hex())


# S04: SHAKE128 extendable-output function
def s04_shake128() -> None:
    xof = hashlib.shake_128(MESSAGE)
    emit("S04", "SHAKE128", xof.hexdigest(32))


# S05: HMAC-SHA256
def s05_hmac_sha256() -> None:
    tag = hmac.new(HMAC_KEY, MESSAGE, hashlib.sha256)
    emit("S05", "HMAC-SHA256", tag.hexdigest())


# S06: HKDF-SHA256 (RFC 5869)
def s06_hkdf_sha256() -> None:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=42,
        salt=HKDF_SALT,
        info=HKDF_INFO,
    )
    emit("S06", "HKDF-SHA256", hkdf.derive(HKDF_IKM).hex())


# S07: PBKDF2-HMAC-SHA256
def s07_pbkdf2() -> None:
    derived = hashlib.pbkdf2_hmac(
        "sha256", PBKDF2_PASSWORD, PBKDF2_SALT, 80_000, dklen=64
    )
    emit("S07", "PBKDF2-SHA256", derived.hex())


# S08: scrypt
def s08_scrypt() -> None:
    kdf = Scrypt(salt=SCRYPT_SALT, length=64, n=2**14, r=8, p=1)
    emit("S08", "scrypt", kdf.derive(SCRYPT_PASSWORD).hex())


# S09: Argon2id
def s09_argon2id() -> None:
    raw = hash_secret_raw(
        secret=PASSWORD,
        salt=ARGON2_SALT,
        time_cost=2,
        memory_cost=19_456,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )
    emit("S09", "Argon2id", raw.hex())


# S10: bcrypt
def s10_bcrypt() -> None:
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(PASSWORD, salt)
    ok = bcrypt.checkpw(PASSWORD, hashed)
    emit("S10", "bcrypt", f"verify={flag(ok)}")


# S11: AES-256-GCM known-answer test
def s11_aes256_gcm() -> None:
    aead = AESGCM(GCM_KEY)
    sealed = aead.encrypt(GCM_IV, GCM_PLAINTEXT, GCM_AAD)
    ciphertext, tag = sealed[:-16], sealed[-16:]
    opened = aead.decrypt(GCM_IV, sealed, GCM_AAD)
    emit("S11", "AES-256-GCM", f"ct={ciphertext.hex()} tag={tag.hex()} roundtrip={flag(opened == GCM_PLAINTEXT)}")


# S12: ChaCha20-Poly1305 (RFC 8439)
def s12_chacha20_poly1305() -> None:
    key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    sealer = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = sealer.encrypt_and_digest(MESSAGE)
    opener = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    plaintext = opener.decrypt_and_verify(ciphertext, tag)
    emit("S12", "ChaCha20-Poly1305", f"roundtrip={flag(plaintext == MESSAGE)}")


# S13: AES-256-CBC with PKCS#7 padding
def s13_aes256_cbc() -> None:
    key = os.urandom(32)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(MESSAGE) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decryptor.update(ciphertext) + decryptor.finalize()) + unpadder.finalize()
    emit("S13", "AES-256-CBC", f"roundtrip={flag(plaintext == MESSAGE)}")


# S14: AES-128-ECB known-answer test - deliberately weak mode
def s14_aes128_ecb() -> None:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(ECB_PLAINTEXT) + padder.finalize()
    cipher = Cipher(algorithms.AES(ECB_KEY), modes.ECB())
    encryptor = cipher.encryptor()
    emit("S14", "AES-128-ECB", (encryptor.update(padded) + encryptor.finalize()).hex())


# S15: AES-256-CTR
def s15_aes256_ctr() -> None:
    key = secrets.token_bytes(32)
    counter_block = secrets.token_bytes(16)
    encryptor = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=counter_block)
    ciphertext = encryptor.encrypt(MESSAGE)
    decryptor = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=counter_block)
    plaintext = decryptor.decrypt(ciphertext)
    emit("S15", "AES-256-CTR", f"roundtrip={flag(plaintext == MESSAGE)}")


# S16: 3DES (TDEA) CBC - deliberately legacy
def s16_tdea_cbc() -> None:
    key = DES3.adjust_key_parity(get_random_bytes(24))
    iv = get_random_bytes(8)
    encryptor = DES3.new(key, DES3.MODE_CBC, iv=iv)
    ciphertext = encryptor.encrypt(pad(MESSAGE, 8))
    decryptor = DES3.new(key, DES3.MODE_CBC, iv=iv)
    plaintext = unpad(decryptor.decrypt(ciphertext), 8)
    emit("S16", "3DES-CBC", f"roundtrip={flag(plaintext == MESSAGE)}")


# S17: RSA-3072 - OAEP, PSS and PKCS#1 v1.5 with one key pair
def s17_rsa3072() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_key = private_key.public_key()

    oaep = asym_padding.OAEP(
        mgf=asym_padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    ciphertext = public_key.encrypt(MESSAGE, oaep)
    plaintext = private_key.decrypt(ciphertext, oaep)
    emit("S17", "RSA-3072 OAEP", f"roundtrip={flag(plaintext == MESSAGE)}")

    pss = asym_padding.PSS(
        mgf=asym_padding.MGF1(hashes.SHA256()),
        salt_length=32,
    )
    signature = private_key.sign(MESSAGE, pss, hashes.SHA256())
    ok = verifies(lambda: public_key.verify(signature, MESSAGE, pss, hashes.SHA256()))
    emit("S17", "RSA-3072 PSS", f"verify={flag(ok)}")

    pkcs1 = asym_padding.PKCS1v15()
    signature = private_key.sign(MESSAGE, pkcs1, hashes.SHA256())
    ok = verifies(lambda: public_key.verify(signature, MESSAGE, pkcs1, hashes.SHA256()))
    emit("S17", "RSA-3072 PKCS1v15", f"verify={flag(ok)}")


# S18: ECDSA P-256 with SHA-256
def s18_ecdsa_p256() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    signature = private_key.sign(MESSAGE, ec.ECDSA(hashes.SHA256()))
    ok = verifies(lambda: private_key.public_key().verify(signature, MESSAGE, ec.ECDSA(hashes.SHA256())))
    emit("S18", "ECDSA P-256", f"verify={flag(ok)}")


# S19: Ed25519 from a fixed seed (RFC 8032)
def s19_ed25519() -> None:
    signing_key = SigningKey(ED25519_SEED)
    signed = signing_key.sign(MESSAGE)
    verify_key = signing_key.verify_key
    ok = verifies(lambda: verify_key.verify(MESSAGE, signed.signature))
    emit("S19", "Ed25519", f"pk={bytes(verify_key).hex()} sig={signed.signature.hex()} verify={flag(ok)}")


def derive_session_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=SESSION_INFO)
    return hkdf.derive(shared_secret)


# S20: X25519 + ECDH P-256 key agreement, HKDF session key
def s20_key_agreement() -> None:
    alice = x25519.X25519PrivateKey.generate()
    bob = x25519.X25519PrivateKey.generate()
    x_alice = alice.exchange(bob.public_key())
    x_bob = bob.exchange(alice.public_key())
    emit("S20", "X25519", f"agree={flag(x_alice == x_bob)}")

    alice_ec = ec.generate_private_key(ec.SECP256R1())
    bob_ec = ec.generate_private_key(ec.SECP256R1())
    z_alice = alice_ec.exchange(ec.ECDH(), bob_ec.public_key())
    z_bob = bob_ec.exchange(ec.ECDH(), alice_ec.public_key())
    emit("S20", "ECDH P-256", f"agree={flag(z_alice == z_bob)}")

    k_alice = derive_session_key(x_alice + z_alice)
    k_bob = derive_session_key(x_bob + z_bob)
    emit("S20", "HKDF session key", f"match={flag(k_alice == k_bob)}")


# S21: ML-KEM-768 (FIPS 203)
def s21_ml_kem_768() -> None:
    decapsulation_key = mlkem.MLKEM768PrivateKey.generate()
    encapsulation_key = decapsulation_key.public_key()
    shared_secret, ciphertext = encapsulation_key.encapsulate()
    recovered = decapsulation_key.decapsulate(ciphertext)
    emit("S21", "ML-KEM-768", f"agree={flag(shared_secret == recovered)} ct={len(ciphertext)} ss={len(shared_secret)}")


# S22: ML-DSA-65 (FIPS 204)
def s22_ml_dsa_65() -> None:
    private_key = mldsa.MLDSA65PrivateKey.generate()
    signature = private_key.sign(MESSAGE)
    ok = verifies(lambda: private_key.public_key().verify(signature, MESSAGE))
    emit("S22", "ML-DSA-65", f"verify={flag(ok)} sig={len(signature)}")


# S23: self-signed X.509 certificate
def s23_x509_self_signed() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, TLS_SERVER_NAME)])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(secrets.randbits(64))
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
    )
    certificate = builder.sign(key, hashes.SHA256())
    ok = verifies(
        lambda: certificate.public_key().verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(certificate.signature_hash_algorithm),
        )
    )
    emit("S23", "X.509 self-signed", f"verify={flag(ok)}")


# S24: TLS 1.3-only client context (no connection is made)
def s24_tls13_client() -> None:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = True
    emit("S24", "TLS 1.3 client", "configured=true")


def main() -> None:
    for scenario in (
        s01_sha256, s02_sha2_sha3_blake2, s03_legacy_hashes, s04_shake128,
        s05_hmac_sha256, s06_hkdf_sha256, s07_pbkdf2, s08_scrypt, s09_argon2id,
        s10_bcrypt, s11_aes256_gcm, s12_chacha20_poly1305, s13_aes256_cbc,
        s14_aes128_ecb, s15_aes256_ctr, s16_tdea_cbc, s17_rsa3072, s18_ecdsa_p256,
        s19_ed25519, s20_key_agreement, s21_ml_kem_768, s22_ml_dsa_65,
        s23_x509_self_signed, s24_tls13_client,
    ):
        scenario()


if __name__ == "__main__":
    main()
