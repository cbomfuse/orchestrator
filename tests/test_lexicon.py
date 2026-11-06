import pytest

from orchestrator.normalize.lexicon import (descriptor_from_fields, normalize_family, normalize_functions,
                                            normalize_material_type, parse_name)


@pytest.mark.parametrize("name,canonical,primitive", [
    ("AES/GCM/NoPadding", "aes-gcm-none", "ae"),
    ("AES128-GCM", "aes-128-gcm", "ae"),
    ("aes-256-gcm", "aes-256-gcm", "ae"),
    ("AES-256-CBC-PKCS7", "aes-256-cbc-pkcs7", "block-cipher"),
    ("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "rsa-oaep-sha2-256", "pke"),
    ("SHA256withRSA", "rsa-sha2-256", "signature"),
    ("SHA256withECDSA", "ecdsa-sha2-256", "signature"),
    ("HmacSHA256", "hmac-256-sha2-256", "mac"),
    ("PBKDF2WithHmacSHA256", "pbkdf2-sha2-256", "kdf"),
    ("SHA-256", "sha2-256", "hash"),
    ("SHA3-256", "sha3-256", "hash"),
    ("SHAKE128", "sha3-128", "xof"),
    ("ChaCha20-Poly1305", "chacha20", "ae"),
    ("DESede/CBC/PKCS5Padding", "3des-cbc-pkcs7", "block-cipher"),
    ("3DES-CBC-PKCS7 (3-key TDEA)", "3des-cbc-pkcs7", "block-cipher"),
    ("RSASSA-PKCS1-v1_5-SHA256 (RSA-3072)", "rsa-3072-pkcs1v15-sha2-256", "signature"),
    ("RSASSA-PSS-SHA256 (RSA-3072)", "rsa-3072-pss-sha2-256", "signature"),
    ("X25519", "ecdh-curve25519", "key-agree"),
    ("Ed25519", "eddsa-edwards25519", "signature"),
    ("Kyber768", "ml-kem-768", "kem"),
    ("Dilithium3", "ml-dsa-65", "signature"),
    ("ML-DSA-65", "ml-dsa-65", "signature"),
    ("SecureRandom", "csprng", "drbg"),
    ("secp256r1", "ec-p256", None),
    ("sha256WithRSAEncryption", "rsa-sha2-256", "signature"),
])
def test_parse_name(name, canonical, primitive):
    d = parse_name(name)
    assert d.canonical() == canonical
    assert d.primitive == primitive


def test_hints_fill_slots_and_reinfer_primitive():
    d = descriptor_from_fields("AES", {"parameterSetIdentifier": "256", "mode": "GCM"})
    assert d.to_dict() == {"family": "aes", "param": "256", "mode": "gcm", "primitive": "ae"}


def test_hint_parameter_set_naming_a_hash_is_a_hash_slot():
    d = descriptor_from_fields("PBKDF2-HMAC-SHA256", {"parameterSetIdentifier": "SHA-256", "primitive": "kdf"})
    assert d.family == "pbkdf2" and d.hash == "sha2-256" and d.param is None


def test_ec_size_becomes_curve_with_note():
    d = descriptor_from_fields("ECDSA", {"parameterSetIdentifier": "256"})
    assert d.curve == "p256" and "curve-from-size" in d.notes


def test_drbg_with_hash_parameter():
    d = descriptor_from_fields("BC DigestRandomGenerator (SHA-256)", {"primitive": "drbg", "parameterSetIdentifier": "SHA-256"})
    assert d.family == "csprng" and d.hash == "sha2-256" and d.param is None


def test_other_enum_values_do_not_pollute_identity():
    d = descriptor_from_fields("ChaCha20-Poly1305", {"mode": "other", "padding": "other"})
    assert d.mode is None and d.padding is None


def test_normalizers():
    assert normalize_family("SHA-2") == "sha2"
    assert normalize_family("Hash-based PRNG") == "csprng"
    assert normalize_material_type("privateKey") == "private-key"
    assert normalize_material_type("initializationVector") == "initialization-vector"
    assert normalize_functions(["Encrypt", "hash", "keyGeneration"]) == ["digest", "encrypt", "keygen"]
