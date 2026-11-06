"""Canonical algorithm descriptors.

CBOM generators spell the same algorithm in many ways (``AES/GCM/NoPadding``, ``AES128-GCM``,
``aes-128-gcm``, ``2.16.840.1.101.3.4.1.6``).  The matcher never compares names directly; it
compares *descriptors* -- a small set of identity slots -- obtained by tokenising the name with the
lexicon below and merging the structured ``algorithmProperties`` a tool reported.  The ground truth
goes through exactly the same function, so both sides speak the same vocabulary.

The lexicon is intentionally self-contained (no dependency on 2CBOM) but follows the same slot
model as 2CBOM's ``AlgorithmDescriptor`` so that results translate directly.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Iterable, Optional

# ----------------------------------------------------------------------------- enumerations
PRIMITIVES = {"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf",
              "key-agree", "kem", "ae", "combiner", "other", "unknown"}

_PRIMITIVE_SYNONYMS = {
    "publickeyencryption": "pke", "public-key-encryption": "pke", "asymmetric": "pke", "asymmetricencryption": "pke",
    "blockcipher": "block-cipher", "streamcipher": "stream-cipher", "keyagree": "key-agree", "keyagreement": "key-agree",
    "key-agreement": "key-agree", "keyexchange": "key-agree", "key-exchange": "key-agree",
    "authenticatedencryption": "ae", "aead": "ae", "authenticated-encryption": "ae",
    "keyderivation": "kdf", "key-derivation": "kdf", "keyderivationfunction": "kdf", "passwordhashing": "kdf",
    "keyencapsulation": "kem", "key-encapsulation": "kem", "messagedigest": "hash", "digest": "hash",
    "hashing": "hash", "digitalsignature": "signature", "signing": "signature", "signatures": "signature",
    "randomnumbergeneration": "drbg", "rng": "drbg", "prng": "drbg", "csprng": "drbg", "random": "drbg",
    "symmetric": "block-cipher", "symmetricencryption": "block-cipher", "cipher": "block-cipher",
    "extendableoutputfunction": "xof", "xof": "xof",
}

MATERIAL_TYPES = {"private-key", "public-key", "secret-key", "key", "ciphertext", "signature", "digest",
                  "initialization-vector", "nonce", "seed", "salt", "shared-secret", "tag", "additional-data",
                  "password", "credential", "token", "other", "unknown"}

_FUNCTION_SYNONYMS = {
    "hash": "digest", "digesting": "digest", "mac": "tag", "authenticate": "tag", "derive": "keyderive",
    "kdf": "keyderive", "keyderivation": "keyderive", "key-derive": "keyderive", "keygeneration": "keygen",
    "generatekey": "keygen", "key-gen": "keygen", "keypairgeneration": "keygen", "random": "generate",
    "encapsulation": "encapsulate", "decapsulation": "decapsulate", "signing": "sign", "verification": "verify",
    "encryption": "encrypt", "decryption": "decrypt",
}
FUNCTIONS = {"generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive", "sign", "verify",
             "encapsulate", "decapsulate", "other", "unknown"}

_PADDING_SYNONYMS = {
    "pkcs1": "pkcs1v15", "pkcs1v1": "pkcs1v15", "pkcs1v1_5": "pkcs1v15", "pkcs1-v1_5": "pkcs1v15", "pkcs1-v1.5": "pkcs1v15",
    "pkcs1v15": "pkcs1v15", "rsaes-pkcs1-v1_5": "pkcs1v15", "pkcs#1": "pkcs1v15",
    "pkcs5": "pkcs7", "pkcs7": "pkcs7", "pkcs#7": "pkcs7", "pkcs#5": "pkcs7",
    "oaep": "oaep", "pss": "pss", "nopadding": "none", "none": "none", "no-padding": "none", "raw": "none",
    "iso10126": "iso10126", "iso10126padding": "iso10126", "ansix923": "x923", "x923": "x923", "x9.23": "x923",
    "zero": "zero", "zeropadding": "zero", "zerobytepadding": "zero", "iso7816": "iso7816",
    "other": "other", "unknown": None,
}

CURVE_ALIASES = {
    "p256": "p256", "p-256": "p256", "secp256r1": "p256", "prime256v1": "p256", "nistp256": "p256", "nist-p256": "p256",
    "p384": "p384", "p-384": "p384", "secp384r1": "p384", "nistp384": "p384", "nist-p384": "p384",
    "p521": "p521", "p-521": "p521", "secp521r1": "p521", "nistp521": "p521", "nist-p521": "p521",
    "p224": "p224", "p-224": "p224", "secp224r1": "p224", "p192": "p192", "p-192": "p192", "secp192r1": "p192",
    "secp256k1": "secp256k1", "curve25519": "curve25519", "x25519": "curve25519",
    "edwards25519": "edwards25519", "ed25519": "edwards25519", "curve448": "curve448", "x448": "curve448",
    "edwards448": "edwards448", "ed448": "edwards448",
    "brainpoolp256r1": "brainpoolp256r1", "brainpoolp384r1": "brainpoolp384r1", "brainpoolp512r1": "brainpoolp512r1",
    "sm2": "sm2", "sm2p256v1": "sm2",
}

HASH_FAMILIES = {"sha2", "sha3", "sha1", "md5", "blake2", "blake3", "ripemd", "md4", "md2", "sm3", "whirlpool",
                 "shake", "streebog"}
EC_FAMILIES = {"ecdsa", "ecdh", "eddsa", "ec", "ecies", "ecmqv", "x25519", "ed25519", "sm2"}
KDF_FAMILIES = {"hkdf", "pbkdf2", "scrypt", "argon2", "bcrypt", "pbkdf1", "ansi-x9.63-kdf", "concatkdf", "kbkdf",
                "sp800-108", "x963kdf"}
PQC_FAMILIES = {"ml-kem", "ml-dsa", "slh-dsa", "fn-dsa", "hqc", "frodokem", "bike", "classic-mceliece", "xmss", "lms",
                "kyber", "dilithium", "falcon", "sphincs+"}

# Ground-truth / 2CBOM family spellings -> lexicon families
FAMILY_ALIASES = {
    "sha-2": "sha2", "sha2": "sha2", "sha-3": "sha3", "sha3": "sha3", "blake2": "blake2", "blake2b": "blake2", "blake2s": "blake2",
    "md5": "md5", "sha-1": "sha1", "sha1": "sha1", "hmac": "hmac", "hkdf": "hkdf", "pbkdf2": "pbkdf2", "scrypt": "scrypt",
    "argon2": "argon2", "argon2id": "argon2", "bcrypt": "bcrypt", "aes": "aes", "chacha20": "chacha20",
    "chacha20-poly1305": "chacha20", "3des": "3des", "tdea": "3des", "des-ede3": "3des", "desede": "3des", "des": "des",
    "rsa": "rsa", "mgf1": "mgf1", "ecdsa": "ecdsa", "ecdh": "ecdh", "eddsa": "eddsa", "ml-kem": "ml-kem", "ml-dsa": "ml-dsa",
    "slh-dsa": "slh-dsa", "fn-dsa": "fn-dsa", "csprng": "csprng", "drbg": "csprng", "x25519": "ecdh", "ed25519": "eddsa",
    "kyber": "ml-kem", "dilithium": "ml-dsa", "falcon": "fn-dsa", "sphincs+": "slh-dsa", "sphincs": "slh-dsa",
    "camellia": "camellia", "aria": "aria", "sm4": "sm4", "seed": "seed", "blowfish": "blowfish", "twofish": "twofish",
    "rc4": "rc4", "rc2": "rc2", "dsa": "dsa", "dh": "dh", "diffie-hellman": "dh", "shake": "sha3", "sha-3 (shake)": "sha3",
    "sha-2 (sha-512/256)": "sha2", "poly1305": "poly1305", "cmac": "cmac", "gmac": "gmac", "siphash": "siphash",
    "ripemd-160": "ripemd", "ripemd160": "ripemd", "ripemd": "ripemd", "sm3": "sm3", "blake3": "blake3", "whirlpool": "whirlpool",
    "ec": "ec", "ecies": "ecies", "xmss": "xmss", "lms": "lms", "hqc": "hqc",
}

# ----------------------------------------------------------------------------- tokeniser
# (regex, kind, canonical-or-None).  Order matters: longer / more specific patterns first.
_ATOMS: list[tuple[str, str, Optional[str]]] = [
    (r"chacha20[-_ ]?poly1305", "family", "chacha20"),
    (r"xchacha20[-_ ]?poly1305", "family", "xchacha20"),
    (r"chacha20", "family", "chacha20"),
    (r"xchacha20", "family", "xchacha20"),
    (r"salsa20", "family", "salsa20"),
    (r"poly1305", "family", "poly1305"),
    (r"ml[-_ ]?kem", "family", "ml-kem"),
    (r"kyber", "family", "ml-kem"),
    (r"ml[-_ ]?dsa", "family", "ml-dsa"),
    (r"dilithium", "family", "ml-dsa"),
    (r"slh[-_ ]?dsa", "family", "slh-dsa"),
    (r"sphincs\+?", "family", "slh-dsa"),
    (r"fn[-_ ]?dsa", "family", "fn-dsa"),
    (r"falcon", "family", "fn-dsa"),
    (r"hmac", "family", "hmac"),
    (r"pbkdf2", "family", "pbkdf2"),
    (r"pbkdf1", "family", "pbkdf1"),
    (r"hkdf", "family", "hkdf"),
    (r"scrypt", "family", "scrypt"),
    (r"bcrypt", "family", "bcrypt"),
    (r"argon2(?:id|i|d)?", "family", "argon2"),
    (r"x963kdf|ansi[-_ ]?x9\.63", "family", "x963kdf"),
    (r"concatkdf", "family", "concatkdf"),
    (r"kbkdf|sp800[-_ ]?108", "family", "kbkdf"),
    (r"sha3[-_ ]?(224|256|384|512)", "hash", "sha3-{1}"),
    (r"sha[-_ ]?3(?![\d])", "family", "sha3"),
    (r"shake[-_ ]?(128|256)", "hash", "shake-{1}"),
    (r"keccak[-_ ]?(224|256|384|512)?", "hash", "keccak-{1}"),
    (r"sha[-_ ]?512[/_-]?(224|256)", "hash", "sha2-512/{1}"),
    (r"sha[-_ ]?(224|256|384|512)", "hash", "sha2-{1}"),
    (r"sha[-_ ]?2(?![\d])", "family", "sha2"),
    (r"sha[-_ ]?1(?![\d])", "hash", "sha1"),
    (r"(?<![a-z0-9])sha(?![a-z0-9])", "hash", "sha1"),
    (r"md5", "hash", "md5"),
    (r"md4", "hash", "md4"),
    (r"md2", "hash", "md2"),
    (r"blake2b[-_ ]?(160|256|384|512)?", "hash", "blake2b-{1}"),
    (r"blake2s[-_ ]?(128|160|224|256)?", "hash", "blake2s-{1}"),
    (r"blake2", "family", "blake2"),
    (r"blake3", "hash", "blake3"),
    (r"ripemd[-_ ]?160|ripemd", "hash", "ripemd-160"),
    (r"sm3", "hash", "sm3"),
    (r"whirlpool", "hash", "whirlpool"),
    (r"mgf1", "family", "mgf1"),
    (r"rsassa[-_ ]?pss|rsa[-_ ]?pss", "family", "rsa-pss"),
    (r"rsaes[-_ ]?oaep|rsa[-_ ]?oaep", "family", "rsa-oaep"),
    (r"rsassa[-_ ]?pkcs1[-_ ]?v1[-._]?5|rsaes[-_ ]?pkcs1[-_ ]?v1[-._]?5", "family", "rsa-pkcs1v15"),
    (r"rsa", "family", "rsa"),
    (r"ecdsa", "family", "ecdsa"),
    (r"ecdh[-_ ]?e?s?|ecmqv", "family", "ecdh"),
    (r"ecies", "family", "ecies"),
    (r"eddsa", "family", "eddsa"),
    (r"x25519", "curve", "curve25519"),
    (r"curve25519", "curve", "curve25519"),
    (r"ed25519", "curve", "edwards25519"),
    (r"edwards25519", "curve", "edwards25519"),
    (r"x448", "curve", "curve448"),
    (r"ed448", "curve", "edwards448"),
    (r"secp256k1", "curve", "secp256k1"),
    (r"secp(192|224|256|384|521)r1|prime(192|256)v1|nist[-_ ]?p[-_ ]?(192|224|256|384|521)|(?<![a-z0-9])p[-_ ]?(192|224|256|384|521)(?![0-9])",
     "curve", "p{num}"),
    (r"brainpoolp(160|192|224|256|320|384|512)(?:r|t)1", "curve", "brainpoolp{1}r1"),
    (r"sm2", "family", "sm2"),
    (r"3des|triple[-_ ]?des|tdea|des[-_ ]?ede3?|desede", "family", "3des"),
    (r"(?<![a-z])des(?![a-z])", "family", "des"),
    (r"aes|rijndael", "family", "aes"),
    (r"camellia", "family", "camellia"),
    (r"aria", "family", "aria"),
    (r"sm4", "family", "sm4"),
    (r"blowfish", "family", "blowfish"),
    (r"twofish", "family", "twofish"),
    (r"serpent", "family", "serpent"),
    (r"rc4|arcfour", "family", "rc4"),
    (r"rc2", "family", "rc2"),
    (r"(?<![a-z])dsa(?![a-z])", "family", "dsa"),
    (r"diffie[-_ ]?hellman|(?<![a-z])dh(?![a-z])|(?<![a-z])dhe(?![a-z])", "family", "dh"),
    (r"cmac", "family", "cmac"),
    (r"gmac", "family", "gmac"),
    (r"siphash", "family", "siphash"),
    (r"(?<![a-z])ec(?![a-z])", "family", "ec"),
    (r"csprng|securerandom|secure[-_ ]?random|drbg|urandom|getrandom|randombytes|random[-_ ]?bytes|randomnumber(?:generator)?|random[-_ ]?number|systemrandom|digestrandomgenerator|random[-_ ]?generator|(?<![a-z])(?:rng|prng|rand|random)(?![a-z])",
     "family", "csprng"),
    (r"gcm[-_ ]?siv", "mode", "gcm-siv"),
    (r"(?<![a-z])(gcm|ccm|cbc|ecb|ctr|cfb8?|ofb|xts|siv|ocb|eax|cts|kw|kwp|wrap)(?![a-z])", "mode", "{1}"),
    (r"oaep", "padding", "oaep"),
    (r"(?<![a-z])pss(?![a-z])", "padding", "pss"),
    (r"pkcs[-_#]?1(?:[-_ ]?(?:v1[-._]?5|v15))?", "padding", "pkcs1v15"),
    (r"pkcs[-_#]?7", "padding", "pkcs7"),
    (r"pkcs[-_#]?5", "padding", "pkcs7"),
    (r"no[-_ ]?padding", "padding", "none"),
    (r"iso[-_ ]?10126", "padding", "iso10126"),
    (r"(?:ansi[-_ ]?)?x9[._]?23", "padding", "x923"),
    (r"zero[-_ ]?(?:byte)?[-_ ]?padding", "padding", "zero"),
    (r"iso[-_ ]?7816", "padding", "iso7816"),
    (r"(?<![a-z])padding(?![a-z])", "stop", None),
    (r"(?<![a-z])(with|and|encryption|decryption|signature|signatures|algorithm|cipher|digest|hash|key|keys|mode|the|of|in|using)(?![a-z])",
     "stop", None),
    (r"\d+", "number", "{0}"),
]
_ATOM_RE = [(re.compile(p, re.IGNORECASE), kind, canon) for p, kind, canon in _ATOMS]


@dataclass
class Token:
    kind: str
    value: Optional[str]
    text: str


def tokenize(name: str) -> list[Token]:
    """Scan ``name`` left to right, emitting the longest matching atom at each position."""
    s = (name or "").strip().lower().replace("_", "-")
    tokens: list[Token] = []
    i = 0
    n = len(s)
    while i < n:
        best = None
        for rx, kind, canon in _ATOM_RE:
            m = rx.match(s, i)
            if m and (best is None or m.end() > best[0].end()):
                best = (m, kind, canon)
            # keep scanning: a later, more specific atom may be longer
        if best is None:
            i += 1
            continue
        m, kind, canon = best
        value: Optional[str]
        if canon is None:
            value = None
        else:
            value = canon
            if "{num}" in canon:
                num = next((g for g in m.groups() if g), "")
                value = canon.replace("{num}", num)
            for gi in range(1, 6):
                if f"{{{gi}}}" in value:
                    g = m.group(gi) if gi <= (m.lastindex or 0) else None
                    value = value.replace(f"{{{gi}}}", g or "")
            if "{0}" in value:
                value = value.replace("{0}", m.group(0))
            value = value.rstrip("-")
        tokens.append(Token(kind, value, m.group(0)))
        i = m.end()
    return tokens


# ----------------------------------------------------------------------------- descriptor
@dataclass
class Descriptor:
    family: Optional[str] = None
    param: Optional[str] = None
    mode: Optional[str] = None
    padding: Optional[str] = None
    curve: Optional[str] = None
    hash: Optional[str] = None
    primitive: Optional[str] = None
    numbers: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    SLOTS = ("family", "param", "mode", "padding", "curve", "hash")

    def canonical(self) -> str:
        parts = [self.family or "?"]
        for slot in ("param", "mode", "padding", "curve", "hash"):
            v = getattr(self, slot)
            if v:
                parts.append(str(v))
        return "-".join(parts)

    def to_dict(self) -> dict:
        d = asdict(self)
        return {k: v for k, v in d.items() if v not in (None, [], "")}

    def copy(self) -> "Descriptor":
        return Descriptor(self.family, self.param, self.mode, self.padding, self.curve, self.hash,
                          self.primitive, list(self.numbers), list(self.notes))


_HASH_SIZES = {"sha2-224": "224", "sha2-256": "256", "sha2-384": "384", "sha2-512": "512", "sha2-512/224": "512/224",
               "sha2-512/256": "512/256", "sha3-224": "224", "sha3-256": "256", "sha3-384": "384", "sha3-512": "512",
               "shake-128": "128", "shake-256": "256", "sha1": "160", "md5": "128", "md4": "128", "md2": "128",
               "ripemd-160": "160", "sm3": "256", "blake3": "256", "whirlpool": "512"}
_PARAM_FAMILIES = {"aes", "rsa", "dsa", "dh", "camellia", "aria", "sm4", "seed", "blowfish", "twofish", "serpent", "rc2",
                   "rc4", "ml-kem", "ml-dsa", "slh-dsa", "fn-dsa", "3des", "des", "blake2", "hmac", "chacha20", "xchacha20"}
_DILITHIUM = {"2": "44", "3": "65", "5": "87"}
_FALCON = {"512": "512", "1024": "1024"}


_PLAUSIBLE = {
    "aes": {"128", "192", "256"}, "camellia": {"128", "192", "256"}, "aria": {"128", "192", "256"}, "sm4": {"128"},
    "seed": {"128"}, "3des": {"112", "128", "168", "192"}, "des": {"56", "64"}, "ml-kem": {"512", "768", "1024"},
    "ml-dsa": {"44", "65", "87"}, "slh-dsa": {"128", "192", "256"}, "fn-dsa": {"512", "1024"},
    "blake2": {"128", "160", "224", "256", "384", "512"}, "hmac": {"128", "160", "224", "256", "384", "512"},
    "chacha20": {"256"}, "xchacha20": {"256"}, "rc2": {"40", "64", "128"}, "rc4": {"40", "64", "128", "256"},
}


def _plausible_param(family: str, raw: str, dilithium: bool = False) -> bool:
    if family == "ml-dsa" and dilithium:
        return raw in _DILITHIUM
    if family in ("rsa", "dsa", "dh"):
        return raw.isdigit() and int(raw) >= 512
    allowed = _PLAUSIBLE.get(family)
    if allowed is None:
        return True
    return raw in allowed


def _hash_family(hash_token: str) -> str:
    if hash_token.startswith("sha2"):
        return "sha2"
    if hash_token.startswith("sha3") or hash_token.startswith("shake") or hash_token.startswith("keccak"):
        return "sha3"
    if hash_token.startswith("blake2"):
        return "blake2"
    if hash_token.startswith("ripemd"):
        return "ripemd"
    return hash_token.split("-")[0]


def normalize_mode(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip().lower().replace("_", "-")
    if s in ("", "none", "unknown", "null"):
        return None
    s = re.sub(r"mode$", "", s).strip("-")
    return s or None


def normalize_padding(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip().lower().replace(" ", "").replace("_", "-")
    if s in ("", "null"):
        return None
    if s in _PADDING_SYNONYMS:
        return _PADDING_SYNONYMS[s]
    s2 = s.replace("-", "")
    return _PADDING_SYNONYMS.get(s2, s)


def normalize_curve(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip().lower().replace("_", "-").replace(" ", "")
    if not s:
        return None
    return CURVE_ALIASES.get(s) or CURVE_ALIASES.get(s.replace("-", "")) or s


def normalize_primitive(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip().lower()
    if not s:
        return None
    if s in PRIMITIVES:
        return s
    s2 = s.replace("_", "").replace("-", "").replace(" ", "")
    return _PRIMITIVE_SYNONYMS.get(s2, _PRIMITIVE_SYNONYMS.get(s, s))


def normalize_function(v: str) -> str:
    s = str(v).strip().lower().replace("_", "").replace("-", "").replace(" ", "")
    if s in FUNCTIONS:
        return s
    return _FUNCTION_SYNONYMS.get(s, s)


def normalize_functions(values: Optional[Iterable]) -> list[str]:
    out = []
    for v in values or []:
        if v is None:
            continue
        f = normalize_function(v)
        if f not in out:
            out.append(f)
    return sorted(out)


def normalize_material_type(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    s = re.sub(r"(?<=[a-z0-9])([A-Z])", r"-\1", s).lower().replace("_", "-").replace(" ", "-")
    aliases = {"privatekey": "private-key", "publickey": "public-key", "secretkey": "secret-key", "symmetric-key": "secret-key",
               "iv": "initialization-vector", "initializationvector": "initialization-vector", "sharedsecret": "shared-secret",
               "additionaldata": "additional-data", "aad": "additional-data", "pw": "password", "keypair": "key"}
    return aliases.get(s.replace("-", ""), aliases.get(s, s))


def normalize_family(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip().lower()
    if not s:
        return None
    if s in FAMILY_ALIASES:
        return FAMILY_ALIASES[s]
    toks = tokenize(s)
    fams = [t.value for t in toks if t.kind == "family"]
    if fams:
        return _base_family(fams[0])
    hashes = [t.value for t in toks if t.kind == "hash"]
    if hashes:
        return _hash_family(hashes[0])
    return s


def _base_family(f: str) -> str:
    if f.startswith("rsa-"):
        return "rsa"
    return f


def parse_name(name: Optional[str]) -> Descriptor:
    """Tokenise ``name`` and assemble a descriptor from the tokens alone."""
    d = Descriptor()
    toks = tokenize(name or "")
    fams = [t for t in toks if t.kind == "family"]
    hashes = [t.value for t in toks if t.kind == "hash"]
    modes = [t.value for t in toks if t.kind == "mode"]
    paddings = [t.value for t in toks if t.kind == "padding"]
    curves = [t.value for t in toks if t.kind == "curve"]
    numbers = [t.value for t in toks if t.kind == "number"]
    d.numbers = numbers

    fam = fams[0].value if fams else None
    if fam in ("rsa-pss", "rsa-oaep", "rsa-pkcs1v15"):
        d.padding = fam.split("-", 1)[1]
        fam = "rsa"
    if fam is None and curves:
        # bare "X25519" / "Ed25519" / "P-256"
        if curves[0] == "edwards25519" or curves[0] == "edwards448":
            fam = "eddsa"
        elif curves[0] in ("curve25519", "curve448"):
            fam = "ecdh"
        else:
            fam = "ec"
    if fam is None and hashes:
        h = hashes[0]
        fam = _hash_family(h)
        if h.startswith("blake2"):
            d.param = h.split("-")[1] if "-" in h else None
            d.notes.append(f"variant:{h.split('-')[0]}")
        else:
            d.param = _HASH_SIZES.get(h)
        if h.startswith("shake"):
            d.notes.append("xof")
    elif fam is not None and hashes:
        d.hash = hashes[0]
    # poly1305 alongside chacha20 is the AEAD construction, not a separate family
    if any(f.value in ("chacha20", "xchacha20") for f in fams):
        if fam == "poly1305" or any(f.value == "poly1305" for f in fams):
            d.notes.append("aead")
        if fam == "poly1305":
            fam = next(f.value for f in fams if f.value in ("chacha20", "xchacha20"))
    if any(f.text.replace("-", "").replace("_", "").replace(" ", "") in ("chacha20poly1305", "xchacha20poly1305") for f in fams):
        d.notes.append("aead")
    d.family = fam
    if d.family in HASH_FAMILIES and d.hash and _hash_family(d.hash) == d.family:
        d.param = d.param or _HASH_SIZES.get(d.hash)
        d.hash = None
    if curves:
        d.curve = curves[0]
    if modes and d.family not in HASH_FAMILIES | {"rsa", "ecdsa", "eddsa", "ml-dsa", "ml-kem", "hmac", "hkdf", "pbkdf2"}:
        d.mode = modes[0]
    elif modes and d.family == "rsa" and modes[0] != "ecb":
        d.mode = modes[0]
    if paddings and d.padding is None:
        d.padding = paddings[0]
    # parameter set: the first number that is plausible for the family
    if d.param is None and numbers and d.family in _PARAM_FAMILIES:
        dilithium = any(f.text.startswith("dilithium") for f in fams)
        for raw in numbers:
            if not _plausible_param(d.family, raw, dilithium):
                continue
            if d.family == "ml-dsa":
                d.param = _DILITHIUM.get(raw, raw) if dilithium else raw
            elif d.family == "3des":
                d.param = {"192": "168", "168": "168", "112": "112", "128": "112"}.get(raw, raw)
            elif d.family == "hmac":
                d.param = _HASH_SIZES.get(d.hash, raw) if d.hash else raw
            else:
                d.param = raw
            break
    if d.family == "hmac" and d.hash and d.param is None:
        d.param = _HASH_SIZES.get(d.hash)
    if d.family == "argon2":
        m = re.search(r"argon2(id|i|d)", (name or "").lower())
        if m:
            d.notes.append(f"variant:argon2{m.group(1)}")
    # numeric parameter for EC families means a NIST curve size
    if d.family in EC_FAMILIES and d.curve is None and numbers:
        d.curve = {"256": "p256", "384": "p384", "521": "p521", "224": "p224", "192": "p192"}.get(numbers[0])
        if d.curve:
            d.notes.append("curve-from-size")
    d.primitive = infer_primitive(d)
    return d


def infer_primitive(d: Descriptor) -> Optional[str]:
    f = d.family
    if f is None:
        return None
    if f in HASH_FAMILIES:
        if "xof" in d.notes or (d.hash or "").startswith("shake"):
            return "xof"
        return "hash"
    if f in ("hmac", "cmac", "gmac", "poly1305", "siphash"):
        return "mac"
    if f in KDF_FAMILIES:
        return "kdf"
    if f in ("aes", "camellia", "aria", "sm4", "seed", "blowfish", "twofish", "serpent", "3des", "des", "rc2"):
        if d.mode in ("gcm", "ccm", "ocb", "eax", "siv", "gcm-siv"):
            return "ae"
        return "block-cipher"
    if f in ("chacha20", "xchacha20"):
        return "ae" if "aead" in d.notes else "stream-cipher"
    if f in ("salsa20", "rc4"):
        return "stream-cipher"
    if f == "rsa":
        if d.padding == "oaep":
            return "pke"
        if d.padding == "pss" or (d.hash and d.padding in ("pkcs1v15", None)):
            return "signature"
        return "pke"
    if f in ("ecdsa", "eddsa", "ml-dsa", "slh-dsa", "fn-dsa", "dsa", "xmss", "lms", "sm2"):
        return "signature"
    if f in ("ecdh", "dh", "ecmqv"):
        return "key-agree"
    if f in ("ml-kem", "hqc", "frodokem", "bike", "classic-mceliece", "ecies"):
        return "kem"
    if f == "csprng":
        return "drbg"
    if f == "mgf1":
        return "other"
    if f == "ec":
        return None
    return None


def descriptor_from_fields(name: Optional[str], props: Optional[dict] = None) -> Descriptor:
    """Descriptor from a name plus CycloneDX-style ``algorithmProperties`` hints (name wins, hints fill)."""
    props = props or {}
    d = parse_name(name)
    ps = props.get("parameterSetIdentifier")
    curve = normalize_curve(props.get("curve"))
    mode = normalize_mode(props.get("mode"))
    padding = normalize_padding(props.get("padding"))
    primitive = normalize_primitive(props.get("primitive"))
    if d.family is None and props.get("variant"):
        d2 = parse_name(str(props["variant"]))
        if d2.family:
            d = d2
    if ps not in (None, ""):
        pss = str(ps).strip()
        pl = pss.lower()
        hd = parse_name(pss)
        if d.family in EC_FAMILIES or (d.family is None and normalize_curve(pl) in CURVE_ALIASES.values()):
            c = normalize_curve(pl)
            if c in CURVE_ALIASES.values():
                d.curve = d.curve or c
            elif pl.isdigit():
                d.curve = d.curve or {"256": "p256", "384": "p384", "521": "p521", "224": "p224", "192": "p192"}.get(pl)
                if d.curve:
                    d.notes.append("curve-from-size")
            elif d.param is None and not pl.isdigit():
                d.param = pl
        elif hd.family in HASH_FAMILIES and d.family not in HASH_FAMILIES:
            # the parameter set names a hash ("SHA-256" for HKDF, PBKDF2, HMAC, MGF1, a hash DRBG ...)
            d.hash = d.hash or (f"{hd.family}-{hd.param}" if hd.param else hd.family)
            if d.family == "hmac":
                d.param = d.param or _HASH_SIZES.get(d.hash)
        elif d.param is None:
            d.param = pl
            if d.family == "3des":
                d.param = {"192": "168", "168": "168", "112": "112", "128": "112"}.get(d.param, d.param)
    if d.family in ("hkdf", "pbkdf2", "mgf1") and d.param and d.hash is None:
        hd = parse_name(str(d.param))
        if hd.family in HASH_FAMILIES:
            d.hash = f"{hd.family}-{hd.param}" if hd.param else hd.family
            d.param = None
    # "Hash DRBG (SHA-256)": a hash family named inside a DRBG asset is its parameter, not its identity
    if primitive == "drbg" and d.family in HASH_FAMILIES:
        d.hash = f"{d.family}-{d.param}" if d.param else d.family
        d.family, d.param = "csprng", None
    if curve and d.curve is None:
        d.curve = curve
    if mode and mode != "other" and d.mode is None and d.family not in HASH_FAMILIES:
        d.mode = mode
    if padding and padding != "other" and d.padding is None:
        d.padding = padding
    d.primitive = primitive or infer_primitive(d)
    return d


def param_equal(a: Optional[str], b: Optional[str]) -> bool:
    if a is None or b is None:
        return False
    sa, sb = str(a).strip().lower(), str(b).strip().lower()
    if sa == sb:
        return True
    norm = lambda s: re.sub(r"[^a-z0-9=,./]", "", s)  # noqa: E731
    return norm(sa) == norm(sb)


def hash_equal(a: Optional[str], b: Optional[str]) -> bool:
    if a is None or b is None:
        return False
    return a.lower() == b.lower()


def padding_equal(a: Optional[str], b: Optional[str]) -> bool:
    if a is None or b is None:
        return False
    if a == b:
        return True
    return {a, b} <= {"pss", "other"} or {a, b} <= {"pkcs7", "pkcs5"}
