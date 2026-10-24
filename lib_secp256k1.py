#!/usr/bin/env python3
"""secp256k1, BIP32, BIP39 and BIP340/BIP86 for bip110-tools. No dependencies.

Only covers what the BLAKE2b sweep needs:
  - secp256k1 curve arithmetic (affine; enough for 5 signatures).
  - BIP39: phrase -> seed (passphrase supported).
  - BIP32: seed -> xprv, derivation, xprv -> xpub.
  - BIP340: Schnorr signatures with tagged hashes.
  - BIP86: taproot key-path key.

Verification: `python3 lib_secp256k1.py selftest` runs the vectors downloaded
into data/.

Private keys are ints in local variables; nothing here writes to disk.
"""

import hashlib
import hmac
import os
import sys

# ---------------------------------------------------------------------------
# The secp256k1 curve
# ---------------------------------------------------------------------------

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)


def inv(a, m=P):
    return pow(a, -1, m)


def is_on_curve(p):
    if p is None:
        return True
    x, y = p
    return (y * y - (x * x * x + A * x + B)) % P == 0


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * inv(2 * y1) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k, p=G):
    k %= N
    if k == 0 or p is None:
        return None
    result = None
    addend = p
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def pubkey(seckey):
    assert 0 < seckey < N, "private key out of range"
    return point_mul(seckey)


def pubkey_compressed(p):
    """(x, y) -> 33 bytes with the parity prefix."""
    return bytes([2 + (p[1] & 1)]) + p[0].to_bytes(32, "big")


# ---------------------------------------------------------------------------
# BIP340: tagged hash and Schnorr
# ---------------------------------------------------------------------------


def tagged_hash(tag, msg):
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def has_even_y(p):
    return p[1] % 2 == 0


def lift_x(x_bytes):
    """32-byte x -> point (x, y) with even Y."""
    if len(x_bytes) != 32:
        raise ValueError("x must be 32 bytes")
    x = int.from_bytes(x_bytes, "big")
    if x >= P:
        raise ValueError("x out of range")
    y_sq = (pow(x, 3, P) + A * x + B) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        raise ValueError("x is not on the curve")
    return (x, y if has_even_y((x, y)) else P - y)


def schnorr_sign(msg32, seckey, aux_rand):
    """BIP340 signature. msg32: 32 bytes. aux_rand: 32 bytes."""
    assert 0 < seckey < N, "private key out of range"
    d = seckey
    P_pt = point_mul(d)
    if P_pt is None:
        raise ValueError("invalid key")
    if not has_even_y(P_pt):
        d = N - d
    t = bytes(a ^ b for a, b in zip(
        d.to_bytes(32, "big"),
        tagged_hash("BIP0340/aux", aux_rand)))
    k0 = int.from_bytes(
        tagged_hash("BIP0340/nonce", t + P_pt[0].to_bytes(32, "big") + msg32), "big") % N
    if k0 == 0:
        raise RuntimeError("zero nonce (negligible probability)")
    R = point_mul(k0)
    if not has_even_y(R):
        k0 = N - k0
    e = int.from_bytes(
        tagged_hash("BIP0340/challenge",
                    R[0].to_bytes(32, "big") + P_pt[0].to_bytes(32, "big") + msg32),
        "big") % N
    return R[0].to_bytes(32, "big") + ((k0 + e * d) % N).to_bytes(32, "big")


def schnorr_verify(msg32, pubkey_x32, sig):
    if len(msg32) != 32 or len(pubkey_x32) != 32 or len(sig) != 64:
        return False
    try:
        p = lift_x(pubkey_x32)
    except ValueError:
        return False
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if r >= P or s >= N:
        return False
    e = int.from_bytes(
        tagged_hash("BIP0340/challenge",
                    r.to_bytes(32, "big") + pubkey_x32 + msg32), "big") % N
    R = point_add(point_mul(s, G), point_mul(N - e, p))
    if R is None or not has_even_y(R) or R[0] != r:
        return False
    return True


# ---------------------------------------------------------------------------
# BIP32: seed -> xprv, derivation
# ---------------------------------------------------------------------------

XPRV_VERSION = 0x0488ADE4
XPUB_VERSION = 0x0488B21E
HARDENED = 0x80000000


class ExtendedKey:
    """BIP32 extended key. key_data: 32 private bytes (xprv) or 33 bytes
    of compressed pubkey (xpub)."""

    def __init__(self, version, depth, parent_fp, child_num, chain_code, key_data):
        self.version = version
        self.depth = depth
        self.parent_fp = parent_fp
        self.child_num = child_num
        self.chain_code = chain_code
        self.key_data = key_data

    # -- construction --------------------------------------------------

    @classmethod
    def from_seed(cls, seed):
        I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        return cls(XPRV_VERSION, 0, b"\x00\x00\x00\x00", 0, I[32:],
                   b"\x00" + I[:32])

    @classmethod
    def from_string(cls, s):
        raw = b58decode_check(s)
        if len(raw) != 78:
            raise ValueError("invalid extended key length")
        return cls(
            version=int.from_bytes(raw[:4], "big"),
            depth=raw[4],
            parent_fp=raw[5:9],
            child_num=int.from_bytes(raw[9:13], "big"),
            chain_code=raw[13:45],
            key_data=raw[45:78],
        )

    # -- serialization -------------------------------------------------

    def serialize(self, version=None):
        v = self.version if version is None else version
        return b58encode_check(
            v.to_bytes(4, "big")
            + bytes([self.depth])
            + self.parent_fp
            + self.child_num.to_bytes(4, "big")
            + self.chain_code
            + self.key_data)

    # -- properties ---------------------------------------------------

    @property
    def is_private(self):
        return self.key_data[:1] == b"\x00" and len(self.key_data) == 33

    def seckey(self):
        if not self.is_private:
            raise ValueError("this key is not private")
        return int.from_bytes(self.key_data[1:], "big")

    def public_key_point(self):
        if self.is_private:
            return pubkey(self.seckey())
        if len(self.key_data) != 33:
            raise ValueError("invalid pubkey length")
        return _decompress(self.key_data)

    def fingerprint(self):
        pub = self.public_key_point()
        pub_hash = hashlib.sha256(pubkey_compressed(pub)).digest()
        return _ripemd160(pub_hash)[:4]

    def neutered(self):
        """Public version (xpub) of this key."""
        if not self.is_private:
            return self
        return ExtendedKey(
            XPUB_VERSION, self.depth, self.parent_fp, self.child_num,
            self.chain_code, pubkey_compressed(self.public_key_point()))

    # -- derivation ----------------------------------------------------

    def derive(self, index):
        if index >= HARDENED:
            if not self.is_private:
                raise ValueError("hardened derivation requires xprv")
            data = b"\x00" + self.seckey().to_bytes(32, "big") \
                + index.to_bytes(4, "big")
        else:
            data = pubkey_compressed(self.public_key_point()) \
                + index.to_bytes(4, "big")
        I = hmac.new(self.chain_code, data, hashlib.sha512).digest()
        tweak = int.from_bytes(I[:32], "big")
        if tweak >= N:
            raise RuntimeError("invalid derivation (tweak out of range)")
        if self.is_private:
            child = (tweak + self.seckey()) % N
            if child == 0:
                raise RuntimeError("invalid derivation (zero key)")
            key_data = b"\x00" + child.to_bytes(32, "big")
        else:
            child = point_add(point_mul(tweak), self.public_key_point())
            key_data = pubkey_compressed(child)
        return ExtendedKey(
            self.version, self.depth + 1, self.fingerprint(),
            index, I[32:], key_data)

    def derive_path(self, path):
        if path.startswith("m/"):
            parts = path[2:].split("/")
        elif path.startswith("m"):
            parts = path[1:].split("/") if len(path) > 1 else []
        else:
            parts = path.split("/")
        key = self
        for p in parts:
            if not p:
                continue
            hardened = p[-1] in "'hH"
            idx = int(p.rstrip("'hH"))
            if hardened:
                idx += HARDENED
            key = key.derive(idx)
        return key


def _decompress(pub33):
    """33 compressed bytes -> point (x, y)."""
    if len(pub33) != 33 or pub33[0] not in (2, 3):
        raise ValueError("invalid compressed pubkey")
    x = int.from_bytes(pub33[1:], "big")
    y_sq = (pow(x, 3, P) + A * x + B) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        raise ValueError("pubkey is not on the curve")
    if (y & 1) != (pub33[0] & 1):
        y = P - y
    return (x, y)


def _ripemd160(data):
    try:
        return hashlib.new("ripemd160", data).digest()
    except ValueError:
        return _ripemd160_pure(data)


def _ripemd160_pure(data):
    """Pure RIPEMD-160, for when OpenSSL does not provide it (FIPS mode)."""
    # Round constants (word selection and rotation) from the RIPEMD-160 spec.
    RL = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ]
    RR = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ]
    SL = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    ]
    SR = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    ]
    KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]

    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def f(j, x, y, z):
        if j < 16:
            return x ^ y ^ z
        if j < 32:
            return (x & y) | (~x & 0xFFFFFFFF & z)
        if j < 48:
            return (x | ~y & 0xFFFFFFFF) ^ z
        if j < 64:
            return (x & z) | (y & ~z & 0xFFFFFFFF)
        return x ^ (y | ~z & 0xFFFFFFFF)

    msg = bytearray(data)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += (len(data) * 8 & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")

    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    for off in range(0, len(msg), 64):
        X = [int.from_bytes(msg[off + i * 4:off + i * 4 + 4], "little")
             for i in range(16)]
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            rnd = j // 16
            t = (al + f(j, bl, cl, dl) + X[RL[j]] + KL[rnd]) & 0xFFFFFFFF
            t = (rol(t, SL[j]) + el) & 0xFFFFFFFF
            al, el, dl, cl, bl = el, dl, rol(cl, 10), bl, t
            t = (ar + f(79 - j, br, cr, dr) + X[RR[j]] + KR[rnd]) & 0xFFFFFFFF
            t = (rol(t, SR[j]) + er) & 0xFFFFFFFF
            ar, er, dr, cr, br = er, dr, rol(cr, 10), br, t
        h = [
            (h[1] + cl + dr) & 0xFFFFFFFF,
            (h[2] + dl + er) & 0xFFFFFFFF,
            (h[3] + el + ar) & 0xFFFFFFFF,
            (h[4] + al + br) & 0xFFFFFFFF,
            (h[0] + bl + cr) & 0xFFFFFFFF,
        ]
    return b"".join(x.to_bytes(4, "little") for x in h)


# ---------------------------------------------------------------------------
# BIP86: taproot key-path key
# ---------------------------------------------------------------------------


def bip86_internal_key(seckey):
    return pubkey(seckey)


def bip86_output_key(seckey):
    """Returns (output_x32, tweaked_seckey).

    BIP341: P = point of the internal key **normalized to even Y** (x-only);
    t = TapTweak(x(P)); Q = P + t*G. The signing key is d (or -d if the raw
    internal key had odd Y) plus t.
    """
    internal_raw = bip86_internal_key(seckey)
    x32 = internal_raw[0].to_bytes(32, "big")
    tweak = int.from_bytes(tagged_hash("TapTweak", x32), "big") % N
    P_pt = lift_x(x32)  # normalizado a Y par
    output = point_add(P_pt, point_mul(tweak))
    d = seckey if has_even_y(internal_raw) else (N - seckey) % N
    tweaked = (d + tweak) % N
    return output[0].to_bytes(32, "big"), tweaked


# ---------------------------------------------------------------------------
# BIP39: phrase -> seed
# ---------------------------------------------------------------------------


def load_wordlist(lang="english", path=None):
    """Loads the BIP39 word list (2048 entries) or None if missing."""
    if path is None:
        here = os.path.dirname(os.path.abspath(__file__))
        for cand in (
            os.path.join(here, "data", f"bip39_{lang}.txt"),
            os.path.join(here, "data", "bip39_english.txt"),
        ):
            if os.path.exists(cand):
                path = cand
                break
    if path is None or not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return [w.strip() for w in f if w.strip()]


def validate_mnemonic(phrase):
    """Validates a BIP39 phrase: count, words and CHECKSUM.

    The checksum is what catches typos: the last words carry parity bits
    derived from SHA256 of the entropy, so a misspelled word (or one in the
    wrong order) makes it fail.

    Returns (ok, reason). If no wordlist is available, only the word count is
    validated.
    """
    words = phrase.split()
    n = len(words)
    if n not in (12, 15, 18, 21, 24):
        return False, (f"{n} words; must be 12, 15, 18, 21 or 24")

    wl = load_wordlist()
    if wl is None:
        return True, ""

    index = {w: i for i, w in enumerate(wl)}
    unknown = [w for w in words if w.lower() not in index]
    if unknown:
        return False, (f"words not in the BIP39 list: "
                       f"{', '.join(unknown[:3])}"
                       f"{'...' if len(unknown) > 3 else ''}")

    # 11 bits per word. The last total/33 bits are the checksum.
    bits = "".join(format(index[w.lower()], "011b") for w in words)
    total = n * 11
    cs_len = total // 33
    ent_len = total - cs_len
    entropy = int(bits[:ent_len], 2).to_bytes(ent_len // 8, "big")
    digest = hashlib.sha256(entropy).digest()
    want = "".join(format(b, "08b") for b in digest)[:cs_len]
    if bits[ent_len:] != want:
        return False, ("checksum mismatch: a word is misspelled or out of "
                       "order (check the last one especially)")
    return True, ""


def prompt_mnemonic(confirm=True, attempts=3):
    """Reads a BIP39 phrase interactively, without echo, with validation.

    Advantages over pasting it into the terminal:
      - It does not show up in the shell history (it never goes through argv).
      - It normalizes spaces: pasting with double spaces or newlines is fine.
      - It validates the BIP39 checksum BEFORE deriving anything, so a typo is
        caught here and not as a signature with the wrong key.

    Returns the validated phrase. Raises SystemExit if it cannot.
    """
    import getpass
    for i in range(1, attempts + 1):
        try:
            raw = getpass.getpass("BIP39 phrase (not shown): ")
        except (EOFError, KeyboardInterrupt):
            raise SystemExit("\nInput cancelled.")
        phrase = " ".join(raw.split())  # collapse spaces and newlines
        if not phrase:
            print("  (empty)")
            continue
        ok, why = validate_mnemonic(phrase)
        if not ok:
            print(f"  {why}")
            print(f"  Attempt {i} of {attempts}.")
            continue
        if confirm:
            again = getpass.getpass("Type it again to confirm: ")
            if " ".join(again.split()) != phrase:
                print("  The two phrases do not match.")
                print(f"  Attempt {i} of {attempts}.")
                continue
        print(f"  OK: {len(phrase.split())} words, valid checksum.")
        return phrase
    raise SystemExit("Could not read a valid BIP39 phrase.")


def _match_word(wl, typed):
    """Looks up a word by prefix.

    The English BIP39 list has the property that the first 4 letters identify
    each word uniquely, so 'aban' -> 'abandon'.

    Returns (unique, matches): unique is the word if typed is exact or the
    prefix is unambiguous; matches lists the options when it is ambiguous.
    """
    t = typed.lower().strip()
    if not t:
        return None, []
    if t in wl:
        return t, []
    m = [w for w in wl if w.startswith(t)]
    return (m[0] if len(m) == 1 else None), m


def prompt_mnemonic_words():
    """Asks for the phrase word by word, validating each one as it is typed.

    It is the most comfortable mode for typing or pasting one at a time:
      - Each word is validated against the BIP39 list on the spot.
      - It accepts prefixes: 'aban' completes to 'abandon' (the first 4
        letters are unique in the English list).
      - '!' restarts, '?' helps, '^' shows the previous word.
      - At the end it validates the CHECKSUM, which is what catches words that
        are correct but in the wrong order.

    Returns the validated phrase. Raises SystemExit if it cannot.
    """
    wl = load_wordlist()
    if wl is None:
        raise SystemExit(
            "Missing data/bip39_english.txt: cannot validate the words.")

    valid_counts = (12, 15, 18, 21, 24)
    print("\nHow many words does your phrase have? (12, 15, 18, 21 or 24)")
    n = None
    for _ in range(3):
        raw = input("  words: ").strip()
        if raw.isdigit() and int(raw) in valid_counts:
            n = int(raw)
            break
        print(f"  Must be one of: {', '.join(map(str, valid_counts))}.")
    if n is None:
        raise SystemExit("Could not determine the number of words.")

    print(f"\nType the {n} words, one per line.")
    print("You can abbreviate (4 letters are enough). '!' restarts, '?' helps.\n")

    words = []
    while len(words) < n:
        i = len(words) + 1
        try:
            typed = input(f"  {i:>2}/{n}: ").strip()
        except (EOFError, KeyboardInterrupt):
            raise SystemExit("\nCancelled.")
        low = typed.lower()

        if low == "!":
            words = []
            print("  restarted.\n")
            continue
        if low == "^":
            if words:
                print(f"      last one typed: {words[-1]}")
            else:
                print("      you have not typed any yet.")
            continue
        if low == "?":
            print("      4 letters are enough for every word in the English list.")
            print("      '!' restarts from the first one.")
            print("      '^' repeats the last word typed.")
            continue
        if not typed:
            continue

        uniq, matches = _match_word(wl, low)
        if uniq:
            if uniq != low:
                print(f"       -> {uniq}")
            words.append(uniq)
        elif matches:
            shown = ", ".join(matches[:8])
            more = f" (+{len(matches) - 8})" if len(matches) > 8 else ""
            print(f"      ambiguous ({len(matches)}): {shown}{more}")
        else:
            print("      not in the BIP39 list. Type it again.")

    phrase = " ".join(words)
    ok, why = validate_mnemonic(phrase)
    if not ok:
        # We do not get here without a valid wordlist, so the failure is the
        # checksum.
        raise SystemExit(
            f"\n{why}\nIt is almost certainly a word in the wrong order. "
            f"Try again.")

    print(f"\nPhrase read ({n} words, valid checksum):")
    for row in range(0, n, 4):
        chunk = words[row:row + 4]
        print("   " + "  ".join(f"{row + j + 1:>2}.{w:<10}"
                                for j, w in enumerate(chunk)))
    ans = input("\nIs it correct? (y/n): ").strip().lower()
    if ans not in ("y", "yes"):
        raise SystemExit("Cancelled. No key was derived.")
    return phrase


def mnemonic_to_seed(mnemonic, passphrase=""):
    import unicodedata
    m = unicodedata.normalize("NFKD", mnemonic).encode("utf-8")
    p = unicodedata.normalize("NFKD", "mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", m, p, 2048, 64)


def seed_to_master(seed):
    return ExtendedKey.from_seed(seed)


# ---------------------------------------------------------------------------
# base58
# ---------------------------------------------------------------------------

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode_check(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
    data, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4] != chk:
        raise ValueError("invalid base58 checksum")
    return data


def b58encode_check(data):
    data = data + hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


# ---------------------------------------------------------------------------
# bech32 / bech32m (decode and encode segwit addresses)
# ---------------------------------------------------------------------------

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3


def bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp, data, const):
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == const


def bech32_create_checksum(hrp, data, const):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0] * 6) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def convertbits(data, frombits, tobits, pad=True):
    acc = bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def decode_segwit_addr(addr):
    """(witness_version, program) or None."""
    if addr != addr.lower() and addr != addr.upper():
        return None
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr):
        return None
    hrp, data_part = addr[:pos], addr[pos + 1:]
    data = [CHARSET.find(c) for c in data_part]
    if any(d == -1 for d in data):
        return None
    const = BECH32M_CONST if data[0] else BECH32_CONST
    if not bech32_verify_checksum(hrp, data, const):
        return None
    witver = data[0]
    program = bytes(convertbits(data[1:-6], 5, 8, False))
    if witver > 16 or len(program) < 2 or len(program) > 40:
        return None
    if witver == 0 and len(program) not in (20, 32):
        return None
    return witver, program


def encode_segwit_addr(hrp, witver, program):
    data = [witver] + convertbits(program, 8, 5)
    const = BECH32M_CONST if witver else BECH32_CONST
    return hrp + "1" + "".join(CHARSET[d] for d in data
                               + bech32_create_checksum(hrp, data, const))


# ---------------------------------------------------------------------------
# High-level API
# ---------------------------------------------------------------------------


class TaprootKey:
    """Taproot key-path key (BIP86), ready to sign sighashes."""

    def __init__(self, seckey):
        self.seckey = seckey % N
        self.output_x32, self.effective = bip86_output_key(self.seckey)

    @classmethod
    def from_mnemonic(cls, mnemonic, path, passphrase=""):
        return cls.from_seed(mnemonic_to_seed(mnemonic, passphrase), path)

    @classmethod
    def from_xprv(cls, xprv, path):
        master = ExtendedKey.from_string(xprv)
        return cls.from_seed_bytes(master.key_data, path, master)

    @classmethod
    def from_seed(cls, seed, path):
        return cls.from_seed_bytes(seed, path, ExtendedKey.from_seed(seed))

    @classmethod
    def from_seed_bytes(cls, seed, path, master=None):
        if master is None:
            master = ExtendedKey.from_seed(seed)
        key = master.derive_path(path)
        return cls(key.seckey())

    def sign(self, msg32, aux_rand=None):
        if aux_rand is None:
            aux_rand = os.urandom(32)
        return schnorr_sign(msg32, self.effective, aux_rand)

    def verify(self, msg32, sig):
        return schnorr_verify(msg32, self.output_x32, sig)


# ---------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------


def _data_path(name):
    here = os.path.dirname(os.path.abspath(__file__))
    for c in (os.path.join(here, "data", name),):
        if os.path.exists(c):
            return c
    return None


def selftest(verbose=True):
    fails = []

    # BIP340
    p = _data_path("bip340_test_vectors.csv")
    if p:
        n = ok = 0
        with open(p, encoding="utf-8") as f:
            for line in f.read().splitlines()[1:]:
                f_ = line.split(",")
                if len(f_) < 7 or not f_[1]:
                    continue
                seckey, pub, aux, msg, sig, res = f_[1:7]
                n += 1
                s = schnorr_sign(bytes.fromhex(msg), int(seckey, 16),
                                 bytes.fromhex(aux))
                if s.hex().upper() == sig.upper():
                    ok += 1
                else:
                    fails.append(f"BIP340: signature mismatch ({line[:50]})")
        print(f"BIP340: {ok}/{n} vectors with private key OK")
    else:
        print("WARNING: no data/bip340_test_vectors.csv")

    # BIP39. The Trezor vectors use the legacy passphrase "TREZOR";
    # final BIP39 (empty passphrase) is verified with the official BIP
    # vector (all-zero entropy -> known seed).
    p = _data_path("bip39_test_vectors.json")
    if p:
        import json
        with open(p, encoding="utf-8") as f:
            v = json.load(f)
        n = ok = 0
        for lang, cases in v.items():
            for c in cases:
                n += 1
                if mnemonic_to_seed(c[1], "TREZOR").hex() == c[2]:
                    ok += 1
                else:
                    fails.append(f"BIP39 ({lang}): {c[1][:30]}")
        print(f"BIP39: {ok}/{n} vectors (legacy TREZOR passphrase) OK")
    else:
        print("WARNING: no data/bip39_test_vectors.json")

    # Official BIP39 vector: empty passphrase.
    official = "abandon abandon abandon abandon abandon abandon abandon " \
               "abandon abandon abandon abandon about"
    want = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811" \
           "aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea" \
           "6690f20ad3d8d48b2d2ce9e38e4"
    if mnemonic_to_seed(official).hex() == want:
        print("BIP39: official BIP vector (empty passphrase) OK")
    else:
        fails.append("BIP39 official vector: empty passphrase mismatch")

    # BIP32: full vector 1
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    m = ExtendedKey.from_seed(seed)
    chain = [
        ("m", "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
         "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"),
        ("m/0'", "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
         "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"),
        ("m/0'/1", "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
         "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"),
        ("m/0'/1/2'", "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
         "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"),
        ("m/0'/1/2'/2", "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
         "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"),
        ("m/0'/1/2'/2/1000000000",
         "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
         "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"),
    ]
    ok32 = 0
    for path, want_prv, want_pub in chain:
        k = m.derive_path(path)
        if k.serialize() != want_prv:
            fails.append(f"BIP32 xprv {path}: {k.serialize()[:20]} != {want_prv[:20]}")
        elif k.neutered().serialize() != want_pub:
            fails.append(f"BIP32 xpub {path}")
        else:
            ok32 += 1
    print(f"BIP32: {ok32}/{len(chain)} chains OK")

    # RIPEMD-160 (pubkey hash) against a known value:
    # HASH160(test-seed pubkey) - reference value from BIP32
    fp_ok = m.fingerprint().hex() == "3442193e"
    if fp_ok:
        print("BIP32: fingerprint (HASH160) OK")
    else:
        fails.append(f"BIP32 fingerprint: {m.fingerprint().hex()} != 3442193e")

    # BIP86: official vectors from the BIP (test phrase, empty passphrase).
    seed39 = mnemonic_to_seed(
        "abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon about")
    m39 = ExtendedKey.from_seed(seed39)
    want_root = ("xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1"
                 "kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu")
    if m39.serialize() != want_root:
        fails.append("BIP86: rootpriv does not match BIP86")
    want_out = [
        ("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
         "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"),
        ("a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb",
         None),
    ]
    ok86 = 0
    import hashlib as _h
    for idx, (want_x, want_addr) in enumerate(want_out):
        kprv = m39.derive_path(f"m/86'/0'/0'/0/{idx}")
        tk = TaprootKey(kprv.seckey())
        addr = encode_segwit_addr("bc", 1, tk.output_x32)
        msg = _h.sha256(b"selftest").digest()
        if tk.output_x32.hex() == want_x and \
                (want_addr is None or addr == want_addr) and \
                tk.verify(msg, tk.sign(msg)):
            ok86 += 1
        else:
            fails.append(f"BIP86 idx {idx}: {tk.output_x32.hex()[:16]}...")
    print(f"BIP86: {ok86}/{len(want_out)} official vectors OK")

    # UNIFIED sighash: the 166 Bitcoin Knots vectors.
    try:
        from lib_unified_sighash import selftest as unified_selftest
        if unified_selftest(verbose=False) != 0:
            fails.append("UNIFIED sighash: Knots vectors fail")
        else:
            print("UNIFIED sighash: 166/166 Knots vectors OK")
    except ImportError:
        fails.append("lib_unified_sighash.py is missing")

    if fails:
        print("\nFAILURES:")
        for f_ in fails[:10]:
            print("  -", f_)
        return 1
    print("\nselftest: ALL OK")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        sys.exit(selftest())
    print(__doc__)
    sys.exit(2)
