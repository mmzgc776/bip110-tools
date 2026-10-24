#!/usr/bin/env python3
"""Decryption of LND aezeed cipher seeds (and BIP39-equivalent encoding).

The 24 words printed by `lncli create` are NOT BIP39. They are aezeed: a
33-byte ciphertext that encodes the version, the birthday and the 16-byte
entropy used to build the wallet's BIP32 root.

Sources:
  - lnd/aezeed/cipherseed.go   (scheme: scrypt + AEZ v5, tau=8)
  - lnd/aezeed/cipherseed_test.go (official test vectors)
  - Yawning/aez (AEZ v5, reference implementation)

Layout of the 33 bytes:
    1 byte  external version (0)
   23 bytes ciphertext (19 of seed + 4 of MAC expansion)
    5 bytes scrypt salt
    4 bytes CRC32 checksum (big endian) over the first 29 bytes

Plaintext seed (19 bytes):
    1 byte  internal version (0)
    2 bytes birthday (days since the genesis block, big endian)
   16 bytes entropy  <- this is the BIP32 seed

Encryption: scrypt(passphrase, salt, N=32768, r=8, p=1) -> 32-byte key,
AEZ.Encrypt(key, nil, [version||salt], tau=8). If there is no passphrase the
literal "aezeed" is used.

Usage:
  python3 lib_aezeed.py selftest
"""

import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------------------------------------------------------------------
# aezeed scheme constants
# ---------------------------------------------------------------------------

NUM_MNEMONIC_WORDS = 24
BITS_PER_WORD = 11
ENCIPHERED_SIZE = 33          # what the 24 words encode
DECIPHERED_SIZE = 19          # version || birthday(2) || entropy(16)
ENTROPY_SIZE = 16
SALT_SIZE = 5
CHECKSUM_SIZE = 4
CIPHER_TEXT_EXPANSION = 4     # tau = 8 bytes / 2
EXTERNAL_VERSION = 0
# INTERNAL version of the plaintext (byte 0 of the decrypted block). It is not
# the encryption version (`EXTERNAL_VERSION`) but the key-derivation scheme:
#   0 = KeyDerivationVersionLegacy
#   1 = KeyDerivationVersionTaproot (enables BIP86, m/86'/0'/0')
# LND accepts both (`keychain.IsKnownVersion`). The public LND vectors are old
# and carry 0; wallets created with taproot carry 1.
INTERNAL_VERSIONS = {
    0: "legacy",
    1: "taproot (BIP86)",
}
INTERNAL_VERSION = 1          # the one a taproot wallet uses

SCRYPT_N = 32768
SCRYPT_R = 8
SCRYPT_P = 1

DEFAULT_PASSPHRASE = b"aezeed"
BITCOIN_GENESIS_TS = 1231006505
SECONDS_PER_DAY = 24 * 60 * 60

# CRC32-C (Castagnoli), the one aezeed uses:
# crc32.MakeTable(crc32.Castagnoli) in Go.
# Reflected polynomial 0x82F63B78, init and xorout 0xFFFFFFFF.
CRC_TABLE = []
for _n in range(256):
    _c = _n
    for _k in range(8):
        _c = (_c >> 1) ^ (0x82F63B78 if _c & 1 else 0)
    CRC_TABLE.append(_c)


def crc32_aezeed(data):
    """CRC32 with the aezeed polynomial, same as zlib.crc32."""
    c = 0xFFFFFFFF
    for b in data:
        c = CRC_TABLE[(c ^ b) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Wordlist: aezeed uses the English BIP39 list
# ---------------------------------------------------------------------------


def _load_wordlist():
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (os.path.join(here, "data", "bip39_english.txt"),):
        if os.path.exists(cand):
            with open(cand, encoding="utf-8") as f:
                return [w.strip() for w in f if w.strip()]
    return None


# ---------------------------------------------------------------------------
# Mnemonic <-> bytes
# ---------------------------------------------------------------------------


def mnemonic_to_bytes(words):
    """24 words -> 33 bytes. Raises ValueError if anything is off."""
    if isinstance(words, str):
        words = words.split()
    if len(words) != NUM_MNEMONIC_WORDS:
        raise ValueError(f"aezeed needs {NUM_MNEMONIC_WORDS} words, "
                         f"not {len(words)}")
    wl = _load_wordlist()
    if wl is None:
        raise ValueError("cannot find data/bip39_english.txt")
    index = {w: i for i, w in enumerate(wl)}

    # 24 words x 11 bits = 264 bits = exactly 33 bytes.
    acc = 0
    for w in words:
        if w not in index:
            raise ValueError(f"word not in the list: {w}")
        acc = (acc << BITS_PER_WORD) | index[w]
    total_bits = NUM_MNEMONIC_WORDS * BITS_PER_WORD
    acc <<= (8 - (total_bits % 8)) % 8   # align to bytes (zero here)
    nbytes = total_bits // 8
    return acc.to_bytes(nbytes, "big")


def bytes_to_mnemonic(data):
    """33 bytes -> 24 words."""
    if len(data) != ENCIPHERED_SIZE:
        raise ValueError(f"expected {ENCIPHERED_SIZE} bytes")
    wl = _load_wordlist()
    if wl is None:
        raise ValueError("cannot find data/bip39_english.txt")
    acc = int.from_bytes(data, "big")
    words = []
    for i in range(NUM_MNEMONIC_WORDS):
        shift = (NUM_MNEMONIC_WORDS - 1 - i) * BITS_PER_WORD
        words.append(wl[(acc >> shift) & 0x7FF])
    return words


# ---------------------------------------------------------------------------
# AEZ v5 (only what aezeed needs: decrypt 19 bytes -> aezTiny branch)
# ---------------------------------------------------------------------------

BLOCK = 16


def _aes_encrypt_block(key, block):
    """AES-128 of a 16-byte block."""
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def _xtime(a):
    """Multiplication by x in GF(2^8) with the AES polynomial."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _gf_mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _xor16(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _aez_extract(k):
    """AEZ extract: if the key is 48 bytes it is used as is; otherwise,
    BLAKE2b-384."""
    if len(k) == 48:
        return k
    return hashlib.blake2b(k, digest_size=48).digest()


# ---------------------------------------------------------------------------
# AEZ AES core: rounds always with MixColumns, embedded keys
# ---------------------------------------------------------------------------

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")


def _build_t_tables():
    """Rijndael T tables (te0..te3), like the ones in the AEZ reference."""
    te0 = []
    for x in range(256):
        s = _SBOX[x]
        b2 = _xtime(s)
        b3 = b2 ^ s
        te0.append((b2 << 24) | (s << 16) | (s << 8) | b3)

    def rol32(v, n):
        return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF

    return te0, [rol32(v, 8) for v in te0], [rol32(v, 16) for v in te0], \
        [rol32(v, 24) for v in te0]


_TE0, _TE1, _TE2, _TE3 = _build_t_tables()


class AEZ:
    """Minimal AEZ v5 for the aezeed case.

    Note: AEZ's AES4/AES10 are NOT standard AES applied in cascade. They are
    its own rounds that always apply MixColumns (including the last one) and
    use the extracted material itself as key words:

        AES4(j, i, l, src) = rounds4(j ^ i ^ l ^ src)
        AES10(l, src)      = rounds10(src ^ l)

    The AES4 keys are [J, I, L] (3 x 16 bytes) and the AES10 keys are
    [I, J, L] repeated three times plus I.
    """

    def __init__(self, key):
        ek = _aez_extract(key)
        # Subkeys I, J, L per eState.init() in aez.go (round_vartime.go):
        #   I = [1I, 2I]         2I = 2*1I
        #   J = [1J, 2J, 4J]     2J = 2*1J, 4J = 2*2J
        #   L[0] = 0^16,  L[1] = ek[32:48]
        #   L[2] = 2*L1,      L[3] = L2^L1
        #   L[4] = 2*L2,      L[5] = L4^L1
        #   L[6] = 2*L3,      L[7] = L6^L1
        # NOTE: L[3] is NOT 4*L1 nor L[5] 5*L1; they use XOR, not cascaded
        # doubling. And L[1] is NOT 1J: it is the third slice of the key.
        self.I = [ek[0:16], _dbl(ek[0:16])]
        j1 = ek[16:32]
        j2 = _dbl(j1)
        self.J = [j1, j2, _dbl(j2)]
        l1 = ek[32:48]
        l2 = _dbl(l1)
        l3 = bytes(a ^ b for a, b in zip(l2, l1))
        l4 = _dbl(l2)
        l5 = bytes(a ^ b for a, b in zip(l4, l1))
        l6 = _dbl(l3)
        l7 = bytes(a ^ b for a, b in zip(l6, l1))
        self.L = [bytes(BLOCK), l1, l2, l3, l4, l5, l6, l7]

        # key words as big-endian uint32: I, J, L
        keys = [int.from_bytes(ek[4 * i:4 * i + 4], "big") for i in range(12)]
        self._iK = tuple(keys[0:4])
        self._jK = tuple(keys[4:8])
        self._lK = tuple(keys[8:12])

    # -- rounds ---------------------------------------------------------

    def _round(self, s, keys, off):
        """One AES round: Sbox, ShiftRows, MixColumns and AddRoundKey.

        Unlike standard AES, AEZ applies MixColumns in ALL rounds, including
        the last one.
        """
        s0, s1, s2, s3 = s
        return [
            _TE0[(s0 >> 24) & 0xFF] ^ _TE1[(s1 >> 16) & 0xFF]
            ^ _TE2[(s2 >> 8) & 0xFF] ^ _TE3[s3 & 0xFF] ^ keys[off],
            _TE0[(s1 >> 24) & 0xFF] ^ _TE1[(s2 >> 16) & 0xFF]
            ^ _TE2[(s3 >> 8) & 0xFF] ^ _TE3[s0 & 0xFF] ^ keys[off + 1],
            _TE0[(s2 >> 24) & 0xFF] ^ _TE1[(s3 >> 16) & 0xFF]
            ^ _TE2[(s0 >> 8) & 0xFF] ^ _TE3[s1 & 0xFF] ^ keys[off + 2],
            _TE0[(s3 >> 24) & 0xFF] ^ _TE1[(s0 >> 16) & 0xFF]
            ^ _TE2[(s1 >> 8) & 0xFF] ^ _TE3[s2 & 0xFF] ^ keys[off + 3],
        ]

    @staticmethod
    def _load(block):
        return [int.from_bytes(block[i:i + 4], "big") for i in range(0, 16, 4)]

    @staticmethod
    def _store(s):
        return b"".join(x.to_bytes(4, "big") for x in s)

    def _aes4(self, j, i, l, x):
        """AES4(j, i, l, x): 16 chained rounds J,I,L,zero over j^i^l^x."""
        s = self._load(_xor16(_xor16(_xor16(j, i), l), x))
        for k in (self._jK, self._iK, self._lK, (0, 0, 0, 0)):
            s = self._round(s, k, 0)
        return self._store(s)

    def _aes10(self, l, x):
        """AES10(l, x): rounds I,J,L repeated 3 times and a fourth one of I."""
        s = self._load(_xor16(x, l))
        for _ in range(3):
            s = self._round(s, self._iK, 0)
            s = self._round(s, self._jK, 0)
            s = self._round(s, self._lK, 0)
        s = self._round(s, self._iK, 0)
        return self._store(s)

    # -- aezHash -------------------------------------------------------

    def aez_hash(self, nonce, ad, tau):
        """Delta = aezHash(nonce, ad, tau).

        NOTE: `tau` is in BYTES (as in the Go reference), NOT in bits.
        It is written big-endian in the last 4 bytes of the first block.
        ad is a list of vectors; for aezeed there is only one
        (version || salt) and the nonce is empty.
        """
        buf = bytearray(BLOCK)
        buf[12:16] = (tau & 0xFFFFFFFF).to_bytes(4, "big")

        # sum = AES4(J ^ J2, 2I, 1L, buf)   -> E(3,1)
        J = _xor16(self.J[0], self.J[1])          # J ^ J2
        total = self._aes4(J, self.I[1], self.L[1], bytes(buf))

        # empty nonce: a padding block is still processed.
        # Exact semantics of the Go for: the block uses L[i%8] and I with i
        # NOT incremented; the increment and the doubling happen at the end.
        empty = len(nonce) == 0
        n = nonce
        i = 1
        nbytes = len(n)
        I = self.I[1]
        while nbytes >= BLOCK:
            b = self._aes4(self.J[2], I, self.L[i % 8], n[:BLOCK])
            total = _xor16(total, b)
            n = n[BLOCK:]
            nbytes -= BLOCK
            # Reference order: double BEFORE incrementing i, that is, after
            # the block with i a multiple of 8 (not of 7).
            if i % 8 == 0:
                I = _dbl(I)
            i += 1
        if nbytes > 0 or empty:
            buf = bytearray(BLOCK)
            buf[:len(n)] = n
            buf[len(n)] = 0x80
            b = self._aes4(self.J[2], self.I[0], self.L[0], bytes(buf))
            total = _xor16(total, b)

        # each additional-data vector
        for k, p in enumerate(ad):
            empty = len(p) == 0
            nbytes = len(p)
            I = self.I[1]
            # J_k = multBlock(5+k, 1J)
            Jk = _mult_int(self.J[0], 5 + k)
            i = 1
            while nbytes >= BLOCK:
                b = self._aes4(Jk, I, self.L[i % 8], p[:BLOCK])
                total = _xor16(total, b)
                p = p[BLOCK:]
                nbytes -= BLOCK
                # Same order as the reference: double before incrementing.
                if i % 8 == 0:
                    I = _dbl(I)
                i += 1
            if nbytes > 0 or empty:
                buf = bytearray(BLOCK)
                buf[:len(p)] = p
                buf[len(p)] = 0x80
                b = self._aes4(Jk, self.I[0], self.L[0], bytes(buf))
                total = _xor16(total, b)
        return total

    # -- aezTiny (for messages of 1 to 31 bytes) ------------------------

    def aez_tiny(self, delta, data, decrypt=False):
        """Encrypts/decrypts 1 to 31 bytes with AEZ's 'tiny' branch.

        It includes the MAC bit: for messages shorter than 16 bytes, the
        reference does an AES4(0, 2I, L3, delta ^ padded) and mixes its high
        bit into out[0] (when encrypting) or unmixes it before the loop (when
        decrypting). Without that, aezeed's 4-byte MAC never checks out.
        """
        n = len(data)
        if n == 0 or n >= 32:
            raise ValueError("aez_tiny only covers 1 to 31 bytes")

        if n == 1:
            rounds = 24
            i = 7
        elif n == 2:
            rounds = 16
            i = 7
        elif n < 16:
            rounds = 10
            i = 7
        else:
            rounds = 8
            i = 6

        half = (n + 1) // 2
        offset = n // 2

        L = bytearray(BLOCK)
        R = bytearray(BLOCK)
        L[:half] = data[:half]
        R[:half] = data[offset:offset + half]

        mask = 0x00
        pad = 0x80
        if n & 1:
            # shift R left by half a nibble
            for k in range(offset):
                R[k] = ((R[k] << 4) | (R[k + 1] >> 4)) & 0xFF
            R[offset] = (R[offset] << 4) & 0xFF
            pad = 0x08
            mask = 0xF0

        j = 0
        step = 1
        if decrypt:
            # When decrypting, the MAC bit is unmixed first.
            if n < 16:
                buf = bytearray(BLOCK)
                buf[:n] = data
                buf[0] |= 0x80
                b = _xor16(bytes(buf), delta)
                tmp = self._aes4(_zero(), self.I[1], self.L[3], b)
                L[0] ^= tmp[0] & 0x80
            j = rounds - 1
            step = -1

        for _k in range(rounds // 2):
            # L ^= E(0,i)( (R & mask) | pad ^ delta , j )
            buf = bytearray(BLOCK)
            buf[:half] = R[:half]
            buf[offset] = (buf[offset] & mask) | pad
            b = _xor16(bytes(buf), delta)
            b = bytearray(b)
            b[15] ^= j & 0xFF
            t = self._aes4(_zero(), self.I[1], self.L[i], bytes(b))
            L = bytearray(_xor16(bytes(L), t))

            # R ^= E(0,i)( (L & mask) | pad ^ delta , j+step )
            buf = bytearray(BLOCK)
            buf[:half] = L[:half]
            buf[offset] = (buf[offset] & mask) | pad
            b = _xor16(bytes(buf), delta)
            b = bytearray(b)
            b[15] ^= (j + step) & 0xFF
            t = self._aes4(_zero(), self.I[1], self.L[i], bytes(b))
            R = bytearray(_xor16(bytes(R), t))

            j = (j + 2 * step) & 0xFF

        out = bytearray(n)
        out[:offset] = R[:offset]
        out[offset:offset + half] = L[:half]
        if n & 1:
            for k in range(n - 1, offset, -1):
                out[k] = ((out[k] >> 4) | (out[k - 1] << 4)) & 0xFF
            out[offset] = ((L[0] >> 4) | (R[offset] & 0xF0)) & 0xFF

        # MAC bit when encrypting (messages shorter than 16 bytes).
        if not decrypt and n < 16:
            buf = bytearray(BLOCK)
            buf[:n] = out
            buf[0] |= 0x80
            b = _xor16(bytes(buf), delta)
            tmp = self._aes4(_zero(), self.I[1], self.L[3], b)
            out[0] ^= tmp[0] & 0x80

        return bytes(out)


def _zero():
    return bytes(BLOCK)


# -- GF(2^128) arithmetic for the L subkeys ----------------------------------


def _dbl(block):
    """Doubles a block in GF(2^128) with the AEZ/GCM polynomial."""
    v = int.from_bytes(block, "big")
    v <<= 1
    if v >> 128:
        v ^= (1 << 128) | 0x87
    return (v & ((1 << 128) - 1)).to_bytes(16, "big")


def _mult_int(block, i):
    """i * block in GF(2^128), by successive doublings."""
    result = bytes(BLOCK)
    b = block
    while i:
        if i & 1:
            result = bytes(x ^ y for x, y in zip(result, b))
        b = _dbl(b)
        i >>= 1
    return result


# ---------------------------------------------------------------------------
# aezeed API
# ---------------------------------------------------------------------------


class AezeedError(Exception):
    pass


def decipher_ex(mnemonic, passphrase=b""):
    """Like `decipher`, but also returns the internal version.

    24 words + passphrase -> (entropy, birthday, internal_version).

    The 16-byte entropy is the BIP32 seed of the LND wallet.
    Raises AezeedError if the words or the passphrase are not correct.
    """
    if isinstance(mnemonic, str):
        words = mnemonic.split()
    else:
        words = list(mnemonic)
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")

    raw = mnemonic_to_bytes(words)

    ext_version = raw[0]
    if ext_version != EXTERNAL_VERSION:
        raise AezeedError(f"unsupported external version {ext_version} "
                          f"(expected {EXTERNAL_VERSION})")

    checksum_offset = ENCIPHERED_SIZE - CHECKSUM_SIZE       # 29
    salt_offset = checksum_offset - SALT_SIZE               # 24
    salt = raw[salt_offset:checksum_offset]
    cipher_seed = raw[1:salt_offset]                        # 23 bytes
    checksum = int.from_bytes(raw[checksum_offset:], "big")

    # 1. word checksum
    fresh = crc32_aezeed(raw[:checksum_offset])
    if fresh != checksum:
        raise AezeedError(
            "the checksum of the 24 words does not match: a word is "
            "misspelled or in the wrong order")

    # 2. key via scrypt. N=32768, r=8, p=1 asks for ~32 MiB; OpenSSL limits
    #    the buffer to less by default, so maxmem has to be raised.
    pw = passphrase if passphrase else DEFAULT_PASSPHRASE
    try:
        key = hashlib.scrypt(pw, salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                             p=SCRYPT_P, dklen=32, maxmem=256 * 1024 * 1024)
    except TypeError:  # maxmem does not exist in this Python version
        key = hashlib.scrypt(pw, salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                             p=SCRYPT_P, dklen=32)

    # 3. decrypt AEZ
    ad = [bytes([EXTERNAL_VERSION]) + salt]     # AD = version || salt
    aez = AEZ(key)
    # lnd calls aez.Encrypt(key, nil, [ad], CipherTextExpansion, seed, nil)
    # and aez.Encrypt does aezHash(nonce, ad, tau*8): tau is MULTIPLIED.
    delta = aez.aez_hash(b"", ad, CIPHER_TEXT_EXPANSION * 8)
    try:
        plain = aez.aez_tiny(delta, cipher_seed, decrypt=True)
    except Exception as e:
        raise AezeedError(f"decryption failed: {e}")

    # The MAC is the last 4 bytes of the decrypted block, and AEZ requires
    # them to be ALL ZERO (yawning/aez Decrypt: sum |= x[len-tau+i], fails if
    # sum != 0). It is NOT re-encrypted: re-encrypting the block and comparing
    # it with the ciphertext is a self-sufficient round-trip that comes out the
    # same with any passphrase (false positive). Checking the zeros DOES depend
    # on the key, because delta and the L/I/J subkeys change with the passphrase.
    mac = plain[DECIPHERED_SIZE:DECIPHERED_SIZE + CIPHER_TEXT_EXPANSION]
    if any(mac):
        raise AezeedError(
            "the passphrase is wrong (the AEZ tag does not verify: "
            "the 4 MAC bytes are not zero)")

    body = plain[:DECIPHERED_SIZE]

    int_version = body[0]
    birthday = int.from_bytes(body[1:3], "big")
    entropy = body[3:3 + ENTROPY_SIZE]
    if int_version not in INTERNAL_VERSIONS:
        conocidas = ", ".join(f"{v} ({n})" for v, n in
                             sorted(INTERNAL_VERSIONS.items()))
        raise AezeedError(
            f"internal version {int_version} not supported (known: "
            f"{conocidas}). LND only knows 0 and 1.")

    return entropy, birthday, int_version


def decipher(mnemonic, passphrase=b""):
    """24 words + passphrase -> (entropy, birthday).

    Shortcut over `decipher_ex` for callers that do not need the internal
    version.
    """
    entropy, birthday, _version = decipher_ex(mnemonic, passphrase)
    return entropy, birthday


def to_bip39_compatible_seed(mnemonic, passphrase=b""):
    """Convenience alias: returns only the entropy (BIP32 seed)."""
    entropy, _birthday = decipher(mnemonic, passphrase)
    return entropy


def validate_aezeed_mnemonic(phrase):
    """Validates an aezeed phrase: 24 words from the BIP39 list + CRC32-C.

    It does NOT validate the BIP39 checksum (aezeed words do not carry one).
    Returns (ok, reason).
    """
    words = phrase.split()
    if len(words) != NUM_MNEMONIC_WORDS:
        return False, (f"{len(words)} words; aezeed always uses "
                       f"{NUM_MNEMONIC_WORDS}")
    wl = _load_wordlist()
    if wl is None:
        return False, "cannot find data/bip39_english.txt"
    index = {w: i for i, w in enumerate(wl)}
    unknown = [w for w in words if w.lower() not in index]
    if unknown:
        return False, (f"words outside the list: "
                       f"{', '.join(unknown[:3])}")
    try:
        raw = mnemonic_to_bytes([w.lower() for w in words])
    except ValueError as e:
        return False, str(e)
    want = int.from_bytes(raw[ENCIPHERED_SIZE - CHECKSUM_SIZE:], "big")
    got = crc32_aezeed(raw[:ENCIPHERED_SIZE - CHECKSUM_SIZE])
    if got != want:
        return False, ("the CRC32-C checksum does not match: a word is "
                       "misspelled or out of order")
    return True, ""


def checksum_offset_dummy():
    """DEPRECATED: use ENCIPHERED_SIZE - CHECKSUM_SIZE directly."""
    return ENCIPHERED_SIZE - CHECKSUM_SIZE


def prompt_aezeed(attempts=3):
    """Asks for the 24 aezeed words on stdin, without echo, validating CRC32-C.

    Same as the BIP39 prompt but with the correct aezeed validation.
    Returns the validated phrase. Raises SystemExit if it cannot.
    """
    import getpass
    for i in range(1, attempts + 1):
        try:
            raw = getpass.getpass(
                "aezeed phrase (24 words, not shown): ")
        except (EOFError, KeyboardInterrupt):
            raise SystemExit("\nInput cancelled.")
        phrase = " ".join(raw.split())
        if not phrase:
            print("  (empty)")
            continue
        ok, why = validate_aezeed_mnemonic(phrase)
        if not ok:
            print(f"  {why}")
            print(f"  Attempt {i} of {attempts}.")
            continue
        print(f"  OK: {len(phrase.split())} words, valid CRC32-C checksum.")
        return phrase
    raise SystemExit("Could not read a valid aezeed phrase.")


def birthday_to_date(birthday):
    """Birthday (days since the genesis block) -> human-readable date."""
    import datetime
    ts = BITCOIN_GENESIS_TS + birthday * SECONDS_PER_DAY
    return datetime.datetime.fromtimestamp(
        ts, datetime.timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# selftest with the official LND vectors
# ---------------------------------------------------------------------------

# From lnd/aezeed/cipherseed_test.go, VERIFIED against the reference
# implementation (Yawning/aez compiled in Go). The mnemonics were generated
# with scrypt(pass, "salt1") + aez.Encrypt(key, nil, [0||"salt1"], 4, plain).
TEST_ENTROPY = bytes.fromhex(
    "81b637d86359e6960de795e41e0b4cfd")
TEST_SALT = b"salt1"

VECTORS = [
    {
        "password": b"",
        "mnemonic": ("above judge emerge veteran reform crunch system all snap "
                     "please shoulder vault hurt city quarter cover enlist "
                     "swear success suggest drink wagon enrich body"),
        "birthday": 0,
    },
    {
        "password": b"!very_safe_55345_password*",
        "mnemonic": ("absorb century submit father path glove gloom super divert "
                     "garden ice mirror wisdom grass dice kit ugly castle "
                     "success suggest drink monster congress flight"),
        "birthday": 3365,
    },
]


def _encipher_for_test(entropy, birthday, version=0, passphrase=b"",
                       salt=b"salt1"):
    """Enciphers a seed (TESTS ONLY): returns the 24 words.

    It does not generate entropy and is not used in production; it exists to
    test decryption with internal-version-1 seeds, which the public LND
    vectors (version 0) do not cover.
    """
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")
    if len(entropy) != ENTROPY_SIZE:
        raise ValueError(f"entropy of {ENTROPY_SIZE} bytes, "
                         f"not {len(entropy)}")
    plain = (bytes([version]) + birthday.to_bytes(2, "big") + entropy
             + b"\x00" * CIPHER_TEXT_EXPANSION)
    pw = passphrase if passphrase else DEFAULT_PASSPHRASE
    key = hashlib.scrypt(pw, salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                         p=SCRYPT_P,
                         dklen=32, maxmem=256 * 1024 * 1024)
    aez = AEZ(key)
    ad = [bytes([EXTERNAL_VERSION]) + salt]
    delta = aez.aez_hash(b"", ad, CIPHER_TEXT_EXPANSION * 8)
    ctxt = aez.aez_tiny(delta, plain, decrypt=False)
    raw = bytes([EXTERNAL_VERSION]) + ctxt + salt
    raw += crc32_aezeed(raw).to_bytes(CHECKSUM_SIZE, "big")
    return " ".join(bytes_to_mnemonic(raw))


def selftest(verbose=True):
    fails = []

    # --- CRC32-C against a known value ---
    # CRC32-C of "123456789" is 0xE3069283.
    if crc32_aezeed(b"123456789") == 0xE3069283:
        print("CRC32-C (Castagnoli): OK")
    else:
        fails.append(f"CRC32-C: {crc32_aezeed(b'123456789'):#x} "
                     f"!= 0xe3069283")

    # --- round-trip mnemonic <-> bytes ---
    words = VECTORS[0]["mnemonic"].split()
    raw = mnemonic_to_bytes(words)
    if len(raw) == 33 and bytes_to_mnemonic(raw) == words:
        print("Mnemonic <-> 33 bytes: OK")
    else:
        fails.append("mnemonic/bytes round-trip failed")

    # --- word checksum of the vectors ---
    for v in VECTORS:
        r = mnemonic_to_bytes(v["mnemonic"].split())
        want = int.from_bytes(r[29:33], "big")
        got = crc32_aezeed(r[:29])
        if got != want:
            fails.append(f"vector checksum mismatch: {v['mnemonic'][:20]}")

    # --- full decryption against the official vectors ---
    ok = 0
    for v in VECTORS:
        try:
            entropy, birthday = decipher(v["mnemonic"], v["password"])
            if entropy == TEST_ENTROPY and birthday == v["birthday"]:
                ok += 1
                if verbose:
                    print(f"  vector OK: passphrase="
                          f"{'(empty)' if not v['password'] else 'yes'} "
                          f"-> birthday {birthday} "
                          f"({birthday_to_date(birthday)})")
            else:
                fails.append(
                    f"entropy/birthday mismatch: {entropy.hex()[:16]} "
                    f"{birthday} != {v['birthday']}")
        except Exception as e:
            fails.append(f"exception in vector: {e}")
    print(f"aezeed decryption: {ok}/{len(VECTORS)} official LND vectors")

    # --- a wrong passphrase must fail ---
    try:
        decipher(VECTORS[1]["mnemonic"], b"passphrase_inventada")
        fails.append("a wrong passphrase was NOT detected")
    except AezeedError:
        if verbose:
            print("Wrong passphrase: correctly rejected")

    # --- a modified word must fail the checksum ---
    words2 = list(VECTORS[0]["mnemonic"].split())
    words2[5] = "zoo" if words2[5] != "zoo" else "abandon"
    try:
        decipher(" ".join(words2), b"")
        fails.append("a modified word was NOT detected")
    except AezeedError:
        if verbose:
            print("Modified word: rejected by the checksum")

    # --- internal version 0 and 1 (round-trip with our own enciphering) ---
    # The LND vectors are version 0; a taproot wallet uses 1.
    rt_ok = 0
    for _ver in (0, 1):
        _m = _encipher_for_test(TEST_ENTROPY, 4242, version=_ver,
                                passphrase=b"prueba")
        _e, _b, _v = decipher_ex(_m, b"prueba")
        if _e == TEST_ENTROPY and _b == 4242 and _v == _ver:
            rt_ok += 1
        else:
            fails.append(f"version {_ver} round-trip failed")
    print(f"Internal version 0 and 1 (round-trip): {rt_ok}/2")

    # --- an unknown version must be rejected ---
    _m = _encipher_for_test(TEST_ENTROPY, 4242, version=7)
    try:
        decipher(_m, b"")
        fails.append("an unknown internal version was NOT rejected")
    except AezeedError:
        if verbose:
            print("Unknown internal version (7): correctly rejected")

    # --- aez_hash against the public Yawning/aez vectors ---
    # nonce = data[0], ad = data[1:], tau in BYTES.
    import json
    import os
    _hp = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "data", "aez_hash.json")
    if os.path.exists(_hp):
        with open(_hp, encoding="utf-8") as _f:
            _hv = json.load(_f)
        _ok = _n = 0
        for _c in _hv:
            _k = bytes.fromhex(_c["k"])
            _tau = _c["tau"]
            _datas = [bytes.fromhex(x) for x in _c["data"]]
            _nonce = _datas[0] if _datas else b""
            _ad = _datas[1:]
            _want = bytes.fromhex(_c["v"])
            _n += 1
            if AEZ(_k).aez_hash(_nonce, _ad, _tau) == _want:
                _ok += 1
        print(f"aez_hash (Yawning/aez): {_ok}/{_n} vectors")
        if _ok != _n:
            fails.append(f"aez_hash: {_n - _ok} of {_n} vectors fail")
    else:
        print("WARNING: no data/aez_hash.json")

    # --- aezeed phrase validation ---
    _okv, _ = validate_aezeed_mnemonic(VECTORS[0]["mnemonic"])
    if _okv:
        print("validate_aezeed_mnemonic: OK")
    else:
        fails.append("validate_aezeed_mnemonic rejects a valid vector")
    _w2 = list(VECTORS[0]["mnemonic"].split())
    _w2[5] = "zoo" if _w2[5] != "zoo" else "abandon"
    _bad, _ = validate_aezeed_mnemonic(" ".join(_w2))
    if not _bad:
        print("validate_aezeed_mnemonic: detects a modified word OK")
    else:
        fails.append("validate_aezeed_mnemonic accepts a modified phrase")

    if fails:
        print("\nFAILURES:")
        for f in fails[:10]:
            print("  -", f)
        return 1
    print("\nselftest aezeed: ALL OK")
    return 0


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        sys.exit(selftest())
    print(__doc__)
    sys.exit(2)
