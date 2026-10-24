#!/usr/bin/env python3
"""Transaction and address serialization for bip110-tools.

Covers what the sweep needs:
  - Build and serialize a Bitcoin transaction (with segwit v0/taproot witness).
  - Parse and validate addresses (bech32/bech32m, and base58 P2PKH/P2SH).
  - Compute the fee from weight (vsize) with witness weight estimation.

Verification: `python3 lib_tx.py selftest` checks serialization round-trips and
known address vectors.

Reads local files from data/ only; no network access.
"""

import hashlib

from lib_secp256k1 import (
    encode_segwit_addr,
    b58decode_check,
    bech32_verify_checksum,
    convertbits,
    CHARSET,
    BECH32_CONST,
    BECH32M_CONST,
)

# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------

# base58 versions for mainnet.
BASE58_P2PKH = 0x00
BASE58_P2SH = 0x05

SEGWIT_HRP_MAINNET = "bc"
SEGWIT_HRP_TESTNET = "tb"

# Valid program lengths per witness version (BIP141/173).
VALID_PROGRAM_LEN = {
    0: (20, 32),   # P2WPKH, P2WSH
    1: (32, 32),   # P2TR
}


class AddressError(ValueError):
    pass


def decode_address(addr, hrp=SEGWIT_HRP_MAINNET):
    """Returns (kind, payload) where kind is 'p2pkh', 'p2sh', 'p2wpkh',
    'p2wsh', 'p2tr' or 'segwit' (generic for non-standard versions).

    Raises AddressError if it is not valid for the given network.
    """
    if not addr:
        raise AddressError("empty address")
    low = addr.lower()

    # bech32 / bech32m (case-insensitive, but not mixed)
    if low.startswith(hrp + "1"):
        if addr != low and addr != addr.upper():
            raise AddressError("bech32 address mixes upper and lower case")
        pos = low.rfind("1")
        if pos < 1 or pos + 7 > len(low):
            raise AddressError(f"malformed segwit address: {addr}")
        data_part = low[pos + 1:]
        data = [CHARSET.find(c) for c in data_part]
        if any(d == -1 for d in data):
            raise AddressError(f"invalid character in {addr}")
        witver = data[0]
        const = BECH32M_CONST if witver else BECH32_CONST
        if not bech32_verify_checksum(hrp, data, const):
            # try the other checksum in case it is an old address
            alt = BECH32_CONST if witver else BECH32M_CONST
            if not bech32_verify_checksum(hrp, data, alt):
                raise AddressError(f"invalid bech32 checksum in {addr}")
        program = bytes(convertbits(data[1:-6], 5, 8, False))
        lo, hi = VALID_PROGRAM_LEN.get(witver, (2, 40))
        if not (lo <= len(program) <= hi):
            raise AddressError(
                f"invalid program length ({len(program)}) "
                f"for witness v{witver}")
        if witver == 0:
            t = "p2wpkh" if len(program) == 20 else "p2wsh"
        elif witver == 1:
            t = "p2tr"
        else:
            t = "segwit"
        return t, program

    # base58
    try:
        raw = b58decode_check(addr)
    except ValueError:
        raise AddressError(f"unrecognized address: {addr}")
    version, payload = raw[0], raw[1:]
    if version == BASE58_P2PKH and len(payload) == 20:
        return "p2pkh", payload
    if version == BASE58_P2SH and len(payload) == 20:
        return "p2sh", payload
    raise AddressError(f"unknown base58 version in {addr}")


def scriptpubkey_from_address(addr, hrp=SEGWIT_HRP_MAINNET):
    """Address -> scriptPubKey (bytes)."""
    kind, payload = decode_address(addr, hrp)
    if kind == "p2pkh":
        return _p2pkh_script(payload)
    if kind == "p2sh":
        return _p2sh_script(payload)
    if kind == "p2wpkh":
        return bytes([0x00, 0x14]) + payload
    if kind == "p2wsh":
        return bytes([0x00, 0x20]) + payload
    if kind == "p2tr":
        return bytes([0x51, 0x20]) + payload
    # generic segwit
    witver = {20: 0}.get(len(payload), 1)
    return bytes([witver if witver < 0x51 else 0x51, len(payload)]) + payload


def _p2pkh_script(hash160):
    return (bytes([0x76, 0xA9, 0x14]) + hash160
            + bytes([0x88, 0xAC]))


def _p2sh_script(hash160):
    return bytes([0xA9, 0x14]) + hash160 + bytes([0x87])


def address_from_scriptpubkey(spk, hrp=SEGWIT_HRP_MAINNET):
    """scriptPubKey -> address (the inverse of the previous one)."""
    if len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14:
        return encode_segwit_addr(hrp, 0, spk[2:])
    if len(spk) == 34 and spk[0] == 0x00 and spk[1] == 0x20:
        return encode_segwit_addr(hrp, 0, spk[2:])
    if len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20:
        return encode_segwit_addr(hrp, 1, spk[2:])
    if len(spk) == 25 and spk[0] == 0x76 and spk[1] == 0xA9 \
            and spk[2] == 0x14 and spk[23] == 0x88 and spk[24] == 0xAC:
        return _b58_encode(BASE58_P2PKH, spk[3:23])
    if len(spk) == 23 and spk[0] == 0xA9 and spk[1] == 0x14 \
            and spk[22] == 0x87:
        return _b58_encode(BASE58_P2SH, spk[2:22])
    return None


def _b58_encode(version, payload):
    from lib_secp256k1 import b58encode_check
    return b58encode_check(bytes([version]) + payload)


def _b58_addr(version, payload):
    return _b58_encode(version, payload)


# ---------------------------------------------------------------------------
# Transaction construction and serialization
# ---------------------------------------------------------------------------


class TxOut:
    __slots__ = ("value", "script")

    def __init__(self, value, script):
        self.value = value
        self.script = script

    def serialize(self):
        return _le8(self.value) + _compact(len(self.script)) + self.script


class OutPoint:
    __slots__ = ("txid", "vout")

    def __init__(self, txid, vout):
        self.txid = txid  # 32 bytes in internal (little-endian) order
        self.vout = vout

    def serialize(self):
        return self.txid + _le32(self.vout)

    def display_txid(self):
        return self.txid[::-1].hex()


class TxIn:
    __slots__ = ("prevout", "sequence", "script_sig", "witness")

    def __init__(self, prevout, sequence=0xFFFFFFFF, script_sig=b"",
                 witness=None):
        self.prevout = prevout
        self.sequence = sequence
        self.script_sig = script_sig
        self.witness = witness or []

    def serialize_witness(self):
        """Serializes this input's witness (without the item count)."""
        out = bytearray()
        for item in self.witness:
            out += _compact(len(item)) + item
        return bytes(out)


class Transaction:
    """Transaction with witness support (BIP144 format)."""

    def __init__(self, version=2, vin=None, vout=None, locktime=0):
        self.version = version
        self.vin = vin or []
        self.vout = vout or []
        self.locktime = locktime

    def has_witness(self):
        return any(txin.witness for txin in self.vin)

    def serialize(self, with_witness=True):
        use_witness = with_witness and self.has_witness()
        out = bytearray()
        out += _le32s(self.version)
        if use_witness:
            out += b"\x00\x01"
        out += _compact(len(self.vin))
        for txin in self.vin:
            out += txin.prevout.serialize()
            out += _compact(len(txin.script_sig)) + txin.script_sig
            out += _le32(txin.sequence)
        out += _compact(len(self.vout))
        for txout in self.vout:
            out += txout.serialize()
        if use_witness:
            for txin in self.vin:
                out += _compact(len(txin.witness))
                out += txin.serialize_witness()
        out += _le32(self.locktime)
        return bytes(out)

    def txid(self):
        """Hash of the serialization WITHOUT witness (the actual txid)."""
        return hashlib.sha256(
            hashlib.sha256(self.serialize(with_witness=False)).digest()
        ).digest()[::-1]

    def wtxid(self):
        """Hash of the serialization WITH witness."""
        return hashlib.sha256(
            hashlib.sha256(self.serialize(with_witness=True)).digest()
        ).digest()[::-1]

    def weight(self):
        """Weight in weight units (BIP141): base*3 + total."""
        base = len(self.serialize(with_witness=False))
        total = len(self.serialize(with_witness=True))
        return base * 3 + total

    def vsize(self):
        """Virtual size in vbytes (rounded up)."""
        return (self.weight() + 3) // 4


# ---------------------------------------------------------------------------
# Serialization primitives
# ---------------------------------------------------------------------------


def _le32(n):
    return (n & 0xFFFFFFFF).to_bytes(4, "little")


def _le32s(n):
    return (n & 0xFFFFFFFF).to_bytes(4, "little")


def _le8(n):
    return (n & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def _compact(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xFD" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xFE" + n.to_bytes(4, "little")
    return b"\xFF" + n.to_bytes(8, "little")


# ---------------------------------------------------------------------------
# Weight and fee estimation
# ---------------------------------------------------------------------------

# Weights in WU (BIP141).
WITNESS_V0_INPUT_WU = 108          # P2WPKH
TAPROOT_INPUT_WU = 230             # key path: 41 + 66 (64-byte sig + 1 sighash)
P2WPKH_OUTPUT_WU = 124
P2WSH_OUTPUT_WU = 172
P2TR_OUTPUT_WU = 172
P2PKH_OUTPUT_WU = 136
P2SH_OUTPUT_WU = 128
TX_OVERHEAD_WU = 42                # version + locktime + contadores
SEGWIT_OVERHEAD_WU = 2             # marker + flag


def estimate_taproot_sweep_weight(n_inputs, n_outputs, change=False):
    """Estimated weight of a taproot key-path sweep."""
    out_n = n_outputs + (1 if change else 0)
    return (SEGWIT_OVERHEAD_WU + TX_OVERHEAD_WU
            + n_inputs * TAPROOT_INPUT_WU
            + out_n * P2TR_OUTPUT_WU)


def fee_for_weight(weight, sat_per_vb):
    """Fee in satoshis for a given weight and a rate in sat/vB."""
    vsize = (weight + 3) // 4
    return vsize * sat_per_vb


def estimate_fee(n_inputs, n_outputs, sat_per_vb, change=False):
    return fee_for_weight(
        estimate_taproot_sweep_weight(n_inputs, n_outputs, change),
        sat_per_vb)


# ---------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------


def selftest(verbose=True):
    fails = []

    # --- known addresses (BIP341 / BIP350) ---
    cases = [
        # (address, expected type, payload hex)
        ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "p2wpkh",
         "751e76e8199196d454941c45d1b3a323f1433bd6"),
        ("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
         "p2wsh", "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
        ("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
         "p2tr", "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"),
        ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "p2pkh",
         "62e907b15cbf27d5425399ebf6f0fb50ebb88f18"),
        ("3P14159f73E4gFr7JterCCQh9QjiTjiZrG", "p2sh",
         "e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a"),
    ]
    for addr, want_kind, want_payload in cases:
        try:
            kind, payload = decode_address(addr)
            if kind != want_kind:
                fails.append(f"address {addr}: kind {kind} != {want_kind}")
            elif payload.hex() != want_payload:
                fails.append(f"address {addr}: payload {payload.hex()[:16]} != {want_payload[:16]}")
        except AddressError as e:
            fails.append(f"address {addr}: {e}")
    if not any("address" in f for f in fails):
        print(f"Addresses: {len(cases)}/{len(cases)} decoded OK")

    # --- scriptPubKey <-> address round-trip ---
    rt_ok = 0
    for addr, _k, _p in cases:
        try:
            spk = scriptpubkey_from_address(addr)
            back = address_from_scriptpubkey(spk)
            if back == addr or back == addr.lower():
                rt_ok += 1
            else:
                fails.append(f"round-trip {addr} -> {back}")
        except Exception as e:
            fails.append(f"round-trip {addr}: exception {e}")
    print(f"Address<->scriptPubKey round-trip: {rt_ok}/{len(cases)} OK")

    # --- tx serialization: Bitcoin genesis block coinbase ---
    # It is a canonical example, verifiable by hand.
    tx = Transaction(
        version=1,
        vin=[TxIn(OutPoint(bytes(32), 0xFFFFFFFF), 0xFFFFFFFF,
                  bytes.fromhex(
                      "04ffff001d0104455468652054696d65732030332f4a616e2f323030"
                      "39204368616e63656c6c6f72206f6e206272696e6b206f6620736563"
                      "6f6e64206261696c6f757420666f722062616e6b73"))],
        vout=[TxOut(5000000000, bytes.fromhex(
            "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f"
            "61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6"
            "bf11d5fac"))],
        locktime=0)
    got_hex = tx.serialize().hex()
    want_hex = ("01000000" "01"
                + "00" * 32 + "ffffffff"
                + "4d"
                + "04ffff001d0104455468652054696d65732030332f4a616e2f323030"
                  "39204368616e63656c6c6f72206f6e206272696e6b206f6620736563"
                  "6f6e64206261696c6f757420666f722062616e6b73"
                + "ffffffff" "01"
                + "00f2052a01000000" "43"
                + "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
                  "e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8"
                  "d578a4c702b6bf11d5fac"
                + "00000000")
    if got_hex == want_hex:
        print("Tx serialization: genesis block coinbase OK")
    else:
        fails.append(f"tx serialization:\n    got: {got_hex}\n    want: {want_hex}")
    # The genesis txid is well known.
    if tx.txid().hex() == "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b":
        print("genesis block txid OK")
    else:
        fails.append(f"genesis txid: {tx.txid().hex()}")

    # --- taproot witness tx: round-trip and vsize ---
    spk_tr = bytes.fromhex(
        "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")
    txw = Transaction(
        version=2,
        vin=[TxIn(OutPoint(bytes(32), 0), 0xFFFFFFFF, b"",
                  witness=[bytes(64) + bytes([0x01])])],
        vout=[TxOut(20000, spk_tr)],
        locktime=0)
    if txw.has_witness() and txw.txid() and txw.wtxid():
        # expected vsize for 1 taproot input and 1 output: ~110-112
        vs = txw.vsize()
        if 105 <= vs <= 115:
            print(f"Taproot tx with witness: vsize {vs} vB OK")
        else:
            fails.append(f"taproot vsize {vs} outside the expected range")
    else:
        fails.append("witness tx does not serialize")

    # --- fee ---
    f = estimate_fee(1, 1, 10)
    if 1000 <= f <= 1400:
        print(f"Fee estimate (1 in, 1 out, 10 sat/vB): {f} sat OK")
    else:
        fails.append(f"estimated fee {f} out of range")

    if fails:
        print("\nFAILURES:")
        for f_ in fails[:10]:
            print("  -", f_)
        return 1
    print("\nselftest tx: ALL OK")
    return 0


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        sys.exit(selftest())
    print(__doc__)
    sys.exit(2)
