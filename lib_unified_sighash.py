#!/usr/bin/env python3
"""SIGHASH_UNIFIED (BIP-110 / Bitcoin Knots) for bip110-tools.

Implements the opt-in algorithm from Knots PR 357: a BIP341-style message
with bit 0x20 in the hash type, protected by the `UnifiedSighash` tagged
hash. It provides one-way replay protection (towards chains that do not
implement the algorithm) and fixes CVE-2013-2292 and CVE-2020-14199 for
signatures that opt in.

References:
  - doc/unified-sighash.md from Bitcoin Knots v29.4.1.knots20260508
  - src/script/interpreter.cpp -> SignatureHashUnified()

Usage: `python3 lib_unified_sighash.py selftest` runs the 166 vectors from
src/test/data/unified_sighash.json.

Read-only: no network access and no files outside data/.
"""

import hashlib
import json
import os

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_UNIFIED = 0x20
SIGHASH_ANYONECANPAY = 0x80

EPOCH = 0

# script types
ST_BASE = 0        # bare / P2SH (legacy)
ST_WITNESS_V0 = 1  # segwit v0 (BIP143)
ST_TAPROOT = 2     # taproot key path (BIP341)
ST_TAPSCRIPT = 3   # tapscript (BIP342)


def tagged_hash(tag, msg):
    """BIP340: SHA256(SHA256(tag) || SHA256(tag) || msg)."""
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


# ---------------------------------------------------------------------------
# Minimal transaction serialization (to build the message)
# ---------------------------------------------------------------------------
# The UNIFIED message needs to read the tx in serialized form, just like
# BIP341. We implement a minimal parser: version, vin (outpoint + nSequence
# + scriptSig), vout (value + scriptPubKey), nLockTime.


def _le(n, size):
    return n.to_bytes(size, "little", signed=(size == 8))


def _read_compact_size(buf, pos):
    b = buf[pos]
    pos += 1
    if b < 0xFD:
        return b, pos
    if b == 0xFD:
        return int.from_bytes(buf[pos:pos + 2], "little"), pos + 2
    if b == 0xFE:
        return int.from_bytes(buf[pos:pos + 4], "little"), pos + 4
    return int.from_bytes(buf[pos:pos + 8], "little"), pos + 8


def _write_compact_size(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xFD" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xFE" + n.to_bytes(4, "little")
    return b"\xFF" + n.to_bytes(8, "little")


class TxOut:
    __slots__ = ("value", "script")

    def __init__(self, value, script):
        self.value = value      # int
        self.script = script    # bytes

    def serialize(self):
        return _le(self.value, 8) + _write_compact_size(len(self.script)) \
            + self.script


class OutPoint:
    __slots__ = ("txid", "vout")

    def __init__(self, txid, vout):
        self.txid = txid  # 32 bytes (internal order, not display)
        self.vout = vout

    def serialize(self):
        return self.txid + _le(self.vout, 4)


class TxIn:
    __slots__ = ("prevout", "sequence")

    def __init__(self, prevout, sequence):
        self.prevout = prevout
        self.sequence = sequence


class Tx:
    __slots__ = ("version", "vin", "vout", "locktime")

    def __init__(self, version, vin, vout, locktime):
        self.version = version
        self.vin = vin
        self.vout = vout
        self.locktime = locktime


def parse_raw_tx(hexstr):
    """Parses a serialized transaction (Bitcoin native format)."""
    buf = bytes.fromhex(hexstr)
    pos = 0
    version = int.from_bytes(buf[pos:pos + 4], "little", signed=True)
    pos += 4

    # marker + flag -> segwit; the Knots vectors do not use it, but we
    # support it just in case.
    is_segwit = False
    if buf[pos] == 0x00 and buf[pos + 1] == 0x01:
        is_segwit = True
        pos += 2

    n_in, pos = _read_compact_size(buf, pos)
    vin = []
    for _ in range(n_in):
        txid = buf[pos:pos + 32]
        pos += 32
        vout = int.from_bytes(buf[pos:pos + 4], "little")
        pos += 4
        script_len, pos = _read_compact_size(buf, pos)
        script = buf[pos:pos + script_len]
        pos += script_len
        sequence = int.from_bytes(buf[pos:pos + 4], "little")
        pos += 4
        vin.append(TxIn(OutPoint(txid, vout), sequence))

    n_out, pos = _read_compact_size(buf, pos)
    vout = []
    for _ in range(n_out):
        value = int.from_bytes(buf[pos:pos + 8], "little", signed=True)
        pos += 8
        script_len, pos = _read_compact_size(buf, pos)
        script = buf[pos:pos + script_len]
        pos += script_len
        vout.append(TxOut(value, script))

    if is_segwit:
        for _ in range(n_in):
            n_items, pos = _read_compact_size(buf, pos)
            for _ in range(n_items):
                item_len, pos = _read_compact_size(buf, pos)
                pos += item_len

    locktime = int.from_bytes(buf[pos:pos + 4], "little")
    return Tx(version, vin, vout, locktime)


# ---------------------------------------------------------------------------
# The five aggregates of the UNIFIED message
# ---------------------------------------------------------------------------


def sha_prevouts(vin):
    h = hashlib.sha256()
    for txin in vin:
        h.update(txin.prevout.serialize())
    return h.digest()


def sha_amounts(spent_outputs):
    h = hashlib.sha256()
    for value, _script in spent_outputs:
        h.update(_le(value, 8))
    return h.digest()


def sha_scripts(spent_outputs):
    h = hashlib.sha256()
    for _value, script in spent_outputs:
        h.update(_write_compact_size(len(script)))
        h.update(script)
    return h.digest()


def sha_sequences(vin):
    h = hashlib.sha256()
    for txin in vin:
        h.update(_le(txin.sequence, 4))
    return h.digest()


def sha_outputs(vout):
    h = hashlib.sha256()
    for out in vout:
        h.update(out.serialize())
    return h.digest()


# ---------------------------------------------------------------------------
# The UNIFIED message
# ---------------------------------------------------------------------------


def unified_sighash(script_code, tx, in_idx, hash_type, script_type,
                    spent_outputs, annex_hash=None, tapleaf_hash=None,
                    codeseparator_pos=0xFFFFFFFF):
    """Computes the UNIFIED digest and returns 32 bytes.

    script_type: 0 bare/P2SH, 1 segwit v0, 2 taproot key path, 3 tapscript.
    spent_outputs: list of (value, scriptPubKey) in input order.
    annex_hash: SHA256 of the serialized annex, or None if there is none.
    tapleaf_hash: 32 bytes (tapscript only).
    codeseparator_pos: 4 bytes LE (tapscript only; 0xffffffff = none).
    """
    taproot = script_type in (ST_TAPROOT, ST_TAPSCRIPT)
    if not (hash_type & SIGHASH_UNIFIED):
        raise ValueError("hash_type without the SIGHASH_UNIFIED bit (0x20)")

    # Each script type keeps its current reading. For taproot/tapscript,
    # BIP341 rejects a hash type it does not define.
    output_type = hash_type & 0x1F
    if taproot:
        if hash_type & ~(0x1F | SIGHASH_ANYONECANPAY | SIGHASH_UNIFIED):
            raise ValueError(f"hash_type {hex(hash_type)} not defined for taproot")
        if output_type not in (SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE):
            raise ValueError(f"output_type {output_type} not defined for taproot")

    anyonecanpay = bool(hash_type & SIGHASH_ANYONECANPAY)

    msg = bytearray()
    msg.append(EPOCH)                                   # 1 byte
    msg.append(hash_type)                               # 1 byte
    msg += _le(tx.version, 4)                           # 4 bytes LE
    msg += _le(tx.locktime, 5)                          # 5 bytes LE (the fifth is 0)

    if not anyonecanpay:
        msg += sha_prevouts(tx.vin)                     # 32
        msg += sha_amounts(spent_outputs)               # 32
        msg += sha_scripts(spent_outputs)               # 32
        msg += sha_sequences(tx.vin)                    # 32

    if output_type != SIGHASH_NONE and output_type != SIGHASH_SINGLE:
        msg += sha_outputs(tx.vout)                     # 32

    msg.append(script_type)                             # 1 byte

    if anyonecanpay:
        msg += tx.vin[in_idx].prevout.serialize()       # 36
        value, script = spent_outputs[in_idx]
        msg += _le(value, 8)                            # valor (8 bytes LE)
        msg += _write_compact_size(len(script)) + script
        msg += _le(tx.vin[in_idx].sequence, 4)          # 4
    else:
        msg += _le(in_idx, 4)                           # 4

    if not taproot:
        msg += _write_compact_size(len(script_code)) + script_code
    else:
        # The annex is committed to, otherwise it would be malleable.
        if annex_hash is not None:
            msg.append(1)
            msg += annex_hash                            # 32
        else:
            msg.append(0)

    if output_type == SIGHASH_SINGLE:
        if in_idx >= len(tx.vout):
            raise ValueError("SIGHASH_SINGLE without an output at the input index")
        msg += hashlib.sha256(tx.vout[in_idx].serialize()).digest()

    if script_type == ST_TAPSCRIPT:
        if tapleaf_hash is None and script_code is not None:
            # The tapleaf hash is derived from the script: BIP342
            # TapLeaf(leaf_version || compact_size(len) || script)
            tapleaf_hash = tagged_hash(
                "TapLeaf",
                bytes([0xC0]) + _write_compact_size(len(script_code))
                + script_code)
        if tapleaf_hash is None:
            raise ValueError("tapscript requires the tapleaf hash")
        msg += tapleaf_hash                             # 32
        msg.append(0)                                   # key version
        msg += _le(codeseparator_pos, 4)                # 4

    return tagged_hash("UnifiedSighash", bytes(msg))


# ---------------------------------------------------------------------------
# selftest against the Knots vectors
# ---------------------------------------------------------------------------


def _data_path(name):
    here = os.path.dirname(os.path.abspath(__file__))
    for c in (os.path.join(here, "data", name),):
        if os.path.exists(c):
            return c
    return None


def selftest(verbose=True):
    p = _data_path("unified_sighash_vectors.json")
    if not p:
        print("WARNING: missing data/unified_sighash_vectors.json")
        return 1
    with open(p, encoding="utf-8") as f:
        vectors = json.load(f)

    header = vectors[0]
    assert header == ["scriptCode", "rawTx", "inIdx", "hashType",
                      "scriptType", "spentOutputs", "sighash"], header

    by_type = {}
    fails = []
    total = 0
    for row in vectors[1:]:
        script_code_hex, raw_tx_hex, in_idx, hash_type, script_type, \
            spent_outputs_hex, want = row
        total += 1
        st = script_type
        try:
            tx = parse_raw_tx(raw_tx_hex)
            spent = [(int(v), bytes.fromhex(s)) for v, s in spent_outputs_hex]
            got = unified_sighash(
                bytes.fromhex(script_code_hex), tx, in_idx, hash_type, st,
                spent)
        except Exception as e:
            fails.append((st, f"exception: {e}"))
            by_type.setdefault(st, [0, 0])[1] += 1
            continue
        by_type.setdefault(st, [0, 0])
        if got.hex() == want:
            by_type[st][0] += 1
        else:
            by_type[st][1] += 1
            fails.append((st, f"{want[:16]}... != {got.hex()[:16]}... "
                              f"(idx {in_idx}, ht {hex(hash_type)})"))

    names = {0: "bare/P2SH", 1: "segwit v0", 2: "taproot", 3: "tapscript"}
    print(f"UNIFIED vectors: {total} total")
    for st in sorted(by_type):
        ok, bad = by_type[st]
        print(f"  type {st} ({names.get(st, '?')}): {ok} OK, {bad} failures")

    if fails:
        print("\nFAILURES (first 10):")
        for st, msg in fails[:10]:
            print(f"  - type {st}: {msg}")
        return 1
    print("\nselftest UNIFIED: ALL OK (166/166)")
    return 0


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        sys.exit(selftest())
    print(__doc__)
    sys.exit(2)
