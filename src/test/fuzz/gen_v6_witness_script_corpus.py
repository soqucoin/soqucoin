#!/usr/bin/env python3
# Copyright (c) 2026 Soqucoin Labs Inc.
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Writes the seed corpus of the v6_witness_script fuzz target.

Each seed is one input in the layout test/fuzz/v6_witness_script.cpp documents:
a flag byte, a witness-shape byte, nVersion, nLockTime and nSequence of the
spending transaction, the satisfaction items, the witnessScript.

The scripts are the two shipped templates (the HTLC and the eLTOO update script
of lightning_script_tests::b1_script_vectors), the keyhash scripts of
dilithium_keyhash_committed_tests and keyhash_broadcast_tests, and the vectors
of v6_witness_script_opcode_set_tests and v6_checksequence_bip112_tests. Keys
and signatures are fixed byte patterns: no seed carries a signature that
verifies, so a keyhash check passes only where the seed selects the accepting
signature check.

The output is deterministic. Run it again after a change and commit the result:
    python3 src/test/fuzz/gen_v6_witness_script_corpus.py
"""

import hashlib
import os
import struct

CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")
PREFIX = "v6_witness_script_"

# Opcodes (script/script.h).
OP_0 = 0x00
OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e
OP_1NEGATE = 0x4f
OP_1 = 0x51
OP_IF = 0x63
OP_NOTIF = 0x64
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_DROP = 0x75
OP_DUP = 0x76
OP_CAT = 0x7e
OP_SUBSTR = 0x7f
OP_LEFT = 0x80
OP_RIGHT = 0x81
OP_SIZE = 0x82
OP_AND = 0x84
OP_OR = 0x85
OP_XOR = 0x86
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_MUL = 0x95
OP_DIV = 0x96
OP_MOD = 0x97
OP_SHA256 = 0xa8
OP_HASH160 = 0xa9
OP_CHECKSIG = 0xac
OP_CLTV = 0xb1
OP_CSV = 0xb2
OP_CTV = 0xb3
OP_CSFS = 0xb4
OP_CDKH = 0xb6
OP_CHECKPATAGG = 0xfd

# The flag byte: bits 0..5 the six deployment flags, bits 6..7 the signature check.
P2WSH, KEYHASH, CONTROLFLOW, CTV, APO, CSFS = 1, 2, 4, 8, 16, 32
ALL = P2WSH | KEYHASH | CONTROLFLOW | CTV | APO | CSFS
SIG_REAL, SIG_REFUSE, SIG_ACCEPT = 0, 1, 2

# The witness-shape byte.
PLAIN, NO_WITNESS, NO_TRAILER, PROGRAM_MISMATCH = 0, 1, 2, 3

SEQUENCE_FINAL = 0xffffffff
SEQUENCE_DISABLE = 0x80000000
SIGHASH_ALL = 0x01
SIGHASH_ANYPREVOUTANYSCRIPT = 0x42


def sha256(data):
    return hashlib.sha256(data).digest()


def op(n):
    """OP_1 to OP_16."""
    assert 1 <= n <= 16
    return bytes([OP_1 + n - 1])


def push(data):
    """A data push the way CScript's operator<< encodes it."""
    n = len(data)
    if n < OP_PUSHDATA1:
        return bytes([n]) + data
    if n <= 0xff:
        return bytes([OP_PUSHDATA1, n]) + data
    assert n <= 0xffff
    return bytes([OP_PUSHDATA2]) + struct.pack("<H", n) + data


def num(n):
    """A push of CScriptNum(n)."""
    if n == 0:
        return push(b"")
    negative = n < 0
    magnitude = abs(n)
    out = bytearray()
    while magnitude:
        out.append(magnitude & 0xff)
        magnitude >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if negative else 0x00)
    elif negative:
        out[-1] |= 0x80
    return push(bytes(out))


def ops(*parts):
    """Concatenates opcodes (ints) and encoded pushes (bytes)."""
    return b"".join(bytes([p]) if isinstance(p, int) else p for p in parts)


def key(i):
    """A 1,312-byte stand-in for an ML-DSA-44 public key."""
    return bytes((i * 31 + j) % 251 for j in range(1312))


def sig(i, hashtype=SIGHASH_ALL):
    """A 2,420-byte stand-in for a signature, with the hashtype byte."""
    return bytes((i * 17 + j) % 241 for j in range(2420)) + bytes([hashtype])


def keyhash(i):
    return sha256(key(i))


def seed(flags, sig_mode, script, items=(), shape=PLAIN, version=2, locktime=0, sequence=0):
    assert len(items) <= 255
    out = bytearray([flags | (sig_mode << 6), shape])
    out += struct.pack("<iII", version, locktime, sequence)
    out.append(len(items))
    for item in items:
        out += struct.pack("<H", len(item)) + item
    return bytes(out) + script


# --- the scripts ---------------------------------------------------------

def single(i):
    return ops(push(keyhash(i)), OP_CDKH, op(1))


def two_of_two(a, b):
    return ops(push(keyhash(b)), OP_CDKH, push(keyhash(a)), OP_CDKH, op(1))


def htlc(hashlock, kh_payee, kh_payer, cltv=500):
    return ops(OP_IF,
               OP_SHA256, push(hashlock), OP_EQUALVERIFY, push(kh_payee), OP_CDKH, op(1),
               OP_ELSE,
               num(cltv), OP_CLTV, OP_DROP, push(kh_payer), OP_CDKH, op(1),
               OP_ENDIF)


def eltoo(kh_au, kh_bu, kh_as, kh_bs, state=600000, csv=288):
    return ops(OP_IF,
               num(state + 1), OP_CLTV, OP_DROP, push(kh_bu), OP_CDKH, push(kh_au), OP_CDKH, op(1),
               OP_ELSE,
               num(csv), OP_CSV, OP_DROP, push(kh_bs), OP_CDKH, push(kh_as), OP_CDKH, op(1),
               OP_ENDIF)


PREIMAGE = bytes([0x07]) * 32
TRUE = bytes([0x01])
FALSE = b""

# The templates with keyhashes of the stand-in keys, so the keyhash check can pass.
HTLC = htlc(sha256(PREIMAGE), keyhash(1), keyhash(2))
ELTOO = eltoo(keyhash(1), keyhash(2), keyhash(3), keyhash(4))
# The templates byte for byte as b1_script_vectors emits them.
HTLC_B1 = htlc(bytes([0xab]) * 32, bytes([0x55]) * 32, bytes([0x66]) * 32)
ELTOO_B1 = eltoo(bytes([0x11]) * 32, bytes([0x22]) * 32, bytes([0x33]) * 32, bytes([0x44]) * 32)

HTLC_CLAIM = [sig(1), key(1), PREIMAGE, TRUE]
HTLC_REFUND = [sig(2), key(2), FALSE]
ELTOO_UPDATE = [sig(1), key(1), sig(2), key(2), TRUE]
ELTOO_SETTLE = [sig(3), key(3), sig(4), key(4), FALSE]

BITCOIN_HTLC = ops(OP_IF,
                   OP_HASH160, push(bytes([0x11]) * 20), OP_EQUALVERIFY, push(bytes([0x02]) * 33), OP_CHECKSIG,
                   OP_ELSE,
                   num(500), OP_CLTV, OP_DROP, push(bytes([0x03]) * 33), OP_CHECKSIG,
                   OP_ENDIF)

A, R, L = SIG_ACCEPT, SIG_REFUSE, SIG_REAL

SEEDS = [
    # One keyhash.
    ("keyhash_single", seed(ALL, A, single(0), [sig(0), key(0)])),
    ("keyhash_single_signature_refused", seed(ALL, R, single(0), [sig(0), key(0)])),
    ("keyhash_single_real_verification", seed(ALL, L, single(0), [sig(0), key(0)])),
    ("keyhash_single_dormant", seed(0, A, single(0), [sig(0), key(0)])),
    ("keyhash_single_no_witness", seed(ALL, A, single(0), [sig(0), key(0)], shape=NO_WITNESS)),
    ("keyhash_single_no_trailer", seed(ALL, A, single(0), [sig(0), key(0)], shape=NO_TRAILER)),
    ("keyhash_single_program_mismatch", seed(ALL, A, single(0), [sig(0), key(0)], shape=PROGRAM_MISMATCH)),
    ("keyhash_single_other_key", seed(ALL, A, single(0), [sig(0), key(1)])),
    ("keyhash_single_prefixed_key", seed(ALL, A, single(0), [sig(0), bytes([0x00]) + key(0)])),
    ("keyhash_single_anyprevout", seed(ALL, A, single(0), [sig(0, SIGHASH_ANYPREVOUTANYSCRIPT), key(0)])),
    ("keyhash_single_anyprevout_apo_clear", seed(ALL & ~APO, A, single(0), [sig(0, SIGHASH_ANYPREVOUTANYSCRIPT), key(0)])),
    ("keyhash_opcode_keyhash_clear", seed(P2WSH | CONTROLFLOW, A, ops(push(keyhash(0)), OP_CDKH))),
    # Two keyhashes.
    ("keyhash_2of2", seed(ALL, A, two_of_two(1, 2), [sig(1), key(1), sig(2), key(2)])),
    ("keyhash_2of2_one_pair", seed(ALL, A, two_of_two(1, 2), [sig(2), key(2)])),
    # The HTLC template.
    ("htlc_claim", seed(ALL, A, HTLC, HTLC_CLAIM)),
    ("htlc_claim_signature_refused", seed(ALL, R, HTLC, HTLC_CLAIM)),
    ("htlc_claim_other_preimage", seed(ALL, A, HTLC, [sig(1), key(1), bytes([0x08]) * 32, TRUE])),
    ("htlc_refund", seed(ALL, A, HTLC, HTLC_REFUND, locktime=500, sequence=SEQUENCE_FINAL - 1)),
    ("htlc_refund_one_block_early", seed(ALL, A, HTLC, HTLC_REFUND, locktime=499, sequence=SEQUENCE_FINAL - 1)),
    ("htlc_refund_final_sequence", seed(ALL, A, HTLC, HTLC_REFUND, locktime=500, sequence=SEQUENCE_FINAL)),
    ("htlc_b1_vector", seed(ALL, A, HTLC_B1, HTLC_CLAIM)),
    # The eLTOO template.
    ("eltoo_update", seed(ALL, A, ELTOO, ELTOO_UPDATE, locktime=600001, sequence=SEQUENCE_FINAL - 1)),
    ("eltoo_update_locktime_at_state", seed(ALL, A, ELTOO, ELTOO_UPDATE, locktime=600000, sequence=SEQUENCE_FINAL - 1)),
    ("eltoo_settlement", seed(ALL, A, ELTOO, ELTOO_SETTLE, version=2, sequence=288)),
    ("eltoo_settlement_version_1", seed(ALL, A, ELTOO, ELTOO_SETTLE, version=1, sequence=288)),
    ("eltoo_settlement_disable_flag", seed(ALL, A, ELTOO, ELTOO_SETTLE, version=2, sequence=SEQUENCE_DISABLE | 288)),
    ("eltoo_settlement_one_block_short", seed(ALL, A, ELTOO, ELTOO_SETTLE, version=2, sequence=287)),
    ("eltoo_b1_vector", seed(ALL, A, ELTOO_B1, ELTOO_SETTLE, version=2, sequence=288)),
    # Timelocks and the hashlock on their own.
    ("csv_delay", seed(ALL, R, ops(num(20), OP_CSV, OP_DROP, op(1)), version=2, sequence=20)),
    ("csv_operand_not_minimal", seed(ALL, R, ops(push(bytes([0x14, 0x00])), OP_CSV, OP_DROP, op(1)), version=2, sequence=20)),
    ("csv_operand_negative", seed(ALL, R, ops(num(-1), OP_CSV, OP_DROP, op(1)), version=2, sequence=20)),
    ("cltv_height", seed(ALL, R, ops(num(100), OP_CLTV, OP_DROP, op(1)), locktime=100, sequence=0)),
    ("hashlock", seed(ALL, R, ops(OP_SHA256, push(sha256(PREIMAGE)), OP_EQUAL), [PREIMAGE])),
    # The opcode set.
    ("opcode_bitcoin_htlc", seed(ALL, R, BITCOIN_HTLC)),
    ("opcode_in_branch_not_taken", seed(ALL, R, ops(OP_0, OP_IF, OP_CHECKSIG, OP_ENDIF, op(1)))),
    ("opcode_1negate", seed(ALL, R, ops(OP_1NEGATE))),
    ("opcode_size", seed(ALL, R, ops(op(1), OP_SIZE))),
    ("opcode_checkpatagg", seed(ALL, R, ops(op(1), OP_CHECKPATAGG))),
    ("opcode_bytes_inside_a_push", seed(ALL, R, ops(push(bytes([OP_CHECKSIG, OP_HASH160, OP_DUP, OP_SIZE])), OP_DROP, op(1)))),
    ("script_ends_inside_a_push", seed(ALL, R, bytes([OP_PUSHDATA2, 0xff]))),
    # Push encodings.
    ("push_pushdata1", seed(ALL, R, ops(push(bytes([0x01]) * 100), OP_DROP, op(1)))),
    ("push_pushdata2", seed(ALL, R, ops(push(bytes([0x01]) * 300), OP_DROP, op(1)))),
    ("push_pushdata4", seed(ALL, R, ops(bytes([OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, OP_CHECKSIG]), OP_DROP, op(1)))),
    ("push_521_bytes", seed(ALL, R, ops(push(bytes([0x01]) * 521), OP_DROP, op(1)))),
    # The restored byte and arithmetic opcodes.
    ("restore_mul", seed(ALL, R, ops(op(2), op(3), OP_MUL, op(6), OP_EQUAL))),
    ("restore_mul_wide", seed(ALL, R, ops(num(1 << 40), op(4), OP_MUL, num(1 << 42), OP_EQUAL))),
    ("restore_div_mod", seed(ALL, R, ops(op(7), op(2), OP_DIV, op(3), OP_EQUALVERIFY, op(7), op(2), OP_MOD, op(1), OP_EQUAL))),
    ("restore_div_by_zero", seed(ALL, R, ops(op(1), OP_0, OP_DIV))),
    ("restore_bitwise", seed(ALL, R, ops(push(b"\x0f"), push(b"\xf0"), OP_OR, push(b"\xff"), OP_EQUALVERIFY,
                                          push(b"\x0f"), push(b"\xf0"), OP_AND, push(b"\x00"), OP_EQUALVERIFY,
                                          push(b"\x0f"), push(b"\xff"), OP_XOR, push(b"\xf0"), OP_EQUAL))),
    ("restore_cat_substr", seed(ALL, R, ops(push(b"\xaa\xbb"), push(b"\xcc\xdd"), OP_CAT, push(b"\xaa\xbb\xcc\xdd"), OP_EQUALVERIFY,
                                             push(b"\x00\x11\x22\x33"), op(1), op(2), OP_SUBSTR, push(b"\x11\x22"), OP_EQUALVERIFY,
                                             push(b"\x00\x11\x22\x33"), op(1), OP_LEFT, push(b"\x00"), OP_EQUALVERIFY,
                                             push(b"\x00\x11\x22\x33"), op(1), OP_RIGHT, push(b"\x33"), OP_EQUAL))),
    # Control flow.
    ("control_nested", seed(ALL, R, ops(op(1), OP_IF, OP_0, OP_IF, OP_0, OP_ELSE, op(1), OP_ENDIF, OP_ELSE, OP_0, OP_ENDIF))),
    ("control_notif", seed(ALL, R, ops(OP_0, OP_NOTIF, op(1), OP_ENDIF))),
    ("control_if_not_closed", seed(ALL, R, ops(op(1), OP_IF, op(1)))),
    ("control_else_alone", seed(ALL, R, ops(OP_ELSE, op(1)))),
    ("control_if_argument_not_minimal", seed(ALL, R, ops(OP_IF, op(1), OP_ELSE, OP_0, OP_ENDIF), [bytes([0x02])])),
    ("control_opcodes_controlflow_clear", seed(P2WSH, R, ops(op(1), op(1), OP_DROP))),
    # The two later-layer opcodes of the set.
    ("ctv_other_template", seed(ALL, R, ops(push(bytes([0x77]) * 32), OP_CTV))),
    ("ctv_opcode_ctv_clear", seed(ALL & ~CTV, R, ops(push(bytes([0x77]) * 32), OP_CTV))),
    ("csfs_not_a_signature", seed(ALL, R, ops(OP_CSFS, op(1)), [sig(5)[:2420], b"message", key(5)])),
    ("csfs_opcode_csfs_clear", seed(ALL & ~CSFS, R, ops(OP_CSFS, op(1)), [sig(5)[:2420], b"message", key(5)])),
    # Sizes.
    ("script_10000_bytes", seed(ALL, R, ops(op(1), OP_DROP) * 4998 + ops(OP_0, OP_NOTIF, op(1), OP_ENDIF))),
    ("script_10001_bytes", seed(ALL, R, ops(op(1), OP_DROP) * 5000 + ops(op(1)))),
    ("witness_item_3000_bytes", seed(ALL, R, ops(OP_DROP, op(1)), [bytes([0x5a]) * 3000])),
    ("witness_64_items", seed(ALL, R, bytes([OP_DROP]) * 64 + ops(op(1)), [bytes([i]) for i in range(64)])),
]


def main():
    names = [name for name, _ in SEEDS]
    assert len(names) == len(set(names)), "seed names must be unique"
    os.makedirs(CORPUS, exist_ok=True)
    for stale in sorted(os.listdir(CORPUS)):
        if stale.startswith(PREFIX):
            os.remove(os.path.join(CORPUS, stale))
    total = 0
    for name, data in SEEDS:
        with open(os.path.join(CORPUS, PREFIX + name), "wb") as f:
            f.write(data)
        total += len(data)
    print("%d seeds, %d bytes, in %s" % (len(SEEDS), total, CORPUS))


if __name__ == "__main__":
    main()
