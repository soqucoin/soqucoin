#!/usr/bin/env python3
# Copyright (c) 2026 Soqucoin Labs Inc.
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generator of witness_address_vectors.json in this directory: the witness
address vectors (versions 1 and 6, 32-byte program, bech32m).

Run it from the repository root with Python 3.7 or later. It uses the
standard library only and writes the file named by its one argument:

    python3 src/test/data/gen_witness_address_vectors.py <output.json>
    cmp <output.json> src/test/data/witness_address_vectors.json

Every run writes the same bytes, and cmp prints nothing when the tracked file
is this script's output. To change the vectors, change this script and write
its output over the tracked file; the unit tests embed the file when they are
built (JSON_TEST_FILES in src/Makefile.test.include).

The checksum code is the BIP-350 reference algorithm. Every vector is
classified again by classify() below before it is written, so a vector's
"reason" is the first check the string fails, in the order classify() applies
the checks and the file's description lists them.
"""
import hashlib
import json
import sys

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3

NETWORKS = [("main", "sq"), ("test", "sq"), ("regtest", "sq"), ("stagenet", "ssq")]
PREFIXES = ["sq", "ssq"]
VERSIONS = [1, 6]
PROGRAM_SIZE = 32


def polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32_encode(hrp, data, const):
    values = hrp_expand(hrp) + data
    mod = polymod(values + [0] * 6) ^ const
    checksum = [(mod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data + checksum)


def to_groups(data):
    """8-bit bytes to 5-bit groups, zero padded."""
    acc = 0
    bits = 0
    ret = []
    for value in data:
        acc = ((acc << 8) | value) & 0xFFF
        bits += 8
        while bits >= 5:
            bits -= 5
            ret.append((acc >> bits) & 31)
    if bits:
        ret.append((acc << (5 - bits)) & 31)
    return ret


def from_groups(groups):
    """5-bit groups to bytes; None when a spare group or non-zero padding is left."""
    acc = 0
    bits = 0
    ret = []
    for value in groups:
        acc = ((acc << 5) | value) & 0xFFF
        bits += 5
        while bits >= 8:
            bits -= 8
            ret.append((acc >> bits) & 255)
    if bits >= 5 or ((acc << (8 - bits)) & 255):
        return None
    return bytes(ret)


def encode(hrp, version, program, const=BECH32M_CONST):
    return bech32_encode(hrp, [version] + to_groups(program), const)


def classify(s, prefix, version):
    """The first check the string fails, or "" when it is a valid address."""
    if s == "":
        return "empty"
    if any(ord(c) < 33 or ord(c) > 126 for c in s):
        return "whitespace"
    if any(c.islower() for c in s) and any(c.isupper() for c in s):
        return "mixed_case"
    if len(s) > 90:
        return "length_over_90"
    pos = s.rfind("1")
    if pos == -1:
        return "separator_missing"
    if pos == 0:
        return "prefix_empty"
    if pos + 7 > len(s):
        return "checksum_short"
    low = s.lower()
    if any(c not in CHARSET for c in low[pos + 1:]):
        return "character"
    hrp = low[:pos]
    values = [CHARSET.find(c) for c in low[pos + 1:]]
    check = polymod(hrp_expand(hrp) + values)
    if check == BECH32_CONST:
        return "checksum_bech32"
    if check != BECH32M_CONST:
        return "checksum"
    if hrp != prefix:
        return "prefix"
    data = values[:-6]
    if not data or data[0] != version:
        return "version"
    program = from_groups(data[1:])
    if program is None:
        return "padding"
    if len(program) != PROGRAM_SIZE:
        return "program_length"
    return ""


def programs():
    out = [
        bytes(32),
        bytes([0xFF] * 32),
        bytes(range(32)),
        hashlib.sha256(b"").digest(),
        hashlib.sha256(bytes([0x51])).digest(),
        bytes.fromhex("ec671f444afa19d8ee919c21c76fd2fbda2d17dc173fe75e94c2fdbea5ef366b"),
    ]
    for i in (1, 2):
        out.append(hashlib.sha256(b"soqucoin witness address vector %d" % i).digest())
    return out


def filler(n):
    """n deterministic bytes."""
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(b"soqucoin witness address filler %d" % i).digest()
        i += 1
    return out[:n]


def swap_adjacent(s, start):
    """Transpose the first two adjacent, different characters at or after start."""
    for i in range(start, len(s) - 1):
        if s[i] != s[i + 1]:
            return s[:i] + s[i + 1] + s[i] + s[i + 2:]
    raise AssertionError("no adjacent pair differs")


def invalid_for(prefix, version):
    base = hashlib.sha256(bytes([0x51])).digest()
    s = encode(prefix, version, base)
    sep = len(prefix)            # index of the separator
    first = sep + 2              # first program character
    out = []

    def add(reason, address):
        out.append((reason, address))

    add("empty", "")
    add("whitespace", " " + s)
    add("whitespace", s + " ")
    add("whitespace", s + "\n")
    add("whitespace", s + "\t")
    add("whitespace", s[:first + 8] + " " + s[first + 8:])

    add("mixed_case", prefix.upper() + s[sep:])
    letter = next(i for i in range(first, len(s)) if s[i].isalpha())
    add("mixed_case", s[:letter] + s[letter].upper() + s[letter + 1:])

    n = PROGRAM_SIZE + 1
    while len(encode(prefix, version, filler(n))) <= 90:
        n += 1
    add("length_over_90", encode(prefix, version, filler(n)))
    longest = n - 1              # the longest program whose string still fits in 90 characters

    add("separator_missing", s[:sep] + s[sep + 1:])
    add("prefix_empty", bech32_encode("", [version] + to_groups(base), BECH32M_CONST))
    add("checksum_short", s[:sep + 1] + s[-5:])

    for c in "bio":
        add("character", s[:first + 5] + c + s[first + 6:])

    i = first + 11
    add("checksum", s[:i] + CHARSET[(CHARSET.index(s[i]) + 1) % 32] + s[i + 1:])
    add("checksum", swap_adjacent(s, first + 20))
    other_version = 6 if version == 1 else 1
    add("checksum", s[:sep + 1] + CHARSET[other_version] + s[sep + 2:])
    add("checksum", s[:-1])
    add("checksum", s[:first + 30] + "q" + s[first + 30:])
    other_prefix = "ssq" if prefix == "sq" else "sq"
    add("checksum", other_prefix + s[sep:])

    add("checksum_bech32", encode(prefix, version, base, BECH32_CONST))
    add("checksum_bech32", encode(prefix, 0, base, BECH32_CONST))

    for hrp in (other_prefix, "bc", "tb", "s", "sqq", "qs", "soq"):
        add("prefix", encode(hrp, version, base))

    for w in list(range(0, 17)) + [17, 31]:
        if w != version:
            add("version", encode(prefix, w, base))
    add("version", bech32_encode(prefix, [], BECH32M_CONST))

    groups = to_groups(base)
    add("padding", bech32_encode(prefix, [version] + groups[:-1] + [groups[-1] | 1], BECH32M_CONST))
    add("padding", bech32_encode(prefix, [version] + groups + [0, 0], BECH32M_CONST))
    add("padding", bech32_encode(prefix, [version] + groups[:-1], BECH32M_CONST))

    for size in range(0, longest + 1):
        if size != PROGRAM_SIZE:
            add("program_length", encode(prefix, version, filler(size)))

    return out


def main():
    valid = []
    for prefix in PREFIXES:
        for version in VERSIONS:
            for program in programs():
                address = encode(prefix, version, program)
                assert classify(address, prefix, version) == ""
                assert classify(address.upper(), prefix, version) == ""
                valid.append({"prefix": prefix, "version": version,
                              "program": program.hex(), "address": address})

    invalid = []
    for prefix in PREFIXES:
        for version in VERSIONS:
            seen = set()
            for reason, address in invalid_for(prefix, version):
                got = classify(address, prefix, version)
                assert got == reason, (prefix, version, reason, got, address)
                assert address not in seen, address
                seen.add(address)
                invalid.append({"prefix": prefix, "version": version,
                                "address": address, "reason": reason})

    description = [
        "Witness address vectors: bech32m (BIP-350), one witness version character, a 32-byte program.",
        "networks maps each network name to its address prefix.",
        ("valid: on a network with this prefix, the program at this witness version encodes to this address, " +
         "and the address decodes to the program. program is hex in the order the bytes sit in the output " +
         "script; the script is the version opcode (OP_1 = 0x51, OP_6 = 0x56), the push 0x20, the program."),
        "The encoder writes lower case. A decoder also accepts a valid address written entirely in upper case.",
        ("invalid: a decoder for this witness version on a network with this prefix refuses the address. " +
         "reason names the first check the string fails, in this order: empty, whitespace, mixed_case, " +
         "length_over_90, separator_missing, prefix_empty, checksum_short, character, checksum_bech32, " +
         "checksum, prefix, version, padding, program_length."),
    ]

    lines = ["{"]
    lines.append('  "description": [')
    lines.append(",\n".join("    " + json.dumps(d) for d in description))
    lines.append("  ],")
    lines.append('  "networks": {' + ", ".join("%s: %s" % (json.dumps(n), json.dumps(p)) for n, p in NETWORKS) + "},")
    lines.append('  "valid": [')
    lines.append(",\n".join("    " + json.dumps(v) for v in valid))
    lines.append("  ],")
    lines.append('  "invalid": [')
    lines.append(",\n".join("    " + json.dumps(v) for v in invalid))
    lines.append("  ]")
    lines.append("}")
    text = "\n".join(lines) + "\n"
    json.loads(text)
    with open(sys.argv[1], "w") as f:
        f.write(text)

    # BIP-350 test vectors: the checksum code above is the reference one.
    assert classify("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "bc", 1) == ""
    assert polymod(hrp_expand("a") + [CHARSET.find(c) for c in "lqfn3a"]) == BECH32M_CONST
    assert polymod(hrp_expand("a") + [CHARSET.find(c) for c in "2uel5l"]) == BECH32_CONST

    counts = {}
    for v in invalid:
        key = (v["prefix"], v["version"], v["reason"])
        counts[key] = counts.get(key, 0) + 1
    print("valid", len(valid), "invalid", len(invalid))
    for prefix in PREFIXES:
        for version in VERSIONS:
            nv = sum(1 for v in valid if v["prefix"] == prefix and v["version"] == version)
            ni = sum(1 for v in invalid if v["prefix"] == prefix and v["version"] == version)
            reasons = sorted((r, c) for (p, w, r), c in counts.items() if p == prefix and w == version)
            print(prefix, version, "valid", nv, "invalid", ni, reasons)


if __name__ == "__main__":
    main()
