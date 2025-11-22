// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2021-2022 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pubkey.h"
#include "crypto/dilithium/sign.h"

#include <string.h>

// Post-quantum: Dilithium verification replaces secp256k1 ECDSA

bool CPubKey::Verify(const uint256& hash, const std::vector<unsigned char>& vchSig) const
{
    if (!IsValid())
        return false;

    // Dilithium signature verification
    // Expected signature size for ML-DSA-44 is 2420 bytes
    if (vchSig.size() != 2420) {
        return false;
    }

    // Verify using Dilithium
    // crypto_sign_verify(sig, siglen, msg, msglen, pk)
    int result = pqcrystals_dilithium2_ref_verify(
        vchSig.data(),
        vchSig.size(),
        hash.begin(),
        hash.size(),
        nullptr, 0,
        vch);

    return result == 0;
}

bool CPubKey::RecoverCompact(const uint256& hash, const std::vector<unsigned char>& vchSig)
{
    // Post-quantum: Not supported for Dilithium (no signature recovery)
    return false;
}

bool CPubKey::IsFullyValid() const
{
    if (!IsValid())
        return false;

    // For Dilithium, a valid public key is one with the correct size (1312 bytes)
    // Additional validation could be added here if needed
    return size() == 1312;
}

bool CPubKey::Compress()
{
    // Post-quantum: Dilithium public keys are not compressible
    // They are already at their fixed size of 1312 bytes
    return IsValid();
}

bool CPubKey::Decompress()
{
    // Post-quantum: Dilithium public keys are not compressible
    // They are already at their fixed size of 1312 bytes
    return IsValid();
}

bool CPubKey::Derive(CPubKey& pubkeyChild, ChainCode& ccChild, unsigned int nChild, const ChainCode& cc) const
{
    // Post-quantum: BIP32 derivation not supported for Dilithium
    // Dilithium does not have additive properties like secp256k1
    return false;
}

void CExtPubKey::Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const
{
    code[0] = nDepth;
    memcpy(code + 1, vchFingerprint, 4);
    code[5] = (nChild >> 24) & 0xFF;
    code[6] = (nChild >> 16) & 0xFF;
    code[7] = (nChild >> 8) & 0xFF;
    code[8] = (nChild >> 0) & 0xFF;
    memcpy(code + 9, chaincode.begin(), 32);
    // Post-quantum: Note that pubkey size is now 1312, not 33
    // This encode function may need to be redesigned for Dilithium
    assert(pubkey.size() == CPubKey::COMPRESSED_SIZE);
    memcpy(code + 41, pubkey.begin(), 1312);
}

void CExtPubKey::Decode(const unsigned char code[BIP32_EXTKEY_SIZE])
{
    nDepth = code[0];
    memcpy(vchFingerprint, code + 1, 4);
    nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
    memcpy(chaincode.begin(), code + 9, 32);
    pubkey.Set(code + 41, code + BIP32_EXTKEY_SIZE);
}

bool CExtPubKey::Derive(CExtPubKey& out, unsigned int _nChild) const
{
    // Post-quantum: BIP32 derivation not supported for Dilithium
    return false;
}

/* static */ bool CPubKey::CheckLowS(const std::vector<unsigned char>& vchSig)
{
    // Post-quantum: Low-S check is ECDSA-specific, not applicable to Dilithium
    // For Dilithium, signatures are deterministic and have fixed properties
    // Return true to indicate signature is acceptable (no malleability in Dilithium)
    return true;
}

/* static */ int ECCVerifyHandle::refcount = 0;

ECCVerifyHandle::ECCVerifyHandle()
{
    // Post-quantum: No secp256k1 context needed for Dilithium
    refcount++;
}

ECCVerifyHandle::~ECCVerifyHandle()
{
    // Post-quantum: No secp256k1 context cleanup needed for Dilithium
    refcount--;
}
