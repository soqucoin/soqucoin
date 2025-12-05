// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2021-2022 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key.h"

#include "arith_uint256.h"
#include "crypto/common.h"
#include "crypto/hmac_sha512.h"
#include "pubkey.h"
#include "random.h"
#include "util.h"

#include "crypto/dilithium/params.h"
#include "crypto/dilithium/sign.h"

// Dilithium2 (ML-DSA-44) constants
// CRYPTO_SECRETKEYBYTES = 2560
// CRYPTO_PUBLICKEYBYTES = 1312
// CRYPTO_BYTES (Signature) = 2420

bool CKey::Check(const unsigned char* vch)
{
    // Minimal check for validity.
    // Dilithium keys are effectively random bytes.
    return true;
}

void CKey::MakeNewKey(bool fCompressedIn)
{
    // fCompressedIn is ignored for Dilithium
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];

    do {
        if (crypto_sign_keypair(pk, sk) != 0) {
            // This should never happen with a good PRNG
            throw std::runtime_error("Dilithium key generation failed");
        }
    } while (pk[0] == 0xFF); // Ensure public key doesn't start with invalid marker

    // Store SK + PK in keydata
    // keydata is resized to 3872 in constructor
    memcpy(keydata.data(), sk, CRYPTO_SECRETKEYBYTES);
    memcpy(keydata.data() + CRYPTO_SECRETKEYBYTES, pk, CRYPTO_PUBLICKEYBYTES);

    fValid = true;
    fCompressed = false; // Dilithium keys are not "compressed" in the ECDSA sense
}

bool CKey::SetPrivKey(const CPrivKey& privkey, bool fCompressedIn)
{
    // We expect the privkey blob to contain both Secret Key and Public Key
    // to fully populate keydata (3872 bytes).

    if (privkey.size() == CRYPTO_SECRETKEYBYTES + CRYPTO_PUBLICKEYBYTES) {
        memcpy(keydata.data(), privkey.data(), privkey.size());
        fValid = true;
        return true;
    }

    // If we only get SK, we can't fully reconstruct without deriving PK.
    // Fail if not full size.
    return false;
}

CPrivKey CKey::GetPrivKey() const
{
    assert(fValid);
    // Return both SK and PK to ensure we can reload it easily
    CPrivKey privkey;
    privkey.resize(CRYPTO_SECRETKEYBYTES + CRYPTO_PUBLICKEYBYTES);
    memcpy(privkey.data(), keydata.data(), privkey.size());
    return privkey;
}

CPubKey CKey::GetPubKey() const
{
    assert(fValid);
    CPubKey result;
    // Extract PK from keydata (offset 2560)
    // CPubKey::SIZE is 1312
    // result.begin() points to a 1312-byte buffer
    memcpy((unsigned char*)result.begin(), keydata.data() + CRYPTO_SECRETKEYBYTES, CRYPTO_PUBLICKEYBYTES);
    assert(result.IsValid());
    return result;
}

bool CKey::Sign(const uint256& hash, std::vector<unsigned char>& vchSig, uint32_t test_case) const
{
    if (!fValid)
        return false;

    vchSig.resize(CRYPTO_BYTES);
    size_t nSigLen = CRYPTO_BYTES;

    // Dilithium signs the message (hash)
    // crypto_sign_signature(sig, siglen, m, mlen, ctx, ctxlen, sk)
    if (crypto_sign_signature(vchSig.data(), &nSigLen, hash.begin(), 32, nullptr, 0, keydata.data()) != 0) {
        return false;
    }

    vchSig.resize(nSigLen);
    return true;
}

bool CKey::VerifyPubKey(const CPubKey& pubkey) const
{
    // Verify that the public key in keydata matches the provided pubkey
    if (memcmp(keydata.data() + CRYPTO_SECRETKEYBYTES, pubkey.begin(), CRYPTO_PUBLICKEYBYTES) != 0) {
        LogPrintf("VerifyPubKey: Public key mismatch\n");
        return false;
    }

    // Also perform a signature verification test
    unsigned char rnd[8];
    std::string str = "Soqucoin key verification\n";
    GetRandBytes(rnd, sizeof(rnd));
    uint256 hash;
    CHash256().Write((unsigned char*)str.data(), str.size()).Write(rnd, sizeof(rnd)).Finalize(hash.begin());
    std::vector<unsigned char> vchSig;
    if (!Sign(hash, vchSig)) {
        LogPrintf("VerifyPubKey: Sign failed\n");
        return false;
    }
    if (!pubkey.Verify(hash, vchSig)) {
        LogPrintf("VerifyPubKey: Verify failed. Sig size: %d\n", vchSig.size());
        return false;
    }
    return true;
}

bool CKey::SignCompact(const uint256& hash, std::vector<unsigned char>& vchSig) const
{
    // Not supported in Dilithium
    return false;
}

bool CKey::Load(CPrivKey& privkey, CPubKey& vchPubKey, bool fSkipCheck = false)
{
    // If privkey contains both SK and PK (3872 bytes)
    if (privkey.size() == CRYPTO_SECRETKEYBYTES + CRYPTO_PUBLICKEYBYTES) {
        memcpy(keydata.data(), privkey.data(), privkey.size());
        fValid = true;
        return true;
    }

    // If privkey is just SK (2560 bytes) and we have vchPubKey (1312 bytes)
    if (privkey.size() == CRYPTO_SECRETKEYBYTES && vchPubKey.size() == CRYPTO_PUBLICKEYBYTES) {
        memcpy(keydata.data(), privkey.data(), CRYPTO_SECRETKEYBYTES);
        memcpy(keydata.data() + CRYPTO_SECRETKEYBYTES, vchPubKey.begin(), CRYPTO_PUBLICKEYBYTES);
        fValid = true;
        return true;
    }

    return false;
}

bool CKey::Derive(CKey& keyChild, ChainCode& ccChild, unsigned int nChild, const ChainCode& cc) const
{
    // BIP32 not supported for Dilithium yet (requires different derivation)
    return false;
}

bool CExtKey::Derive(CExtKey& out, unsigned int _nChild) const
{
    // BIP32 not supported
    return false;
}

void CExtKey::SetMaster(const unsigned char* seed, unsigned int nSeedLen)
{
    // BIP32 not supported
}

CExtPubKey CExtKey::Neuter() const
{
    CExtPubKey ret;
    ret.nDepth = nDepth;
    memcpy(ret.vchFingerprint, vchFingerprint, 4);
    ret.nChild = nChild;
    ret.pubkey = key.GetPubKey();
    ret.chaincode = chaincode;
    return ret;
}

void CExtKey::Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const
{
    // BIP32 not supported
}

void CExtKey::Decode(const unsigned char code[BIP32_EXTKEY_SIZE])
{
    // BIP32 not supported
}
