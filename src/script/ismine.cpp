// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ismine.h"

#include "key.h"
#include "keystore.h"
#include "script/script.h"
#include "script/sign.h"
#include "script/standard.h"

#include <boost/foreach.hpp>

using namespace std;

typedef vector<unsigned char> valtype;

unsigned int HaveKeys(const vector<valtype>& pubkeys, const CKeyStore& keystore)
{
    unsigned int nResult = 0;
    BOOST_FOREACH (const valtype& pubkey, pubkeys) {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (keystore.HaveKey(keyID))
            ++nResult;
    }
    return nResult;
}

isminetype IsMine(const CKeyStore& keystore, const CScript& scriptPubKey, SigVersion sigversion)
{
    bool isInvalid = false;
    return IsMine(keystore, scriptPubKey, isInvalid, sigversion);
}

isminetype IsMine(const CKeyStore& keystore, const CTxDestination& dest, SigVersion sigversion)
{
    bool isInvalid = false;
    return IsMine(keystore, dest, isInvalid, sigversion);
}

isminetype IsMine(const CKeyStore& keystore, const CTxDestination& dest, bool& isInvalid, SigVersion sigversion)
{
    CScript script = GetScriptForDestination(dest);
    return IsMine(keystore, script, isInvalid, sigversion);
}

isminetype IsMine(const CKeyStore& keystore, const CScript& scriptPubKey, bool& isInvalid, SigVersion sigversion)
{
    vector<valtype> vSolutions;
    txnouttype whichType;
    if (!Solver(scriptPubKey, whichType, vSolutions)) {
        if (keystore.HaveWatchOnly(scriptPubKey))
            return ISMINE_WATCH_UNSOLVABLE;
        return ISMINE_NO;
    }

    CKeyID keyID;
    switch (whichType) {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        break;
    case TX_PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        if (sigversion != SIGVERSION_BASE && vSolutions[0].size() != 33) {
            isInvalid = true;
            return ISMINE_NO;
        }
        if (keystore.HaveKey(keyID))
            return ISMINE_SPENDABLE;
        break;
    case TX_WITNESS_V0_KEYHASH: {
        if (!keystore.HaveCScript(CScriptID(CScript() << OP_0 << vSolutions[0]))) {
            // We do not support bare witness outputs unless the P2SH version of it would be
            // acceptable as well. This protects against matching before segwit activates.
            // This also applies to the P2WSH case.
            break;
        }
        isminetype ret = ::IsMine(keystore, GetScriptForDestination(CKeyID(uint160(vSolutions[0]))), isInvalid, SIGVERSION_WITNESS_V0);
        if (ret == ISMINE_SPENDABLE || ret == ISMINE_WATCH_SOLVABLE || (ret == ISMINE_NO && isInvalid))
            return ret;
        break;
    }
    case TX_PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (sigversion != SIGVERSION_BASE) {
            CPubKey pubkey;
            if (keystore.GetPubKey(keyID, pubkey) && !pubkey.IsCompressed()) {
                isInvalid = true;
                return ISMINE_NO;
            }
        }
        if (keystore.HaveKey(keyID))
            return ISMINE_SPENDABLE;
        break;
    case TX_SCRIPTHASH: {
        CScriptID scriptID = CScriptID(uint160(vSolutions[0]));
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript)) {
            isminetype ret = IsMine(keystore, subscript, isInvalid);
            if (ret == ISMINE_SPENDABLE || ret == ISMINE_WATCH_SOLVABLE || (ret == ISMINE_NO && isInvalid))
                return ret;
        }
        break;
    }
    case TX_WITNESS_V0_SCRIPTHASH: {
        if (!keystore.HaveCScript(CScriptID(CScript() << OP_0 << vSolutions[0]))) {
            break;
        }
        uint160 hash;
        CRIPEMD160().Write(&vSolutions[0][0], vSolutions[0].size()).Finalize(hash.begin());
        CScriptID scriptID = CScriptID(hash);
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript)) {
            isminetype ret = IsMine(keystore, subscript, isInvalid, SIGVERSION_WITNESS_V0);
            if (ret == ISMINE_SPENDABLE || ret == ISMINE_WATCH_SOLVABLE || (ret == ISMINE_NO && isInvalid))
                return ret;
        }
        break;
    }

    case TX_WITNESS_V1_SCRIPTHASH: {
        // Dilithium witness v1 address - check if we have the key
        // The vSolutions[0] contains the 32-byte SHA256 hash of the Dilithium public key
        // We need to check if our keystore has any Dilithium key whose pubkey hashes to this value

        // For now, we iterate through all keys in the wallet to find a match
        // TODO: optimize this with a reverse lookup map
        std::set<CKeyID> setKeyIDs;
        keystore.GetKeys(setKeyIDs);

        for (const CKeyID& keyID : setKeyIDs) {
            CPubKey pubkey;
            if (keystore.GetPubKey(keyID, pubkey)) {
                // Hash the Dilithium public key with single SHA256 (same as getnewaddress)
                uint256 hash;
                CSHA256().Write(pubkey.begin(), pubkey.size()).Finalize(hash.begin());

                // Check if this matches the witness program
                if (vSolutions[0].size() == 32 &&
                    memcmp(hash.begin(), vSolutions[0].data(), 32) == 0) {
                    return ISMINE_SPENDABLE;
                }
            }
        }

        // If we don't have the key, check for watch-only
        if (keystore.HaveWatchOnly(scriptPubKey))
            return ISMINE_WATCH_SOLVABLE;
        break;
    }

    case TX_MULTISIG: {
        // Only consider transactions "mine" if we own ALL the
        // keys involved. Multi-signature transactions that are
        // partially owned (somebody else has a key that can spend
        // them) enable spend-out-from-under-you attacks, especially
        // in shared-wallet situations.
        vector<valtype> keys(vSolutions.begin() + 1, vSolutions.begin() + vSolutions.size() - 1);
        if (sigversion != SIGVERSION_BASE) {
            for (size_t i = 0; i < keys.size(); i++) {
                if (keys[i].size() != 33) {
                    isInvalid = true;
                    return ISMINE_NO;
                }
            }
        }
        if (HaveKeys(keys, keystore) == keys.size())
            return ISMINE_SPENDABLE;
        break;
    }
    }

    if (keystore.HaveWatchOnly(scriptPubKey)) {
        // TODO: This could be optimized some by doing some work after the above solver
        SignatureData sigs;
        return ProduceSignature(DummySignatureCreator(&keystore), scriptPubKey, sigs) ? ISMINE_WATCH_SOLVABLE : ISMINE_WATCH_UNSOLVABLE;
    }
    return ISMINE_NO;
}
