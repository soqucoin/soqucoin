#include "keys.h"
#include "random.h"
#include "util.h"

extern "C" {
#include "dilithium-ref/api.h"
}

CDilithiumKey::CDilithiumKey() : fValid(false) {}

CDilithiumKey::~CDilithiumKey() {}

void CDilithiumKey::MakeNewKey()
{
    valtype priv(pqcrystals_dilithium2_ref_SECRETKEYBYTES);
    valtype pub(pqcrystals_dilithium2_ref_PUBLICKEYBYTES);
    if (pqcrystals_dilithium2_ref_keypair(pub.data(), priv.data()) != 0) {
        throw std::runtime_error("Dilithium keygen failed");
    }
    privkey = CDilithiumPrivateKey(priv);
    pubkey = CDilithiumPublicKey(pub);
    fValid = true;
}

bool CDilithiumKey::SetPrivKey(const valtype& vchPrivKey)
{
    if (vchPrivKey.size() != pqcrystals_dilithium2_ref_SECRETKEYBYTES) return false;
    privkey.v = vchPrivKey;
    fValid = true;
    return true;
}

valtype CDilithiumKey::GetPrivKey() const { return privkey.v; }
valtype CDilithiumKey::GetPubKey() const { return pubkey.v; }

std::vector<unsigned char> CDilithiumKey::Sign(const std::string& message) const
{
    if (!fValid) throw std::runtime_error("Invalid Dilithium key");
    std::vector<unsigned char> sig(pqcrystals_dilithium2_ref_BYTES);
    size_t siglen = 0;
    if (pqcrystals_dilithium2_ref_signature(sig.data(), &siglen,
                                            (const unsigned char*)message.data(), message.size(),
                                            NULL, 0, privkey.v.data()) != 0) {
        throw std::runtime_error("Dilithium signing failed");
    }
    sig.resize(siglen);
    return sig;
}

bool CDilithiumKey::Verify(const valtype& pubkey_bytes, const std::string& message, const valtype& sig) const
{
    return pqcrystals_dilithium2_ref_verify(sig.data(), sig.size(),
                                            (const unsigned char*)message.data(), message.size(),
                                            NULL, 0, pubkey_bytes.data()) == 0;
}

