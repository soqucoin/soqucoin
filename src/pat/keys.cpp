#include "keys.h"
#include "random.h"
#include "util.h"

extern "C" {
#include "dilithium-ref/api.h"
}

// ⛔ Bind pat/types.h's aliases to the vendored implementation's own constants.
// A parameter-set change — ML-DSA-44 to -65, or a regression to round-3
// Dilithium2 — must BREAK THE BUILD here rather than silently mis-size a buffer.
// PATBasePrivateKey was 2528 (round-3 Dilithium2) while the implementation is
// FIPS-204 ML-DSA-44 at 2560; it went unnoticed because the alias is unused.
// These assertions are the reason it cannot drift again.
static_assert(std::tuple_size<PATBasePublicKey>::value ==
                  pqcrystals_dilithium2_ref_PUBLICKEYBYTES,
    "PATBasePublicKey does not match the vendored ML-DSA public key size");
static_assert(std::tuple_size<PATBasePrivateKey>::value ==
                  pqcrystals_dilithium2_ref_SECRETKEYBYTES,
    "PATBasePrivateKey does not match the vendored ML-DSA secret key size "
    "(2560 for FIPS-204 ML-DSA-44; 2528 is the superseded round-3 Dilithium2)");
static_assert(std::tuple_size<PATBaseSignature>::value ==
                  pqcrystals_dilithium2_ref_BYTES,
    "PATBaseSignature does not match the vendored ML-DSA signature size");

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

