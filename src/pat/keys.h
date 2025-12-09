#pragma once

#include "types.h"
#include <string>

class CDilithiumKey
{
public:
    CDilithiumKey();
    ~CDilithiumKey();

    void MakeNewKey();
    bool SetPrivKey(const valtype& vchPrivKey);

    valtype GetPrivKey() const;
    valtype GetPubKey() const;

    std::vector<unsigned char> Sign(const std::string& message) const;
    bool Verify(const valtype& pubkey, const std::string& message, const valtype& sig) const;

private:
    CDilithiumPrivateKey privkey;
    CDilithiumPublicKey pubkey;
    bool fValid;
};
