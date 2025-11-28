#include "script/script.h"
#include "uint256.h"
#include <vector>

namespace pat
{

typedef std::vector<unsigned char> CValType;

struct LogarithmicProof {
    uint256 merkle_root;
    uint256 pk_xor;   // XOR of all 32-byte ρ prefixes
    uint256 msg_root; // Root of the message tree (or commitment)
    uint32_t count;   // number of signatures
    // 104 bytes total (32+32+32+4)
};

bool ParseLogarithmicProof(const CValType& vchProof, LogarithmicProof& proofOut);

bool CreateLogarithmicProof(
    const std::vector<CValType>& vSignatures,
    const std::vector<CValType>& vPublicKeys,
    const std::vector<CValType>& vMessages,
    CValType& vchProofOut,
    std::vector<CValType>& vSiblingPathOut); // for witness

bool VerifyLogarithmicProof(
    const CValType& vchProof,
    const std::vector<CValType>& vSiblingPath,
    const std::vector<CValType>& vClaimedSigs,
    const std::vector<CValType>& vClaimedPks,
    const std::vector<CValType>& vClaimedMsgs);

bool VerifyLogarithmicProof(
    const LogarithmicProof& proof,
    const CValType& agg_pk,
    const CValType& msg_root);

} // namespace pat
