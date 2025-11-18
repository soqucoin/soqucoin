#include "rpc/server.h"
#include "pat/keys.h"
#include "pat/sign.h"
#include "utilstrencodings.h"

using namespace std;

UniValue generatedilithiumkey(const JSONRPCRequest& request)
{
    RPCHelpMan{"generatedilithiumkey",
        "Generate a new Dilithium keypair",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "publickey", "The public key"},
            {RPCResult::Type::STR_HEX, "privatekey", "The private key (keep secret!)"}
        }},
        RPCExamples{HelpExampleCli("generatedilithiumkey", "")}
    }.Check(request);

    CDilithiumKey key;
    key.MakeNewKey();
    
    return UniValue(UniValue::VType::VOBJ)
        .pushKV("publickey", HexStr(key.GetPubKey()))
        .pushKV("privatekey", HexStr(key.GetPrivKey()));
}

UniValue signdilithiummessage(const JSONRPCRequest& request)
{
    RPCHelpMan{"signdilithiummessage",
        "Sign a message with a Dilithium private key",
        {
            {"privatekey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The private key"},
            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message to sign"}
        },
        RPCResult{RPCResult::Type::STR_HEX, "signature", "The signature"},
        RPCExamples{HelpExampleCli("signdilithiummessage", "\"privkey\" \"hello world\"")}
    }.Check(request);

    std::vector<unsigned char> privkey = ParseHex(request.params[0].get_str());
    std::string message = request.params[1].get_str();

    CDilithiumKey key;
    key.SetPrivKey(privkey);
    
    std::vector<unsigned char> sig = key.Sign(message);
    
    return HexStr(sig);
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "pat",                "generatedilithiumkey",   &generatedilithiumkey,   {} },
    { "pat",                "signdilithiummessage",   &signdilithiummessage,   {"privatekey","message"} },
};

void RegisterPATRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
#include "rpc/server.h"
#include "pat/keys.h"
#include "pat/sign.h"
#include "utilstrencodings.h"

using namespace std;

UniValue generatedilithiumkey(const JSONRPCRequest& request)
{
    RPCHelpMan{"generatedilithiumkey",
        "Generate a new Dilithium keypair",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "publickey", "The public key"},
            {RPCResult::Type::STR_HEX, "privatekey", "The private key (keep secret!)"}
        }},
        RPCExamples{HelpExampleCli("generatedilithiumkey", "")}
    }.Check(request);

    CDilithiumKey key;
    key.MakeNewKey();
    
    return UniValue(UniValue::VType::VOBJ)
        .pushKV("publickey", HexStr(key.GetPubKey()))
        .pushKV("privatekey", HexStr(key.GetPrivKey()));
}

UniValue signdilithiummessage(const JSONRPCRequest& request)
{
    RPCHelpMan{"signdilithiummessage",
        "Sign a message with a Dilithium private key",
        {
            {"privatekey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The private key"},
            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message to sign"}
        },
        RPCResult{RPCResult::Type::STR_HEX, "signature", "The signature"},
        RPCExamples{HelpExampleCli("signdilithiummessage", "\"privkey\" \"hello world\"")}
    }.Check(request);

    std::vector<unsigned char> privkey = ParseHex(request.params[0].get_str());
    std::string message = request.params[1].get_str();

    CDilithiumKey key;
    key.SetPrivKey(privkey);
    
    std::vector<unsigned char> sig = key.Sign(message);
    
    return HexStr(sig);
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "pat",                "generatedilithiumkey",   &generatedilithiumkey,   {} },
    { "pat",                "signdilithiummessage",   &signdilithiummessage,   {"privatekey","message"} },
};

void RegisterPATRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}

