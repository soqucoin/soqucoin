#include "rpc/server.h"
#include "pat/keys.h"
#include "utilstrencodings.h"

using namespace std;

static UniValue Pair(const std::string& name, const std::string& value)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV(name, value);
    return obj;
}

UniValue generatedilithiumkey(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "generatedilithiumkey\n"
            "Generate a new Dilithium keypair.\n"
            "Returns object with publickey and privatekey in hex.\n"
        );

    CDilithiumKey key;
    key.MakeNewKey();

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("publickey", HexStr(key.GetPubKey())));
    result.push_back(Pair("privatekey", HexStr(key.GetPrivKey())));
    return result;
}

UniValue signdilithiummessage(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "signdilithiummessage \"privatekey\" \"message\"\n"
            "Sign a message with a Dilithium private key.\n"
        );

    vector<unsigned char> privkey = ParseHex(params[0].get_str());
    string message = params[1].get_str();

    CDilithiumKey key;
    key.SetPrivKey(privkey);

    vector<unsigned char> sig = key.Sign(message);
    return HexStr(sig);
}

static UniValue generatedilithiumkey_rpc(const JSONRPCRequest& request)
{
    return generatedilithiumkey(request.params, request.fHelp);
}

static UniValue signdilithiummessage_rpc(const JSONRPCRequest& request)
{
    return signdilithiummessage(request.params, request.fHelp);
}

static const CRPCCommand commands[] =
{
    { "pat", "generatedilithiumkey", &generatedilithiumkey_rpc, true, {} },
    { "pat", "signdilithiummessage", &signdilithiummessage_rpc, true, {"privatekey","message"} },
};

void RegisterPATRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int i = 0; i < ARRAYLEN(commands); i++)
        tableRPC.appendCommand(commands[i].name, &commands[i]);
}
