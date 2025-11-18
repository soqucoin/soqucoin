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

static UniValue generatedilithiumkey_legacy(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "generatedilithiumkey\n"
            "\nGenerate a new Dilithium keypair.\n"
            "\nResult:\n"
            "{\n"
            "  \"publickey\": \"xxxx\", (hex)\n"
            "  \"privatekey\": \"xxxx\" (hex — keep secret!)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("generatedilithiumkey", "")
        );

    CDilithiumKey key;
    key.MakeNewKey();

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("publickey", HexStr(key.GetPubKey())));
    obj.push_back(Pair("privatekey", HexStr(key.GetPrivKey())));
    return obj;
}

static UniValue signdilithiummessage_legacy(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "signdilithiummessage \"privatekey\" \"message\"\n"
            "\nSign a message with a Dilithium private key.\n"
            "\nArguments:\n"
            "1. \"privatekey\" (string, required) The private key (hex)\n"
            "2. \"message\"     (string, required) The message to sign\n"
            "\nResult:\n"
            "\"signature\" (string) The signature (hex)\n"
            "\nExamples:\n"
            + HelpExampleCli("signdilithiummessage", "\"privkey\" \"hello world\"")
        );

    vector<unsigned char> privkey = ParseHex(params[0].get_str());
    string message = params[1].get_str();

    CDilithiumKey key;
    key.SetPrivKey(privkey);

    vector<unsigned char> sig = key.Sign(message);

    return HexStr(sig);
}

UniValue generatedilithiumkey(const JSONRPCRequest& request)
{
    return generatedilithiumkey_legacy(request.params, request.fHelp);
}

UniValue signdilithiummessage(const JSONRPCRequest& request)
{
    return signdilithiummessage_legacy(request.params, request.fHelp);
}

static const CRPCCommand commands[] =
{
    { "pat", "generatedilithiumkey",   &generatedilithiumkey,   true,  {} },
    { "pat", "signdilithiummessage",  &signdilithiummessage,  true,  {"privatekey", "message"} },
};

void RegisterPATRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
