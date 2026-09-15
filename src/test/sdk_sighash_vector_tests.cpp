// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// The single-key Dilithium witness v1 spend as this node signs it, on a fixed
// transaction with a fixed key. An external signer can pin its BIP 143 sighash
// digests, witness layout and txid to this node's own signing path without a
// running node: soqucoin-sdk carries the transaction, the digests and one
// node-produced witness as a checked-in fixture (tx/testdata/sighash_node_vector.json,
// tx/sighash_node_test.go). If the two disagree, the node is right.
//
// The key is the FIPS 204 ML-DSA-44 key expanded from the seed
// SHA-256("soqucoin"), packed as secret key || public key (2560 + 1312 bytes),
// the layout CKey::Set expects. Its witness program is already a node vector
// in the SDK (keys/node_vectors_test.go). Signing is randomised
// (DILITHIUM_RANDOMIZED_SIGNING in crypto/dilithium/config.h), so the witness
// differs on every run and is verified rather than compared; the digests and
// the txid are deterministic and are compared to the recorded values.
//
// Print the signed transaction for a new fixture with
//   test_soqucoin --run_test=sdk_sighash_vector_tests --log_level=message

#include "core_io.h"
#include "crypto/sha256.h"
#include "key.h"
#include "keystore.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sign.h"
#include "test/test_bitcoin.h"
#include "uint256.h"
#include "utilstrencodings.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(sdk_sighash_vector_tests, BasicTestingSetup)

// Secret key || public key of the seed key, as CKey::Set takes it.
static const char* const SDK_VECTOR_KEY_HEX = "0b39b2d8b60903256dfc5ed15ea69f082f6d17e8f3728ae902912b050eec394d86cf485b2bc3e1d1bf8c789aa529485b4b4256a711059ad70e74779af25ddfb9e12f431cf8c0807017104ffe2f2646b0bb4b7db75e1588297c6a37da10964438ac42c302369001f2b61d4259d773cd60d1317a3790d65f8f432b03870ba7b5af19a6101405705aa22199c080a28205cc40616436914a8041193420a2188cd448066144110102510c1512e0163202022c14368de1200a58300c10a15063c648d1a851829660cb4448413282d828655134882223461140411b868d08864093c80d52c220e0144224062d1487489042302409608906518c100a1c462961806400a811d3406e4a1469c23009193881a314829938264aa26c4a06664bc00c4b226850a28512c22d19473292148512252c00470683088dd88045e3084c93024c09a88881a6284202484cb87022144802252193002e60c821a0242cdaa425d3462c4426421002428b489023a2481436484b20624b40441847249a282051047202b3509bb4249b402d029905910886e1b8255cc24d6290305b2005d4363182140e1ac551613082110485cc282922258459948962086ed480708426509bc0644a120051c685a24206241370c01822c9886012b4280a8608c1c28d9a18640c216a43a064a3b68962b064dca070d1286400a900cc88684c12041a474dc832848a002a9848726098889132212338840815040c940814262de424111a161060406182340d0c1810e3460c94346cd3c8448c282608192c04b92809182e6398495a288014b01040a24513344449b46c1a362049182813452eca9220c00411d03229403840d3008c44348118a510093326cbc08192a25188b824a4062d81a23108424409a7485c0060940429212790a4a24c01480a13c4800c304e9028840b296e64248e00958119054402124620102601466ac8340a51484914c368091184ca028cda420c8bb04ce0364a5ca46d120470d4342561362523238e603440d344414b264949006c01b38004252241b880dc227008a5918390518a36829004084316804b0425080660c4886520a1284b80898ba43048108e0900401b2260a4264ccb361122c94c0a1644138689218764938448414828a4c25121331008342821c48c612651e284511911321395801342861cb12d240912d3b00998228a5cb860d8989014232a23141151341052b00c03227240c08920424213340998308918948062089010447003b920964040bc8ddf6a8299136cc44a41e0078f21a7709c3b2cb0f19d124476d20498e73597feb0a7905f692a5502352cf5d34b32c02f0d2d345df7c07c35e2ccd523699adf9757b3ede2a08ef538e357726b5b302d4816740e3385e3c5a563cf4b6739cc49c6f1dfdd1863a8bc555fb0f0d2507bfcc86200e11aaf527d70cc3e9402ad2e1fef8a90dbb40604d893f329d64de1f30d5185c7de1be2036c93d1c250919bf592207e6266704195d6be6303a783d153e253bc8a9f25c989065bca611f3734eeb2daa31fa43ce623c403077feb6ab2543d66f2da79dbf89818ffcb3d8d755aa97e1b2d3a1e57a448a38ac3c2d36fd48d3ffc5374fbbd67fd350fc65ea948d7be64da2bc923a62a28bb1dc0da04783ddffe784610e55d51cb029b1c61ac9fe3aa6dbef6cf3db4aeeb9cee4613c163b7befe7ea9efcebeaefbbd38da06051d5cc6f4dc1d95f4dd490ed52fe256c45fa67b51a1a26bdd6ef4f3a46d6a08261954b4b6254ec072af298f63a07d7d77d47b63db19c65a7c168991ca81abce8be68ed33a5ad2f21fdd9c83d8c30bb348ddcc4e9f4cf8cb50e072f1cf857be49aaa61efa89dc33ccc9019a1898b21dacd97bbad87ef5a3cd6421760743016ae88f70e761d14e81f8cdc3f250a0cca769e70f9d27cc9df9795382d18ae3b9b33a560d62d97e795ea4b3dcc1e3d9762c81445ac6ea4f5fee45c537ae4cccef95372e271a1e01deadf8577097ab941aaa871f51c49f61c155c0ec09235a20645561d577a65cf0b4408b542301710559422e39172f323d137f22c3db20ec329002433fc47f7e5ac5ed267c56dcd73cc6a0e97878ee7f9775c76874f81d14d11ce842fc44be37d41b41a9cd84db635000804c87e9919517cd4f423d5d779720b7cd173689b20952607c1c6a0754a7775bf451132f3a5f629955aa3c252c20bb000c208d4b880912b6f9d65fc391edde1e0885a96146d5bd8c34d6e2db698c626a40b6a08513cc472003cee160839c3ceb5c1223ac90f223a3f108e9835d5dc9d06cd8dd5c9f18c0455659cdc83bec9fb9e2fe9dd0c509b33132ab43bda2303872109599aeedc33597a92ec771b50ffefb5bd570220086ad2e66f121521d1ff894c9a8119e432321bca4edc2b1e40f65e34d57e4d1c03c6c4323b20823e95051a43a63999ba87066f2a3aadeff58dc92053dadf1dcf86be219bc6989d17eee324a53c703cdce648c313cd1027f5c8602d74a22bb530fe6c035a2206799c9ce8f9c850f0e1791a16355eacd28d0d75a8b8284cefcb2dee740bdf725aa507be5d737e08bbed103211963e281dca021440b3dd55d95da6d1676edcabaf94edc8b4c7d19a4bf6158f0ab4e055e7652368afe464b78560512ed04f7902dad2a56140d4bd5bfe38d4750470beb4fc1a54987f0d72a460c038724a355c667d1b09e858cb96908032b2e50529bbc1a8374cb325182918d9241c691ad7e043344a9271b14a8844479eafa571b743fd3f0b83d89dd6d7299f24a1fa448b9c461999b62d144b4e19f6d54ace1f7b87595c4bbe2cc06e7eee15ef5b12b79a9b846948b2f10128512b6d7ee836df42b984fbb28629a34efb753d9d196cb92d4b2ac5edb5193629b6da5c9cd4bce23f1e94de8f86f35a935a963d4ea3874e10450758b98602cee089eb43eb6d3f0f7fdc7cf3a4bbcc63827c7eeaa369eb9278dd3dfc6c01dbcc9bdfebc4e1ae63e9c727cd6af369b83265fec0569f009ac58e7ffdfd576ad5cc3bd2922c09c7e41afe9c174e36bc4d066ffc770e4198c29e551b33aef1c7f2c7329a558352ceb06c2485e0c8af41bbb7ce44d85d434674e01f51e1e0a4588d5116c184ddb9b2c0dc005fe149d023ebedcc3c929a8a85e8d3929b62c231a61099402e9573b28fad784e86c6ae40be4cee4e4e9f63f76c3b3d403f70aba90a35880df81f4e4db3daf44a3605bcbc49ff72b9686d58554e27cdcbf7cffc049aba6c5994b75b4b844fa63c0bc2820e613afa062da976505e06d112387cb9877686f8a8f6ef99b01512ae07e3e518c75b1e051d73415cff249d621b5083e470c2ecbd169ba3ed1fc8abf303492a395531bdd3d92d65adcebc635f5bd8060bb5eb4530b57f2c4eed0bd368687853170a4b5dc46071403ebddf6b885c71433139ee193c9e6bb46c14b7e17a4f0995d451a9d65796afaf4c09c71c659dfc8bbba1baebd9e75ab0cff28b2e4d7f7e11e5abde6a8747b8529a582445cd3f1615cad40db28e7ad91b460f3bfe38dd353d78018f11972f42849267adda5302959c72a773a5357f859534346659726ff2562602c634b9da0a38ca7a4efb0d3befc02fa8a03925aa92c1bb770b39b2d8b60903256dfc5ed15ea69f082f6d17e8f3728ae902912b050eec394df924571b1621f473eaab733ebd7d16a3c374090fc31d1eb87deb71304a892bbfdda5457e4c932a139516e9e891b0c76411ab93df0e2e4f99b1ec7d66541b9079a38d741245958de393701c8d600bfecc882ea700ca8b9b08ecfb4e18b663a6025e0ab69858ec010ea2665b2682aa6a330ee01594b7a90c320646e8baff768dd9f99c5436acfa8f6c38f18234fc12961b26f88c3f7a0ae42861a6e392b8079c88425d5f74d3302a2ad5217c90599228fb289e4b5d1173a6f3554a0b66b82ec2e7a9e1d0b05744f9c5a84035a60bd2a91ee6ce7ca426ec5507ee2962221014f2ea087ad38d8ada7703ea5507171480cc36af6e1cfad74aca0f0751c53ded7af3f6fd111adfd2f15937e9f4d19f99ecb914005c8e6164f20db494a75a3f668ee994b41ae398afa0f766b96ae8f5649a24952d45abc9ab62b08bbd65ab3549328b8593db30a1a9d497d343adf8b70d3d937e4204176f2f55a7b81d4215172fe45b6af506013690f92cd0bd21cac6cf263e41609b68797d8b90279a3d43ebc0285fb1711a6fb98be8ba4b4a8158720e9e9b7309e32cdcacf8e38ffc23dcfe9c6912ab27c2802b7143df6b89baaa851f8025c7007e7579c86031170edc0968cabc98c69bde46de2065e2d078b109e6078a906b969b269dd050e3c2c7b84b1da349c03004da5797803788d8f318b0db7cb02deb6e3d6d05713c856f8fd3c3be0e0413a7a94107560185dfe955e533c1093624549ad9e5e93c1f380879c4296be525ff56f42aeebf1b801017c932df8c216a9355c72a1e48110946f7dea26449e6a5e913762ff8ccd6f75f6d17e34bd79d0cbdcd1c250f2cd0b53a73e719378ba375d066d3478ef3d8cc87305e26c8a5adde3332f5f7f4ad706233f56d44b6466179a5a8b8758336da54c159128bb04e8b0b156f76413462a3de9b8567b0477c4837482057560d40d4936ea59d0e5b57b7d78983ce265d26e299a4f840f2e5496c0b49f573561a337fb033d1ddadf331d47f272291e5595088fe4333e81c9c07422536e82c02fd83cd121142fa56dc4bdf5086968a16de2c867678692c8c485fbdab7ca0ca2bc7bdeb7e400a9c2d8179194f43ebbae8c291aa4010ec4c88b7c47e6e987a811a63cee5387407364d0af83f812a251f642b93674b6835dabb594f9d405ef49dcaf5c6ba6caf9999a150c0f669860776bc6302c54c8bfc0fcc92ebbf32fbb9d188136908f0c5ad158b230bfa62313b3ff6c629c2e0b89b7669f4e15b0d86ecdd00124207bb2e2b6c442de70387cdddab26c60372446d78fe1f59ac247c961f272526190388040ff188e58136739e40ccefbf472bc1bbcb127809075c21dd6760229ffcebb829dda468bb2cc98ace3ae776b1f28053552979851a5e9b2544c0fed1f6583ab1528abf72a89115f434cbeb801c4e23c0f1508bb6b26443d4fdffa1ec5f6c618ae7ea40a3de328da923d3af67b115b9701a841b32f3f7d91e746ab3ac77a23ae596aa2c11b31fe650465172209b23f68e6834853e3e949176e948ea7004becf5e4829d129b1074b21d7edd986d89c1690bb68a6e2f7ba961af9c00b75439d0a99d964b06d977cf273eec0b1c7a0c6ac804684a44335863513d0d20d5a7ecb1abbd4ee9134d1dfad5b1e809c63f63bd8899d1790c28bd0a49f8c91246331dc21544a6f0aa6e444056a0018aaa98cd432c26f43c4208e7c7412b51f0b94125f5816cbf9afd681c753cbe4062239e90ab7547f100bbf036a63928845bfce8fa0e4e026227277604596f32742f0c00e9d1b29d88b434c240258a90690";

// SHA-256 of the raw 1312-byte public key: the witness v1 program.
static const char* const SDK_VECTOR_PROGRAM =
    "ec671f444afa19d8ee919c21c76fd2fbda2d17dc173fe75e94c2fdbea5ef366b";

// Prevouts in display order, as an RPC or the SDK's UTXO type carries them.
static const char* const SDK_VECTOR_PREVOUT_TXID[2] = {
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    "f0e0d0c0b0a090807060504030201000ffeeddccbbaa99887766554433221100"};
static const uint32_t SDK_VECTOR_PREVOUT_N[2] = {0, 3};
static const CAmount SDK_VECTOR_AMOUNT[2] = {5000000000LL, 1234567890LL};

// Payment to a program of 32 x 0x33, change back to the seed key.
static const CAmount SDK_VECTOR_PAY = 4000000000LL;
static const CAmount SDK_VECTOR_CHANGE = 2232517890LL;

// SIGHASH_ALL digests per input, raw byte order (the bytes handed to the
// signer), and the txid in display order. Recorded from this test.
static const char* const SDK_VECTOR_DIGEST[2] = {
    "1e40260eedf36670d02f8c341a873f12c298598d3c41d88fe36b23c1fd6209e3",
    "ef738e53f0e0f02a0c4787398d61365b7567fae8243ff26205e138ca8d503e38"};
static const char* const SDK_VECTOR_TXID = "b77cd3e98008b45f8b8f20583527ee2e806fec53dedf8e9f2217d45965e4c399";

static CMutableTransaction SdkVectorTransaction(const CScript& changeScript)
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 0;
    for (int i = 0; i < 2; i++) {
        CTxIn in;
        in.prevout = COutPoint(uint256S(SDK_VECTOR_PREVOUT_TXID[i]), SDK_VECTOR_PREVOUT_N[i]);
        in.nSequence = 0xffffffff;
        tx.vin.push_back(in);
    }
    std::vector<unsigned char> payProgram(32, 0x33);
    tx.vout.push_back(CTxOut(SDK_VECTOR_PAY, CScript() << OP_1 << payProgram));
    tx.vout.push_back(CTxOut(SDK_VECTOR_CHANGE, changeScript));
    return tx;
}

BOOST_AUTO_TEST_CASE(node_signs_the_sdk_vector)
{
    std::vector<unsigned char> keyBytes = ParseHex(SDK_VECTOR_KEY_HEX);
    BOOST_REQUIRE_EQUAL(keyBytes.size(), 2560u + 1312u);
    CKey key;
    key.Set(keyBytes.begin(), keyBytes.end(), false);
    BOOST_REQUIRE(key.IsValid());
    CPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());
    BOOST_REQUIRE_EQUAL(pubkey.size(), 1312u);

    uint256 program;
    CSHA256().Write(pubkey.begin(), pubkey.size()).Finalize(program.begin());
    BOOST_CHECK_EQUAL(HexStr(program.begin(), program.end()), SDK_VECTOR_PROGRAM);
    CScript scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(program.begin(), program.end());

    CMutableTransaction tx = SdkVectorTransaction(scriptPubKey);
    BOOST_CHECK_EQUAL(tx.GetHash().GetHex(), SDK_VECTOR_TXID);

    CBasicKeyStore keystore;
    BOOST_REQUIRE(keystore.AddKey(key));

    // The node's own signing path, as soqucoin-tx sign= and the wallet drive it.
    for (unsigned int i = 0; i < 2; i++) {
        SignatureData sigdata;
        BOOST_REQUIRE_MESSAGE(
            ProduceSignature(MutableTransactionSignatureCreator(&keystore, &tx, i, SDK_VECTOR_AMOUNT[i], SIGHASH_ALL),
                             scriptPubKey, sigdata),
            "ProduceSignature failed for input " << i);
        UpdateTransaction(tx, i, sigdata);
    }

    // The witness does not change the txid.
    BOOST_CHECK_EQUAL(tx.GetHash().GetHex(), SDK_VECTOR_TXID);

    for (unsigned int i = 0; i < 2; i++) {
        uint256 digest = SignatureHash(scriptPubKey, tx, i, SIGHASH_ALL, SDK_VECTOR_AMOUNT[i], SIGVERSION_WITNESS_V0);
        BOOST_CHECK_EQUAL(HexStr(digest.begin(), digest.end()), SDK_VECTOR_DIGEST[i]);

        const std::vector<std::vector<unsigned char> >& stack = tx.vin[i].scriptWitness.stack;
        BOOST_REQUIRE_EQUAL(stack.size(), 2u);
        BOOST_REQUIRE_EQUAL(stack[0].size(), 2421u);
        BOOST_CHECK_EQUAL(stack[0].back(), (unsigned char)SIGHASH_ALL);
        BOOST_REQUIRE_EQUAL(stack[1].size(), 1313u);
        BOOST_CHECK_EQUAL(stack[1][0], 0x00);
        BOOST_CHECK(std::equal(pubkey.begin(), pubkey.end(), stack[1].begin() + 1));
        BOOST_CHECK(tx.vin[i].scriptSig.empty());

        ScriptError err = SCRIPT_ERR_OK;
        BOOST_CHECK_MESSAGE(
            VerifyScript(tx.vin[i].scriptSig, scriptPubKey, &tx.vin[i].scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS,
                         MutableTransactionSignatureChecker(&tx, i, SDK_VECTOR_AMOUNT[i]), &err),
            "input " << i << ": " << ScriptErrorString(err));

        // The digest commits to the amount: one shor more and the same witness
        // fails at the signature check itself, not earlier.
        err = SCRIPT_ERR_OK;
        BOOST_CHECK(!VerifyScript(tx.vin[i].scriptSig, scriptPubKey, &tx.vin[i].scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS,
                                  MutableTransactionSignatureChecker(&tx, i, SDK_VECTOR_AMOUNT[i] + 1), &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SIG_NULLFAIL);
    }

    BOOST_TEST_MESSAGE("sdk vector signed transaction: " << EncodeHexTx(tx));
    for (unsigned int i = 0; i < 2; i++) {
        BOOST_TEST_MESSAGE("sdk vector input " << i << " digest: "
                           << HexStr(SignatureHash(scriptPubKey, tx, i, SIGHASH_ALL, SDK_VECTOR_AMOUNT[i], SIGVERSION_WITNESS_V0)));
    }
    BOOST_TEST_MESSAGE("sdk vector txid: " << tx.GetHash().GetHex());
}

BOOST_AUTO_TEST_SUITE_END()
