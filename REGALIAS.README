http://www.fileformat.info/tool/hash.htm
http://gobittest.appspot.com/Address

INSTALL
-------
cd bcert
protoc --cpp_out=.. bcert.proto
cd ..
mv bcert.pb.cc bcert.pb.cpp
 
CHANGES
-------
Makefile:
  bcert.o
  alias.o
  bcert.pb.o
  -l libprotobuf
bitcoinrpc.cpp .h:
  registeralias
  getregistrations
rpcwallet.cpp: 
  registeralias RPC
  derived from createmultisig
rpcblockchain.cpp: 
  getregistrations RPC
  derived from gettxoutsetinfo
txdb.cpp: 
  CCoinsViewDB::GetAliasRegistration(CPubKey searchKey) -> txID, ccoins, outs
  derived from CCoinsViewDB::GetStats
script.cpp:
  IsMultisigWithPubKey(CScript scriptPubKey, CPubKey searchKey) -> bool 
  ExtractPubKeysFromMultisig(CScript scriptPubKey) -> vector<CPubKey>
  derived from ExtractDestination
alias.cpp:
  class CAlias
  class CRegistration
  new
main.cpp:
  CCoinsView::GetFirstMultisigWithPubKey
  CCoinsViewBacked::GetFirstMultisigWithPubKey
  derived from GetStats
main.h:
  class CCoinsView:
    virtual bool GetFirstMultisigWithPubKey
  class CCoinsViewBacked:
    bool GetFirstMultisigWithPubKey
  derived from GetStats
key.cpp:
  SetSecretByNumber (derived from SetSecret)
  HasPrivKey (derived from GetPrivKey)


cd src
make -f makefile.unix
./bitcoind -testnet stop ; sleep 1 ; ./bitcoind -testnet -daemon
protoc --python-output=. cert.proto
./mycert.py

Example
-------
$ ./mycert.py
{
    "txid" : "fe42d4c0c223d57a9aed5a12a7cd9ada408be48c52d3904f461d729b16
+af9518",
    "alias_str" : "ALIAS_TESTV1_FOO",
    "alias_pubkey" : "02e0195388643da614b6bc15f7dc75af94947112d2a9d835f9
+c15f9771688823d5",
    "alias_pubkey_addr" : "n272R5QJKqtEqoYKqL6gB18j19xtPyRoBc",
    "owner_pubkey" : "02bc1a3277fee367f9d3935bb02361c1d8f95ad7a9fe03e321
+a28f3275772c95f5",
    "owner_pubkey_addr" : "msGLjNx8sNeZGAYtu2nBFnVPDdkZP1Ru9M",
    "redeemScript" : "532102e0195388643da614b6bc15f7dc75af94947112d2a9d8
+35f9c15f9771688823d52102bc1a3277fee367f9d3935bb02361c1d8f95ad7a9fe03e32
+1a28f3275772c95f521027e860652a243d97bafdcc4aaa948d61b6ae3ab74a3c00037f4
+eb89a9503a9c6253ae",
    "redeemScript_str" : "3 02e0195388643da614b6bc15f7dc75af94947112d2a9
+d835f9c15f9771688823d5
+02bc1a3277fee367f9d3935bb02361c1d8f95ad7a9fe03e321a28f3275772c95f5
+027e860652a243d97bafdcc4aaa948d61b6ae3ab74a3c00037f4eb89a9503a9c62 3
+OP_CHECKMULTISIG",
    "amount" : 0.50000000
}

(ran ./mycert twice)
$ ./bitcoind -testnet getregistrations foo
[
    {
        "scriptPubKey" : "532102e0195388643da614b6bc15f7dc75af94947112d2a9d835f9c15f9771688823d52102bc1a3277fee367f9d3935bb02361c1d8f95ad7a9fe03e321a28f3275772c95f521027e860652a243d97bafdcc4aaa948d61b6ae3ab74a3c00037f4eb89a9503a9c6253ae",
        "nRequired" : 3,
        "amount" : 0.50000000,
        "alias_pubkey" : "02e0195388643da614b6bc15f7dc75af94947112d2a9d835f9c15f9771688823d5",
        "alias_addr" : "n272R5QJKqtEqoYKqL6gB18j19xtPyRoBc",
        "owner_pubkey" : "02bc1a3277fee367f9d3935bb02361c1d8f95ad7a9fe03e321a28f3275772c95f5",
        "owner_addr" : "msGLjNx8sNeZGAYtu2nBFnVPDdkZP1Ru9M",
        "certhash" : "027e860652a243d97bafdcc4aaa948d61b6ae3ab74a3c00037f4eb89a9503a9c62"
    },
    {
        "scriptPubKey" : "532102e0195388643da614b6bc15f7dc75af94947112d2a9d835f9c15f9771688823d521029f5fba4912f0fb9f3621ea7adb2c83a96ce3177189acf72c57006b9410dbf52e21027e860652a243d97bafdcc4aaa948d61b6ae3ab74a3c00037f4eb89a9503a9c6253ae",
        "nRequired" : 3,
        "amount" : 0.50000000,
        "alias_pubkey" : "02e0195388643da614b6bc15f7dc75af94947112d2a9d835f9c15f9771688823d5",
        "alias_addr" : "n272R5QJKqtEqoYKqL6gB18j19xtPyRoBc",
        "owner_pubkey" : "029f5fba4912f0fb9f3621ea7adb2c83a96ce3177189acf72c57006b9410dbf52e",
        "owner_addr" : "n1HV6trHVN7WZZQYq5uvndUUfhbRsLFSCE",
        "certhash" : "027e860652a243d97bafdcc4aaa948d61b6ae3ab74a3c00037f4eb89a9503a9c62"
    }
]
(by now the 2nd one has already been spent)
