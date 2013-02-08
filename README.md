# BCPKI

## Goal

The BCPKI-project (blockchain-PKI) establishes the blockchain as a _root CA_. 
The goal is to allow a payment protocol to:
- be all-bitcoin integrated
- not rely on centralized CAs
- allow for flexible certificates

BCPKI is not a payment protocol, but establishes a special kind of _root CA_ that payment protocols may decide to use.
There may be other applications besides payment protocols.

## What has been done here

First, we have drafted a quite general specification for bitcoin certificates (protobuf messages) that allow for a variety of payment protocols (e.g. static as well as customer-side-generated payment addresses).
This part has surely been done elsewhere as well and is orthogonal to the goal of this project.
What is new here is the signatures _under_ the certificates.

We have patched the bitcoind to handle certificates, submit signatures to the blockchain, verify certificates against the blockchain, pay directly to certificates (with various payment methods), revoke certificates.
Signatures in the blockchain are stored entirely in the UTXO set (i.e. the unspend, unprunable outputs). 
This seems to make signature lookup and verification reasonably fast: 
it took us 10s in the mainnet test we performed, and is instant on the testnet.

Payment methods include: static bitcoin addresses, client-side derived
payment addresses (pay-to-contract), pay-to-contract with multisig destinations (P2SH)

Full-length real-world examples for all payment methods are provided in the tutorial pages.
These examples have actually been carried out on testnet3.

For further details and specifications see the wiki: [Technical](wiki/technical).

## Build

install protobuf:
```
apt-get install libprotobuf-dev python-protobuf
cd src/bcert
./make.sh
cd ..
ln -s bcert.pb.cc bcert.pb.cpp
```
continue as usual:
```
make -f makefile.unix 
```
create directory for binary certificates:
```
mk ~/.bitcoin/testnet3/bcerts
mk ~/.bitcoin/bcerts
```
the python command line tools require:
```
pip install ecdsa
```

## New RPCs (see rpcbcpki.cpp)

### basic use (RPCs that appear in wiki examples)

do not access blockchain:
- aliasdump : output all values associated with an alias name (normalization,hash,privkey,address,etc.)
- importticket : import derived keys from a given base address and a given ticket number (pay-to-contract)

access blockchain:
- bcverify : verify arbitrary signatures for a given alias, in particular verify certificates
- bclist : list all signature values for a given alias

commit transaction (testnet only):
- bcsigncert : sign a given certificate under a given alias name 

- sendtoalias : send money directly to alias (certificate must be available locally)
    this can handle various methods such as static bitcoin address, pay-to-contract with single or multiple basekeys. 
- spendoutpoint : spends a given outpoint (txid,vout) to a self-owned address 

### extended use (RPC that does not appear in wiki examples)

commit transaction (testnet only):
- bcsign : sign given values under a given alias name 

If you want to use the RPCs bcsigncert, sendtoalias, spendoutpoint and bcsign on the mainnet then you have to
uncomment the calls to rpc_testnetonly() throughout rpcbcpki.cpp.

### deprecated

- aliasnew
- aliasget

## Python Tools

under src/bcert

library:
- e.py : conversion functions between secrets, EC points, pubkeys, ids and bitcoin addresses
- bcert.py : wrapper around bcert_pb2.py, parsers/conversion functions for certificates (binary, ascii, hexdump, yaml, etc.)

command line tools:
- mkbcrt.py : generate binary protobuf certificates from yaml
- dumpbcrt.py : convert binary protobuf certificate to various forms (pretty-print, ascii armored, hexdump, hash digest, etc.)

## Changes

### makefile.unix:
 added object:
  - bcert.o
  - alias.o
  - bcert.pb.o
  - rpctojson.o 
  - rpcbcpki.o 
 added libs 
  - protobuf

### bitcoinrpc.cpp .h:
 - _getnewaddress_ and _dumpprivkey_ have new optional bool argument
 - new RPCs

### rpcwallet.cpp: 
 - gettransaction outputs more raw data
 - depends on rpctojson.h

### rpcdump.cpp: 
 - dumpprivkey accepts optional bool argument to output secret in hex format
 - importprivkey also accepts secret in hex format  

### rpcblockchain.cpp: 
  unchanged? copied snippets from here to elsewhere

### txdb.cpp .h: 
 - GetFirstMatch

### main.cpp .h:
 - GetFirstMatch
 
### script.cpp .h:
 unchanged?

### key.cpp .h:
 - CKey::SetSecret(vector<unsigned int>) overloaded
 - CKey GetDerivedKey(std::vector<unsigned char> ticket) const;

### wallet.cpp .h:
 - CWallet::SelectCoinsMinConf
 - CWallet::SelectCoins
 setting fClear to false these functions now build upon the set of pre-selected coins that is passed as setCoinsRet and proceed as before, i.e. select more coins as required and a change address if required.

## New Files

 - alias.h .cpp
 - bcert.h .cpp
 - rpbcpki.cpp
 - rpctojson.h .cpp

The directory src/bcert contains the protobuf specification bcert.proto and the python command line tools.
The latter build upon the file bitcoin.py from the electrum client.
Everything in this subdirectory is GPLv3.

## Useful Links

#### Hash/Conversion tools
 - http://www.fileformat.info/tool/hash.htm
 - http://gobittest.appspot.com/Address

#### Papers
 - [Homomorphic Payment Addresses and the Pay-to-Contract Protocol](http://arxiv.org/pdf/1212.3257)
