# BCPKI

## Build

install protobuf
```
apt-get install libprotobuf-dev python-protobuf
cd src/bcert
./make.sh
cd ..
ln -s bcert.pb.cc bcert.pb.cpp
```
continue as usual
```
make -f makefile.unix 
```

## New RPCs (rpcbcpki.cpp)

### basic use (appear in wiki examples)

don't access blockchain:
- aliasdump : output all values associated with an alias name (normalization,hash,privkey,address,etc.)

access blockchain:
- bcverify : verify arbitrary signatures for a given alias, in particular verify certificates
- bclist : list all signature values for a given alias

commit transaction:
- bcsigncert : sign a given certificate under a given alias name 

- sendtoalias : send money directly to alias (certificate must be available locally)
    this can handle various methods such as static bitcoin address, pay-to-contract with single or multiple basekeys. 
- spendoutpoint : spends a given outpoint (txid,vout) to a self-owned address 
- importticket : import derived keys from a given base address and a given ticket number

### extended use (does not appear in wiki examples)
- bcsign : sign given values under a given alias name 

### deprecated

- aliasnew
- aliasget

## Python Tools

under src/bcert

library:
- e.py : conversion function between secrets, EC points, pubkeys, ids and bitcoin addresses

command line tools:
- mkcert.py : generate binary protobuf certificates (e.g. parse yaml)
- dumpcert.py : convert binary protobuf certificate to various forms (pretty-print, ascii armored, yaml, etc.)
- dumpcertstore.py : wrapper around dumpcert.py that takes alias name and looks up binary cert from local store 

TODO:
- join dumpcertstore.py with dumpcert.py
- also need up/download.py with cert server access

## Changes

### makefile.unix:
 added object:
  - bcert.o
  - alias.o
  - bcert.pb.o
  - rpctojson.o \
  - rpcbcpki.o \
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
 - CKey::SetSecretByNumber(uint256 num); 
 - CKey GetDerivedKey(std::vector<unsigned char> ticket) const;
 - key.cpp depends on bignum.h

## Useful Links

http://www.fileformat.info/tool/hash.htm
http://gobittest.appspot.com/Address