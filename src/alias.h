#include <string>
#include "uint256.h"
#include "key.h" // CSecret
#include "base58.h" // CBitcoinAddress
#include "main.h" 
#include "script.h" // IsAliasRegistration

#include <boost/assign/list_of.hpp>

/*
#include "wallet.h"
#include "walletdb.h"
#include "bitcoinrpc.h"
#include "init.h"

using namespace std;
using namespace boost;
using namespace boost::assign;
*/
using namespace json_spirit;

#define BTCPKI_ALIAS "alias"
#define BTCPKI_VERSION "0.2"
#define BTCPKI_PREFIX "v0.2_"
#define BTCPKI_TESTNETONLY true
#define BTCPKI_MAXAMOUNT 50000  

using namespace std;

enum pubkey_type { ADDR, OWNER, CERT };

class CAlias 
{
    bool check(const string& name);
    string normalize(const string& str);

    string name;
    string normalized;
    uint256 hash;
    CKey key;
    // CBigNum num;

public:
    // CAlias();
    bool SetName(const string& name);

    bool isSet() const { return (name.size() > 0); };
    uint256 GetHash() const { return hash; };
    string GetHashHex() const { return hash.ToString(); };
    string GetName() const { return name; };
    string GetNormalized() const { return normalized; };
    //    CPubKey GetPubKey() const { return key.GetPubKey(); };
    CKey GetKey() const { return key; };
    CPubKey GetPubKey() const { return key.GetPubKey(); };
    string GetPubKeyHex() const { return HexStr(key.GetPubKey().Raw()); };
    CKeyID GetPubKeyID() const { return key.GetPubKey().GetID(); };
    //    CBigNum GetBignum() const { return num; };
    // CSecret GetSecret() const;
    string addressbookname(const pubkey_type type) const;
    Object ToJSON() const;
};

class CRegistration 
{
  // CPubKey aliasPubKey, ownerPubKey, certPubKey;
  CKey aliasKey, ownerKey, certKey;
  CScript script;
  bool fCert;

public:
  CRegistration() { };

  CRegistration(const CAlias& alias, const CPubKey& owner, const uint256& certhash);

  /*
  CRegistration(const CAlias alias) {
    aliasPubKey = alias.GetPubKey();
    fCert = false;
  }
  CRegistration(const CAlias alias, const CPubKey owner) {
    aliasPubKey = alias.GetPubKey();
    ownerPubKey = owner;
    fCert = false;
  }
  
  bool SetAlias(const CAlias alias);
  bool SetOwner(const CPubKey owner);
  bool SetCertHash(const uint256 certhash);
  */
  bool SetByScript(const CScript& scriptPubKey);

  CScript GetScript() const { return script; }; 
  string GetScriptHex() const { return HexStr(script.begin(), script.end()); }; 
  bool GetfCert() const { return fCert; }
  CPubKey GetOwnerPubKey() const { return ownerKey.GetPubKey(); }; 
  string GetOwnerPubKeyHex() const { return HexStr(ownerKey.GetPubKey().Raw()); }; 
  CPubKey GetCertPubKey() const { return certKey.GetPubKey(); }; 
  string GetCertPubKeyHex() const { return HexStr(certKey.GetPubKey().Raw()); }; 
  CKey GetCertKey() const { return certKey; }; 
  Object ToJSON() const;
};

Object KeyToJSON(const CKey& key);
Object ScriptToJSON(const CScript& script);
Object CoinsToJSON(const CCoins& coins);
Object OutPointToJSON(const COutPoint& outpt);
