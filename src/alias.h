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
#define BTCPKI_REGAMOUNT 100*50000  

using namespace std;

enum pubkey_type { ADDR, OWNER, CERT };

class CRegistration;

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
    bool AppearsInCoins(const CCoins coins) const;
    bool AppearsInScript(const CScript script) const;
    bool Lookup(vector<CPubKey>& reg) const;
    bool Verify(CPubKey sig) const;
    Object ToJSON() const;
};

class CRegistrationEntry
{
  CKey aliasKey, ownerKey;
  
  bool fCert;
  CKey certKey;

  bool fBacked;
  COutPoint outpt;

 public:
  CRegistrationEntry() { fCert = false; fBacked = false; };
  CRegistrationEntry(const CAlias& alias, const CPubKey& owner, const uint256& certhash);

  // Non-Backed const
  bool SetByScript(const CScript& scriptPubKey);
  CScript GetScript() const;
  CKeyID GetOwnerPubKeyID() const { return ownerKey.GetPubKey().GetID(); }; 
  CBitcoinAddress GetOwnerAddr() const { return CBitcoinAddress(ownerKey.GetPubKey().GetID()); }; 
  CKeyID GetCertPubKeyID() const { return certKey.GetPubKey().GetID(); }; 
  CKey GetCertKey() const { return certKey; }; 

  CBitcoinAddress GetDerivedOwnerAddr(uint256 ticket) const { return CBitcoinAddress(ownerKey.GetDerivedKey(ticket).GetPubKey().GetID()); };
  
  //bool GetfCert() const { return fCert; }
  //CPubKey GetOwnerPubKey() const { return ownerKey.GetPubKey(); }; 
  //string GetOwnerPubKeyHex() const { return HexStr(ownerKey.GetPubKey().Raw()); }; 
  //CPubKey GetCertPubKey() const { return certKey.GetPubKey(); }; 
  //string GetCertPubKeyHex() const { return HexStr(certKey.GetPubKey().Raw()); }; 

  // Backed const
  int64 GetNValue() const;

  // All
  Object ToJSON() const;

  // Old
  //  string GetScriptHex() const { return HexStr(script.begin(), script.end()); }; 

  friend class CRegistration;
};

class CRegistration 
{
  vector<CRegistrationEntry> vreg;

  bool fBacked;
  uint256 txid;
  vector<unsigned int> outs;
  
public:
  CRegistration() { fBacked = false; };

  bool Lookup(const CAlias& alias);

  // const
  unsigned int GetNEntries() const { return vreg.size(); };
  CRegistrationEntry GetEntry(unsigned int n) const { return vreg[n]; };
  Object ToJSON() const;

  friend class CAlias;
};

Object KeyToJSON(const CKey& key);
Object ScriptToJSON(const CScript& script);
Object CoinsToJSON(const CCoins& coins);
Object OutPointToJSON(const COutPoint& outpt);

