#include <string>
#include "uint256.h"
#include "key.h" // CSecret
#include "base58.h" // CBitcoinAddress
#include "main.h" 
#include "script.h" // IsAliasRegistration

#include <boost/assign/list_of.hpp>

//TODO remove using namespace from .h
//using namespace json_spirit;

#define BTCPKI_ALIAS "alias"
#define BTCPKI_VERSION "0.2"
#define BTCPKI_PREFIX "v0.2_"
#define BTCPKI_TESTNETONLY true

enum pubkey_type { ADDR, OWNER, CERT };

class CRegistration;

class CBcValue
{
protected:
  uint256 value;
  CKey key;
  bool fSet;

  void init(const uint256& val);
  explicit CBcValue() { };

public:
  explicit CBcValue(const uint256& val) { init(val); };
  explicit CBcValue(const std::string& str); // requires hex string up to 64 characters (32 bytes)

  bool IsSet() const { return fSet; };
  uint256 GetValue() const { return value; };
  CKey GetKey() const { return key; };
  CPubKey GetPubKey() const { return key.GetPubKey(); };
  CKeyID GetPubKeyID() const { return key.GetPubKey().GetID(); };
  std::string GetHex() const { return value.ToString(); };
  std::string GetPubKeyHex() const { return HexStr(key.GetPubKey().Raw()); };
  bool AppearsInScript(const CScript script, bool fFirst = true) const;
  std::vector<unsigned int> FindInCoins(const CCoins coins, const int64 minamount,  bool fFirst = true) const;
  bool IsValidInCoins(const CCoins coins) const;
  json_spirit::Object ToJSON() const;
  CScript MakeScript(const std::vector<CPubKey> owners) const;
};

class CAlias: public CBcValue 
{
  std::string name;
  std::string normalized;

  bool check(const std::string& name);
  std::string normalize(const std::string& str);

 public:
  explicit CAlias(const std::string& name); // requires a valid alias string (limited charset)
  std::string GetName() const { return name; };
  std::string GetNormalized() const { return normalized; };
  std::string addressbookname(const pubkey_type type) const; // TODO double-check this function
  bool IsValidInCoins(const CCoins coins) const;
  // TODO double-check:
  // deprecated int LookupSignatures(std::vector<CPubKey>& sigs) const;
  bool Lookup(uint256& txidRet) const;
  bool VerifySignature(const CBcValue val, uint256& txidRet) const;
  json_spirit::Object ToJSON() const;
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
  // deprecated bool SetByScript(const CScript& scriptPubKey); 
  CScript GetScript() const;
  CKeyID GetOwnerPubKeyID() const { return ownerKey.GetPubKey().GetID(); }; 
  CBitcoinAddress GetOwnerAddr() const { return CBitcoinAddress(ownerKey.GetPubKey().GetID()); }; 
  CKeyID GetCertPubKeyID() const { return certKey.GetPubKey().GetID(); }; 
  CKey GetCertKey() const { return certKey; }; 

  CBitcoinAddress GetDerivedOwnerAddr(uint256 ticket) const { return CBitcoinAddress(ownerKey.GetDerivedKey(ticket).GetPubKey().GetID()); };
  
  //bool GetfCert() const { return fCert; }
  //CPubKey GetOwnerPubKey() const { return ownerKey.GetPubKey(); }; 
  //std::string GetOwnerPubKeyHex() const { return HexStr(ownerKey.GetPubKey().Raw()); }; 
  //CPubKey GetCertPubKey() const { return certKey.GetPubKey(); }; 
  //std::string GetCertPubKeyHex() const { return HexStr(certKey.GetPubKey().Raw()); }; 

  // Backed const
  int64 GetNValue() const;

  // All
  json_spirit::Object ToJSON() const;

  // Old
  //  std::string GetScriptHex() const { return HexStr(script.begin(), script.end()); }; 

  friend class CRegistration;
};

class CRegistration 
{
  std::vector<CRegistrationEntry> vreg;

  bool fBacked;
  uint256 txid;
  std::vector<unsigned int> outs;
  
public:
  CRegistration() { fBacked = false; };

  // deprecated bool Lookup(const CAlias& alias);

  // const
  unsigned int GetNEntries() const { return vreg.size(); };
  CRegistrationEntry GetEntry(unsigned int n) const { return vreg[n]; };
  json_spirit::Object ToJSON() const;

  friend class CAlias;
};

json_spirit::Object KeyToJSON(const CKey& key);
json_spirit::Object PubKeyToJSON(const CPubKey& key);
json_spirit::Object ScriptToJSON(const CScript& script);
json_spirit::Object CoinsToJSON(const CCoins& coins, const bool fOuts = false);
json_spirit::Object OutPointToJSON(const COutPoint& outpt);
json_spirit::Object TxidToJSON(const uint256& txid);

