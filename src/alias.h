#ifndef BCPKI_ALIAS_H
#define BCPKI_ALIAS_H

#include <string>
#include "uint256.h"
#include "key.h" // CSecret
#include "base58.h" // CBitcoinAddress
#include "main.h" 
#include "script.h" // IsAliasRegistration
#include "json/json_spirit_utils.h"

#include <boost/assign/list_of.hpp>

#define BCPKI_SIGVERSION "0.4"
#define BCPKI_SIGPREFIX "BCSIG_v0.4_"
#define BCPKI_TESTNETONLY true
#define BCPKI_MINAMOUNT 100*50000

// debug flag, true produces more output than necessary in JSON return objects
const unsigned int JSONverbose = 0;

enum pubkey_type { ADDR, OWNER, BASE, DERIVED };

class CRegistration;

// Blockchain value 
class CBcValue
{
protected:
  std::vector<unsigned char> vch;
  CKey key;
  CKeyID keyID;
  bool fSet;

  bool init();
  bool setValue(uint160 n);
  void _toJSON(json_spirit::Object& result); // should be const

public:
  explicit CBcValue() { };
  // explicit CBcValue(const uint256 val) { init_uint256(val); };
  // should be const, but begin(),end() are not const
  // explicit CBcValue(const uint160 val) { value = val; init(); };
  explicit CBcValue(const std::vector<unsigned char> val) { vch = val; init(); };
  explicit CBcValue(const uint160 n) { setValue(n); }
  explicit CBcValue(const std::string& str); // requires hex string up to 64 characters (32 bytes), interpreted as little-endian number

  bool IsSet() const { return fSet; };
  uint160 Get160() const { std::vector<unsigned char> cp(vch); cp.resize(20); return uint160(cp); };
  uint256 Get256() const { std::vector<unsigned char> cp(vch); cp.resize(32); return uint256(cp); };
  CKey GetKey() const { return key; };
  CPubKey GetPubKey() const { return key.GetPubKey(); };
  CKeyID GetPubKeyID() const { return keyID; };
  std::string GetPubKeyHex() const { return HexStr(key.GetPubKey().Raw()); };
  std::string GetPrivKeyB58() const;
  bool AppearsInScript(const CScript script, bool fFirst = true) const;
  std::vector<unsigned int> FindInCoins(const CCoins coins, const int64 minamount = BCPKI_MINAMOUNT,  bool fFirst = true) const;
  bool IsValidInCoins(const CCoins coins) const;
  CScript MakeScript(const std::vector<CPubKey> owners, const unsigned int nReq = 0) const;
  // should be const, but begin(),end() are not const
  std::string GetPubKeyIDHex() { return HexStr(keyID.begin(),keyID.end()); };
  std::string GetLEHex() { return HexStr(vch); }; // little-endian hex string
  std::string addressbookname() { return GetLEHex() + "_VALUE"; }; 
  json_spirit::Object ToJSON();

  friend bool operator==(const CBcValue &a, const CBcValue &b) { return a.GetPubKey() == b.GetPubKey(); }
};

class CAlias: public CBcValue 
{
  std::string name;
  std::string normalized;

  bool check(const std::string& name);
  std::string normalize(const std::string& str);

 public:
  // requires a valid alias string (limited charset), applies normalization and Hash160
  explicit CAlias() { };
  explicit CAlias(const std::string& name); 

  std::string GetName() const { return name; };
  std::string GetNormalized() const { return normalized; };
  std::string addressbookname(const pubkey_type type) const; // TODO double-check this function
  bool IsValidInCoins(const CCoins coins) const;
  // TODO double-check:
  // deprecated int LookupSignatures(std::vector<CPubKey>& sigs) const;
  bool Lookup(uint256& txidRet) const;
  bool VerifySignature(const CBcValue val, uint256& txidRet) const;
  json_spirit::Object ToJSON(); // should be const 
};

/* deprecated 26.1.13
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
*/

json_spirit::Object KeyToJSON(const CKey& key);
json_spirit::Object PubKeyToJSON(const CPubKey& key);
json_spirit::Object ScriptToJSON(const CScript& script);
json_spirit::Object CoinsToJSON(const CCoins& coins, const bool fOuts = false);
json_spirit::Object OutPointToJSON(const COutPoint& outpt);
json_spirit::Object TxidToJSON(const uint256& txid);


#endif // BCPKI_ALIAS_H
