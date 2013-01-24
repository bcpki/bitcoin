//#include <locale>
#include "alias.h"
#include "hash.h" // Hash
#include "base58.h" // CBitcoinAddress
#include "txdb.h" // GetFirstMatch
#include "bitcoinrpc.h" // ValueFromAmount

#include <boost/foreach.hpp>
using namespace std;
using namespace json_spirit;

/* CBcValue */

void CBcValue::init_uint256(const uint256 val) {
  value = val;
  key.SetSecretByNumber(val);
  keyID = key.GetPubKey().GetID();
  fSet = true;
}

bool CBcValue::init_vch(vector<unsigned char> vch) {
  if (vch.size() > 32)
    return false;
  vch.resize(32);
  uint256 val(vch);
  init_uint256(val); 
  return fSet;
}

bool CBcValue::init_uint160(uint160 val) {
  std::vector<unsigned char> vch(val.begin(),val.end());
  return init_vch(vch);
};

CBcValue::CBcValue(const string& str) {
    if (!IsHex(str))
      throw runtime_error("CBcValue::CBcValue:: hash not in hex format");

    if (str.size() > 64)
      throw runtime_error("CBcValue::CBcValue:: hex str is more than 64 characters (32 bytes)");

    init_uint256(uint256(str));
}

bool CBcValue::AppearsInScript(const CScript script, bool fFirst) const {
  txnouttype typeRet = TX_NONSTANDARD;
  vector<vector<unsigned char> > vSolutions;
  if (!Solver(script, typeRet, vSolutions))
    return false;

  if (typeRet != TX_MULTISIG)
    return false;

  if (fFirst)
    return (CPubKey(vSolutions[1]) == key.GetPubKey());
  else
    BOOST_FOREACH(const vector<unsigned char> sol, vSolutions)
    {
      if (CPubKey(sol) == key.GetPubKey())
	return true;
    }
  return false;
}

vector<unsigned int> CBcValue::FindInCoins(const CCoins coins, const int64 minamount,  bool fFirst) const {
  vector<unsigned int> outs;
  unsigned int i;
  BOOST_FOREACH(const CTxOut &out, coins.vout) {
    if (AppearsInScript(out.scriptPubKey, fFirst) && (out.nValue >= minamount))
      {
	outs.push_back(i);
	i++;
      }
  }
  return outs;
}

bool CBcValue::IsValidInCoins(const CCoins coins) const {
  std::vector<unsigned int> outs = FindInCoins(coins, (int64) 100*50000, true);
  return (outs.size() > 0);
}

CScript CBcValue::MakeScript(const vector<CPubKey> owners) const {
  CScript script;
  vector<CKey> keys (1,key);
  BOOST_FOREACH(const CPubKey owner, owners) {
    CKey newkey;
    newkey.SetPubKey(owner);
    keys.push_back(newkey);
  } 
  script.SetMultisig(keys.size(), keys);

  return script;
};

Object CBcValue::ToJSON() {
  Object result;
  result.push_back(Pair("value-LE", GetLEHex()));
  result.push_back(Pair("pubkey", GetPubKeyHex()));
  uint160 hash = Hash160(GetPubKey().Raw());
  result.push_back(Pair("pubkeyhash", HexStr(hash.begin(),hash.end())));
  result.push_back(Pair("pubkeyhash", GetPubKeyIDHex()));
  result.push_back(Pair("addr", CBitcoinAddress(GetPubKeyID()).ToString()));
  return result;
}

/* CAlias */

bool CAlias::check(const string& str) {
  if (str.size() == 0)
    return false;
  unsigned char c = str[0];
  if (!((c>=65 && c<=90) || (c>=97 && c<=122)))
    return false;
  BOOST_FOREACH(unsigned char c, str)
  {
      if (!((c>=65 && c<=90) || (c>=97 && c<=122) || (c>=48 && c<=57) || (c==95) || (c==45)))
	return false;
  }
  c = str[str.size()-1];
  if (!((c>=65 && c<=90) || (c>=97 && c<=122) || (c>=48 && c<=57)))
    return false;
  return true;
  return (normalize(str).size() > 0);
}

string CAlias::normalize(const string& str) {
  string result = "";
  unsigned char last(0);
  BOOST_FOREACH(unsigned char c, str)
  {
    // skip _,-
    if (c==45 || c==95)
      continue;
    // toupper
    if (c>=97 && c<=122)
	c = c-(97-65);
    // convert O to 0
    if (c==79)
      c = 48;
    // convert I,L to 1
    if (c==73 || c==76)
      c = 49;
    // skip repetitions
    if (c==last)
      continue;
    result += c;
    last = c;
  }
  //return BTCPKI_PREFIX + result;
  return result;
}

CAlias::CAlias(const string& str) {
  if (check(str))
    {
    name = str;
    normalized = normalize(name);
    vector<unsigned char> vch(normalized.begin(),normalized.end());
    hash = Hash160(vch);
    init_uint160(hash);
    //init_uint256(Hash(vch.begin(),vch.end()));
    }
}

string CAlias::addressbookname(pubkey_type type) const {
  switch (type)
    {
    case ADDR:
      return name+"_ADDR_"+BTCPKI_VERSION;
    case OWNER:
      return name+"_OWNER_"+BTCPKI_VERSION;
    case CERT:
      return name+"_CERT_"+BTCPKI_VERSION;
    default:
      return "";
    }
} 

/* deprecated
bool CAlias::AppearsInScript(const CScript script) const {
  txnouttype typeRet = TX_NONSTANDARD;
  vector<vector<unsigned char> > vSolutions;
  if (!Solver(script, typeRet, vSolutions))
    return false;

  return ((typeRet == TX_MULTISIG) && (CPubKey(vSolutions[1]) == key.GetPubKey()));
}
*/

bool CAlias::IsValidInCoins(const CCoins coins) const {
  std::vector<unsigned int> outs = FindInCoins(coins, (int64) 100*50000, true);
  return (outs.size() > 0);
}

/* deprecated
int CAlias::LookupSignatures(vector<CPubKey>& sigs) const {
  boost::function<bool (const CCoins)> func;
  boost::function<bool (const CAlias* first, const CCoins)> mem;
  mem = std::mem_fun(&CAlias::IsValidInCoins);
  func = std::bind1st(mem, this);
  uint256 txid;
  if (!pcoinsTip->GetFirstMatch(func, txid))
    return -1;
  CCoins coins;
  pcoinsTip->GetCoins(txid, coins);
  sigs.clear();
  BOOST_FOREACH(const CTxOut &out, coins.vout) {
    ExtractPubKeysFromMultisig(out.scriptPubKey,sigs); //appends found pubkeys to sigs vector
  }
  return coins.nHeight;
}
*/

bool CAlias::Lookup(uint256& txidRet) const {
  boost::function<bool (const CCoins)> func;
  boost::function<bool (const CAlias* first, const CCoins)> mem;
  mem = std::mem_fun(&CAlias::IsValidInCoins);
  func = std::bind1st(mem, this);
  return pcoinsTip->GetFirstMatch(func, txidRet);
}

bool CAlias::VerifySignature(const CBcValue val, uint256& txidRet) const {
  if (!Lookup(txidRet))
    return false;

  CCoins coins;
  if (!pcoinsTip->GetCoins(txidRet, coins))
    throw runtime_error("CAlias::VerifySignature: GetCoins failed.");

  return val.IsValidInCoins(coins);
}
  
Object CAlias::ToJSON() {
  Object result;
  result.push_back(Pair("fSet", fSet));
  result.push_back(Pair("str", name));
  result.push_back(Pair("normalized", normalized));
  result.push_back(Pair("hash", hash.GetHex()));
  result.push_back(Pair("hashraw", HexStr(hash.begin(),hash.end())));
  result.push_back(Pair("bcvalue", CBcValue::ToJSON()));
  return result;
}

/* CRegistrationEntry */

CRegistrationEntry::CRegistrationEntry(const CAlias& alias, const CPubKey& owner, const uint256& certhash) {
  aliasKey = alias.GetKey();
  ownerKey.SetPubKey(owner);

  fCert = (certhash > 0);
  fBacked = false;
  if (fCert)
    certKey.SetSecretByNumber(certhash);
}

CScript CRegistrationEntry::GetScript() const {
  CScript script;
  vector<CKey> keys;
  keys.push_back(aliasKey);
  keys.push_back(ownerKey);
  if (fCert)
      keys.push_back(certKey);
  script.SetMultisig(keys.size(), keys);

  return script;
};
  
/* deprecated
bool CRegistrationEntry::SetByScript(const CScript& scriptPubKey) {
  vector<CPubKey> pubkeys;
  if (!ExtractPubKeysFromMultisig(scriptPubKey,pubkeys))
    return false;

  if (pubkeys.size() < 2) 
    return false;
  
  aliasKey.SetPubKey(pubkeys[0]);
  ownerKey.SetPubKey(pubkeys[1]);
  if (pubkeys.size() > 2)
    {
      fCert = true;
      certKey.SetPubKey(pubkeys[2]);
    }
  else
    fCert = false;
  return true;
}
*/

int64 CRegistrationEntry::GetNValue() const {
  CCoins coins;
  pcoinsTip->GetCoins(outpt.hash, coins);
  return coins.vout[outpt.n].nValue;
};

Object CRegistrationEntry::ToJSON() const {
  Object result;
  result.push_back(Pair("alias", KeyToJSON(aliasKey)));
  result.push_back(Pair("owner", KeyToJSON(ownerKey)));
  result.push_back(Pair("fcert", fCert));
  if (fCert)
   result.push_back(Pair("cert", KeyToJSON(certKey)));
  result.push_back(Pair("script", ScriptToJSON(GetScript())));

  // Backed
  result.push_back(Pair("fbacked", fBacked));
  if (fBacked)
    {
      result.push_back(Pair("outpt", OutPointToJSON(outpt)));
      result.push_back(Pair("amount",ValueFromAmount(GetNValue())));
    }
  return result;
}

/* CRegistration */

/* deprecated
bool CRegistration::Lookup(const CAlias& alias) {

  CCoins coins;
  fBacked = pcoinsTip->GetFirstMultisigWithPubKey(alias.GetPubKey(),txid,coins,outs);
  if (!fBacked)
    return false;

  for (unsigned int i=0; i<outs.size(); i++) {
    unsigned int nOut = outs[i];
    CRegistrationEntry entry;
    if (!entry.SetByScript(coins.vout[nOut].scriptPubKey))
      throw runtime_error("CRegistration::Lookup: SetByScript failed.");
    entry.outpt = COutPoint(txid,nOut);
    entry.fBacked = true;
    vreg.push_back(entry);
  };
  return true;
};
*/

Object CRegistration::ToJSON() const {
  Object result;
  result.push_back(Pair("fBacked", fBacked));
  if (fBacked)
    {
      CCoins coins;
      pcoinsTip->GetCoins(txid, coins);
      result.push_back(Pair("txid",txid.ToString()));
      result.push_back(Pair("coins", CoinsToJSON(coins)));
      result.push_back(Pair("nEntries", (int)outs.size()));
    }

  Array entries;
  BOOST_FOREACH(CRegistrationEntry regentry, vreg)
  {
    entries.push_back(regentry.ToJSON());
  }
  result.push_back(Pair("entries", entries));
  
  return result;
}

/* CPubKey */

Object PubKeyToJSON(const CPubKey& key) {
  Object result;
  result.push_back(Pair("pubkey", HexStr(key.Raw())));
  result.push_back(Pair("addr", CBitcoinAddress(key.GetID()).ToString()));
  return result;
};

/* CKey */

Object KeyToJSON(const CKey& key) {
  Object result;
  result.push_back(Pair("pubkey", HexStr(key.GetPubKey().Raw())));
  result.push_back(Pair("addr", CBitcoinAddress(key.GetPubKey().GetID()).ToString()));
  if (key.HasPrivKey())
    {
      //    result.push_back(Pair("privkey", HexStr(pk.begin(),pk.end())));
      bool fCompr;
      const CSecret& sec = key.GetSecret(fCompr);
      result.push_back(Pair("secret", HexStr(sec.begin(),sec.end())));
    }
  return result;
};

/* CScript */

Object ScriptToJSON(const CScript& script) {
  Object result;
  result.push_back(Pair("raw", HexStr(script.begin(), script.end())));
  result.push_back(Pair("str", script.ToString()));
  return result;
};

/* CCoins */

Object CoinsToJSON(const CCoins& coins, bool fOuts) {
  Object result;
  if ((unsigned int)coins.nHeight == MEMPOOL_HEIGHT)
    result.push_back(Pair("confirmations", 0));
  else
    result.push_back(Pair("confirmations", pcoinsTip->GetBestBlock()->nHeight - coins.nHeight + 1));
  result.push_back(Pair("nHeight", coins.nHeight));
  CBlockIndex *pindex = FindBlockByHeight(coins.nHeight);
  result.push_back(Pair("nTime", strprintf("%u",pindex->nTime)));
  result.push_back(Pair("strTime", DateTimeStrFormat("%Y-%m-%dT%H:%M:%S", pindex->nTime).c_str()));
  Array outs;
  BOOST_FOREACH(const CTxOut &out, coins.vout) {
    outs.push_back(ScriptToJSON(out.scriptPubKey));
  }
  result.push_back(Pair("outs", outs));
  return result;
};

/* COutPoint */

Object OutPointToJSON(const COutPoint& outpt) {
  Object result;
  result.push_back(Pair("txid", outpt.hash.GetHex()));
  result.push_back(Pair("n", (int)outpt.n));
  return result;
};

/* uint256 txid */

Object TxidToJSON(const uint256& txid) {
  CCoins coins;
  if (!pcoinsTip->GetCoins(txid, coins))
    throw runtime_error("TxidToJSON: GetCoins failed.");
  Object result = CoinsToJSON(coins,true);
  result.push_back(Pair("txid", txid.ToString()));
  return result;
};

  

