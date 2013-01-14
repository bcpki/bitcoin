#include <iostream>
#include <locale>
#include "alias.h"
#include "hash.h" // requires -l ssl

#include <boost/foreach.hpp>

using namespace std;

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
  return BTCPKI_PREFIX + result;
}

//CSecret CAlias::GetSecret() const {
//  CSecret secret;
//}

bool CAlias::SetName(const string& str) {
  if (check(str))
    {
    name = str;
    normalized = normalize(name);
    hash = Hash(normalized.begin(),normalized.end());
    //    num = CBigNum(hash);
    key.SetSecretByNumber(hash);
    return true;
    }
  else
    return false;
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

Object CAlias::ToJSON() const {
  Object result;
  result.push_back(Pair("str", name));
  result.push_back(Pair("normalized", normalized));
  result.push_back(Pair("hash", hash.ToString()));
  result.push_back(Pair("pubkey", GetPubKeyHex()));
  result.push_back(Pair("addr", GetPubKeyID().ToString()));
  return result;
}

/* CRegistration */

CRegistration::CRegistration(const CAlias& alias, const CPubKey& owner, const uint256& certhash) {
  // aliasPubKey = alias.GetPubKey();
  aliasKey = alias.GetKey();
  ownerKey.SetPubKey(owner);
  vector<CKey> keys;
  keys.push_back(aliasKey);
  keys.push_back(ownerKey);

  fCert = false;
  if (certhash > 0)
    {
      certKey.SetSecretByNumber(certhash);
      //      if (!certKey.SetSecretByNumber(certhash))
      //throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "CRegistration: SetSecretByNumber failed");
      //certPubKey = certKey.GetPubKey();    
      keys.push_back(certKey);
      fCert = true;
    }

  script.SetMultisig(keys.size()-1, keys);
}

bool CRegistration::SetByScript(const CScript& scriptPubKey) {
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
  script = scriptPubKey; 
  return true;
}

Object CRegistration::ToJSON() const {
  Object result;
  result.push_back(Pair("alias", KeyToJSON(aliasKey)));
  result.push_back(Pair("owner", KeyToJSON(ownerKey)));
  result.push_back(Pair("fcert", fCert));
  if (fCert)
    result.push_back(Pair("cert", KeyToJSON(certKey)));
  result.push_back(Pair("redeemScript", ScriptToJSON(script)));
  return result;
}

/* CKey */

Object KeyToJSON(const CKey& key) {
  Object result;
  result.push_back(Pair("pubkey", HexStr(key.GetPubKey().Raw())));
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

Object CoinsToJSON(const CCoins& coins) {
  Object result;
  if ((unsigned int)coins.nHeight == MEMPOOL_HEIGHT)
    result.push_back(Pair("confirmations", 0));
  else
    result.push_back(Pair("confirmations", pcoinsTip->GetBestBlock()->nHeight - coins.nHeight + 1));
  result.push_back(Pair("nHeight", coins.nHeight));
  CBlockIndex *pindex = FindBlockByHeight(coins.nHeight);
  result.push_back(Pair("nTime", strprintf("%u",pindex->nTime)));
  result.push_back(Pair("strTime", DateTimeStrFormat("%Y-%m-%dT%H:%M:%S", pindex->nTime).c_str()));
  return result;
};

/* COutPoint */

Object OutPointToJSON(const COutPoint& outpt) {
  Object result;
  result.push_back(Pair("txid", outpt.hash.GetHex()));
  result.push_back(Pair("n", (int)outpt.n));
  return result;
};
