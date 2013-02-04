// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "alias.h"
#include "util.h" // ParseHex
#include "hash.h" // Hash
#include "base58.h" // CBitcoinAddress
#include "txdb.h" // GetFirstMatch
#include "bitcoinrpc.h" // ValueFromAmount

#include <boost/foreach.hpp>
using namespace std;
using namespace json_spirit;

/* CBcValue */

bool CBcValue::init() {
  fSet = key.SetSecretByNumber(Get256());
  if (fSet)
    keyID = key.GetPubKey().GetID();
  return fSet;
};

CBcValue::CBcValue(const string& str) {
    if (!IsHex(str))
      throw runtime_error("CBcValue::CBcValue:: hash not in hex format");

    if (str.size() > 40)
      throw runtime_error("CBcValue::CBcValue:: hex str is more than 40 characters (20 bytes)");

    vch = ParseHex(str);
    init();
}

bool CBcValue::setValue(uint160 n) {
  vch = vector<unsigned char>(n.begin(),n.end());
  return init();
}

string CBcValue::GetPrivKeyB58() const {
  bool fCompressed;
  CSecret secret = key.GetSecret(fCompressed);
  return CBitcoinSecret(secret,true).ToString();
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
  std::vector<unsigned int> outs = FindInCoins(coins); // use defaults for optional arguments, should be minamount=100*50000, fFirst=true
  return (outs.size() > 0);
}

CScript CBcValue::MakeScript(const vector<CPubKey> owners, const unsigned int nReq) const {
  CScript script;
  vector<CKey> keys (1,key);
  BOOST_FOREACH(const CPubKey owner, owners) {
    CKey newkey;
    newkey.SetPubKey(owner);
    keys.push_back(newkey);
  }
  if (nReq == 0)
    script.SetMultisig(keys.size(), keys); // default: require all keys
  else
    script.SetMultisig(nReq+1, keys); // require n of owners + the value key itself 

  return script;
};

void CBcValue::_toJSON(Object& result) {
  result.push_back(Pair("bcvalue", GetLEHex()));
  if (JSONverbose > 0) {
    result.push_back(Pair("fSet", IsSet()));
    result.push_back(Pair("bigendian", Get256().GetHex()));
    result.push_back(Pair("key", KeyToJSON(key)));
  }
  result.push_back(Pair("privkey", GetPrivKeyB58()));
  result.push_back(Pair("pubkey", GetPubKeyHex()));
  result.push_back(Pair("id", GetPubKeyIDHex()));
  result.push_back(Pair("addr", CBitcoinAddress(GetPubKeyID()).ToString()));
}

Object CBcValue::ToJSON() {
  Object result;
  _toJSON(result);
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
  return BCPKI_SIGPREFIX + result;
}

CAlias::CAlias(const string& str) {
  if (check(str))
    {
    name = str;
    normalized = normalize(name);
    uint160 n = Hash160(vector<unsigned char>(normalized.begin(),normalized.end()));
    if (!setValue(n))
      throw runtime_error("CAlias::CAlias(string): initialization error.");
    }
}

string CAlias::addressbookname(pubkey_type type) const {
  switch (type)
    {
    case ADDR:
      return normalized+"_ADDR";
    case OWNER:
      return normalized+"_OWNER";
    case BASE:
      return normalized+"_BASE";
    case DERIVED:
      return normalized+"_DERIVED";
    }
  throw runtime_error("CAlias::addressbookname: unknown type.");
  return "";
} 

bool CAlias::IsValidInCoins(const CCoins coins) const {
  std::vector<unsigned int> outs = FindInCoins(coins, (int64) 100*50000, true);
  return (outs.size() > 0);
}

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
  if (JSONverbose > 0) {
    result.push_back(Pair("str", name));
    result.push_back(Pair("fSet", fSet));
  }
  result.push_back(Pair("normalized", normalized));
  _toJSON(result);
  if (JSONverbose > 0) result.push_back(Pair("owner account", addressbookname(OWNER)));
  return result;
}

/* CPubKey */

Object PubKeyToJSON(const CPubKey& key) {
  Object result;
  result.push_back(Pair("pubkey", HexStr(key.Raw())));
  CKeyID id = key.GetID();
  result.push_back(Pair("hash160", HexStr(id.begin(),id.end())));
  result.push_back(Pair("addr", CBitcoinAddress(key.GetID()).ToString()));
  return result;
};

/* CKey */

Object KeyToJSON(const CKey& key) {
  Object result;
  result.push_back(Pair("isCompressed", key.IsCompressed()));
  result.push_back(Pair("pubkey", HexStr(key.GetPubKey().Raw())));
  CKeyID keyID = key.GetPubKey().GetID();
  result.push_back(Pair("id", HexStr(keyID.begin(),keyID.end())));
  result.push_back(Pair("addr", CBitcoinAddress(key.GetPubKey().GetID()).ToString()));
  if (key.HasPrivKey())
    {
      bool fCompr;
      const CSecret& sec = key.GetSecret(fCompr);
      result.push_back(Pair("secret", HexStr(sec.begin(),sec.end())));
      result.push_back(Pair("privkey", CBitcoinSecret(sec,true).ToString()));
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



