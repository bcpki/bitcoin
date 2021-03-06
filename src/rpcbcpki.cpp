// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bitcoinrpc.h"
#include "bcert.h"  
#include "init.h"
#include "rpctojson.h"

using namespace json_spirit;
using namespace std;
using namespace boost;
using namespace boost::assign; // list_of

// utils
CPubKey rpc_aliasnew(const CAlias alias, pubkey_type type) {
  CPubKey newKey;
  if (!pwalletMain->GetKeyFromPool(newKey, false))
    throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
  pwalletMain->SetAddressBookName(newKey.GetID(), alias.addressbookname(type));
  return newKey;
}

CAlias rpc_buildalias(const string& name) {
  CAlias alias(name);
  if (!alias.IsSet())
    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "rpc_buildalias: alias may contain only characters a-z,A-Z,0-1,_,-, must start with letter and not end in _,-");
  return alias; 
}

pubkey_type rpc_buildtype(const string& name) {
  pubkey_type type;
  // TODO make it case-insensitive
  if (name == "owner") 
    type = OWNER;
  else if (name == "base")  
    type = BASE;
  else
    throw JSONRPCError(RPC_TYPE_ERROR, "type must be owner or base.");
  return type;
}

vector<pair<unsigned int,vector<unsigned char> > > CoinValues(const CCoins coins) {
  vector<pair<unsigned int,vector<unsigned char> > > values;
  unsigned int i = 0;
  BOOST_FOREACH(const CTxOut &out, coins.vout) {
    txnouttype typeRet = TX_NONSTANDARD;
    vector<vector<unsigned char> > vSolutions;
    i++;
    if (!Solver(out.scriptPubKey, typeRet, vSolutions))
      continue;
    if (typeRet != TX_MULTISIG)
      continue;
    if (out.nValue >= BCPKI_MINAMOUNT)
      values.push_back(make_pair(i-1,vSolutions[1]));
  }
  return values;
}

void rpc_addtxid(const uint256 txid, Object& result, bool fValues = false) {
  result.push_back(Pair("txid", txid.ToString()));
  if (JSONverbose > 0) result.push_back(Pair("tx", TxidToJSON(txid)));
  CCoins coins;
  if (!pcoinsTip->GetCoins(txid, coins))
    throw runtime_error("rpc_addtxid: GetCoins failed.");
  if ((unsigned int)coins.nHeight == MEMPOOL_HEIGHT)
    result.push_back(Pair("confirmations", 0));
  else
    result.push_back(Pair("confirmations", pcoinsTip->GetBestBlock()->nHeight - coins.nHeight + 1));
  CBlockIndex *pindex = FindBlockByHeight(coins.nHeight);
  result.push_back(Pair("strTime", DateTimeStrFormat("%Y-%m-%dT%H:%M:%S", pindex->nTime).c_str()));
  if (fValues) {
    vector<pair<unsigned int,vector<unsigned char> > > values;
    int i = 0;
    Array entries;
    BOOST_FOREACH(const CTxOut &out, coins.vout) {
      txnouttype typeRet = TX_NONSTANDARD;
      vector<vector<unsigned char> > vSolutions;
      i++;
      if (!Solver(out.scriptPubKey, typeRet, vSolutions))
	continue;
      if (typeRet != TX_MULTISIG)
	continue;
      if (out.nValue < BCPKI_MINAMOUNT)
	continue;
      //	values.push_back(make_pair(i-1,vSolutions[1]));
      Object obj;
      uint160 hash = Hash160(vSolutions[1]);
      obj.push_back(Pair("vout", i-1));
      obj.push_back(Pair("id", HexStr(hash.begin(),hash.end())));
      obj.push_back(Pair("ownersReq", vSolutions.front()[0]-1));
      //      obj.push_back(Pair("scriptPubKey", out.scriptPubKey.ToString() ));
      obj.push_back(Pair("amount", ValueFromAmount(out.nValue)));
      for(unsigned int j=2; j<vSolutions.size()-1; j++)  
	obj.push_back(Pair("owner", HexStr(vSolutions[j])));
      entries.push_back(obj);
    }
    result.push_back(Pair("values", entries));
  }
}

void rpc_testnetonly() {
  if (BCPKI_TESTNETONLY && !fTestNet)
    throw runtime_error("RPC registeralias: disabled on mainnet");
}

int rpc_verify(CAlias alias, CBitcoinCert& cert) {
  // take cert from bcerts directory
  // verify signatures
  // compare alias

  cert.ReadAliasFile(alias);
  vector<pair<CAlias, unsigned int> > ret;
  if (cert.Verify(ret)) {
    BOOST_FOREACH(const PAIRTYPE(CAlias, unsigned int)& p, ret) 
      if (p.first == alias) // (p.second >= 6)
	return p.second;
  }
  return -1;
}

Value rpc_bcsign(const vector<CBcValue> values, const unsigned int nReq, const unsigned int nOwners, vector<CPubKey>& owners, CWalletTx& wtx) {
  // check arguments
  {
    if (nReq < 1 || nOwners > 2)
      throw JSONRPCError(-8, "nOwners must be 1 or 2");
    if (nReq < 1 || nReq > nOwners)
      throw JSONRPCError(-8, "must have 1 <= nReq <= nOwners");
  }

  // collect output here
  Object result;

  // collect internal owners
  {
    while (owners.size() < nOwners) {
      // get new owner pubkey from keypool
      CPubKey newKey;
      if (!pwalletMain->GetKeyFromPool(newKey, false))
	throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
      owners.push_back(newKey);
    }
  }

  if (JSONverbose > 0) {
    Array ownerArray; // just for return object
    BOOST_FOREACH(CPubKey owner, owners)
      ownerArray.push_back(PubKeyToJSON(owner));
    result.push_back(Pair("owners", ownerArray));
  }
  
  // make output scrips
  vector<pair<CScript,int64> > vecSend;
  {
    Array outs;
    BOOST_FOREACH(CBcValue val, values)
      {
	pair<CScript,int64> out (val.MakeScript(owners,nReq),BCPKI_MINAMOUNT); // require nReq of the owner keys (currently 1 or 2) 
	vecSend.push_back(out);
	Object entry;
	entry.push_back(Pair("value",val.ToJSON()));
	entry.push_back(Pair("script",ScriptToJSON(out.first)));
	entry.push_back(Pair("nAmount",BCPKI_MINAMOUNT));
	outs.push_back(entry);
      }
    if (JSONverbose > 0) result.push_back(Pair("outs", outs));
  }

  // Wallet comments
  {
    wtx.mapValue["bcsignv"] = BCPKI_SIGVERSION;
    // values are needed later to spend the outputs for revocation (they need to be imported as privkeys) 
    wtx.mapValue["bcvalues"] = "";
    BOOST_FOREACH(CBcValue val, values) {
      wtx.mapValue["bcvalues"] += "("+val.GetPrivKeyB58()+":"+val.GetLEHex()+")";
    }
    wtx.mapValue["owners"] = "";
    BOOST_FOREACH(CPubKey owner, owners) {
      CBitcoinAddress addr;
      addr.Set(owner.GetID());
      wtx.mapValue["owners"] += "("+HexStr(owner.Raw())+":"+addr.ToString()+")";
    }
  }

  // create and commit transaction
  {
    CReserveKey keyChange(pwalletMain);
    int64 nFeeRequired;
    if (!pwalletMain->CreateTransaction(vecSend,wtx,keyChange,nFeeRequired))
      throw JSONRPCError(RPC_WALLET_ERROR, "Transaction creation failed. Sufficient funds?");
    result.push_back(Pair("nFee", ValueFromAmount(nFeeRequired)));
    if (JSONverbose > 0) result.push_back(Pair("changeKey", PubKeyToJSON(keyChange.GetReservedKey())));
    
    if (!pwalletMain->CommitTransaction(wtx, keyChange))
      throw JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed");
    result.push_back(Pair("txid", wtx.GetHash().GetHex()));
  }

  return result;
}

bool rpc_parsealiasobject(const string argStr, CAlias& alias, unsigned int& nReq, unsigned int& nOwners, vector<CPubKey>& owners, Object& result)
{
  if (argStr.size() == 0 || argStr[0] != '{')
    return false;

  Object obj;
  {
    Value val;
    if (!read_string(argStr, val))
      throw runtime_error(string("Error parsing JSON:")+argStr);
    obj = val.get_obj();
  }
  
  // alias
  {
    if (find_value(obj, "alias").type() == null_type)
      throw JSONRPCError(-8, "alias missing");
    string aliasStr = find_value(obj, "alias").get_str();
    if (JSONverbose > 0) result.push_back(Pair("aliasStr", aliasStr));
    alias = CAlias(aliasStr);
  }
  
  // count owners
  if (find_value(obj, "owners").type() != null_type) {
    nOwners = find_value(obj, "owners").get_array().size();
    if (nOwners > 2)
      throw JSONRPCError(-8, "only up to 2 owners allowed");
  }
      
  // nRequired
  if (find_value(obj, "n").type() == null_type) {
    if (nOwners == 0)
      nReq = nOwners = 1; // require one pubkey from keypool
    else
      nReq = nOwners; // require all listed pubkeys
  }
  else {
    nReq = find_value(obj, "n").get_int();
    if (nReq < 1 || nReq > 2)
      throw JSONRPCError(-8, "n must be 1 or 2");
    if (nOwners == 0)
      nOwners = nReq; // take nReq pubkeys from keypool
    else
      if (nOwners < nReq)
	throw JSONRPCError(-8, "n must be <= number of owners");
  }
  
  if (JSONverbose > 0) {
    result.push_back(Pair("nOwners", (int)nOwners));
    result.push_back(Pair("nReq", (int)nReq));
  }

  // collect external owners
  {
    Array ownerArray; // just for return object
    if (find_value(obj, "owners").type() != null_type) {
      BOOST_FOREACH(Value ownerVal, find_value(obj, "owners").get_array()) {
	if (ownerVal.type() != str_type) 
	  throw JSONRPCError(-8, "owner is not str type");
	string ownerStr = ownerVal.get_str();
	if (ownerStr.size() > 0) {   // ownerStr == "" means to add an internal owner later 
	  CPubKey ownerPubKey(ParseHex(ownerStr));
	  // TODO check if this is a valid pubkey, length of ownerStr, point on curve, etc
	  owners.push_back(ownerPubKey);
	  ownerArray.push_back(PubKeyToJSON(ownerPubKey));
	}
      }
    }
    if (JSONverbose > 0) result.push_back(Pair("externalowners",ownerArray));
  }
  return true;
}

// RPCs alias...
// do not access blockchain
/* deprecated
Value aliasnew(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "aliasnew <alias> <type> [n=1]\n"
	    "Creates a new account whose label is the normalization of alias (including version number) concatenated with the type."
	    "<type> is either \"owner\" or \"base\"."
	    "n new keys are created for this account and their pubkeys are dumped.\n");

    RPCTypeCheck(params, list_of(str_type)(str_type)(int_type));

    CAlias alias = rpc_buildalias(params[0].get_str());
    pubkey_type type = rpc_buildtype(params[1].get_str());
				  
    if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();

    // number of keys
    int n = 1;
    if (params.size() == 3)
      n = params[2].get_int();
    if (n < 1 || n > 2)
        throw JSONRPCError(RPC_TYPE_ERROR, "getowners: n must be 1 or 2.");
      
    // Generate new keys and add to wallet
    Array result; 
    for (int i=0; i<n; i++) {
      CPubKey newKey = rpc_aliasnew(alias,type);
      result.push_back(HexStr(newKey.Raw()));
    }

    return result;
}

Value aliasget(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "aliasget <alias> <type>\n"
            "Returns the list of pubkeys of type owner or base that we have generated for the given alias.");

    CAlias alias = rpc_buildalias(params[0].get_str());
    pubkey_type type = rpc_buildtype(params[1].get_str());

    // Find all addresses that have the given account
    Array ret;
    const string owner = alias.addressbookname(type);
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, string)& item, pwalletMain->mapAddressBook)
    {
        const CBitcoinAddress& address = item.first;
        const string& strName = item.second;
        if (strName != owner) 
	  continue;
	CKeyID keyID;
	if (!address.GetKeyID(keyID))
	  throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
	CKey key;
	if (!pwalletMain->GetKey(keyID, key))
	  continue; // key not in keystore
        ret.push_back(HexStr(key.GetPubKey().Raw()));
    }
    return ret;
}
*/

Value aliasdump(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "aliasget <alias>\n"
            "Returns different values associated with alias: the normalized alias, the hash of that (called the \"bcvalue\"), the bcvalue b58encoded into a privkey (called the \"privkey\"), the derived pubkey (bcvalue*basepoint of curve, called the \"pubkey\"), the hash of that pubkey (called the \"id\"), and that hash b58encoded into a bitcoin address (called the \"address\")."
	    "The id (equivalently, the address) can be calculated from any of the other values, and is therefore used as a locator (e.g. database index, filename) for meta-data associated with alias.\n");

    string str = params[0].get_str();
    if (IsHex(str)) {
      CBcValue val(str);
      return val.ToJSON();
    } else {
      CAlias alias = rpc_buildalias(str);
      return alias.ToJSON();
    }
}
  
// RPCs bcalias...
// access blockchain
Value bcverify(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2 || params.size() < 1)
        throw runtime_error(
            "bcverify <alias> [<hash>]\n"
            "verify a blockchain signature under name <alias>.\n"
	    "<hash> is in hex format up to 256 bit (64 characters).\n"
	    "if no hash is given, we look for a cert for <alias> in .bitcoin/bcerts and verify that.\n");

    Object result;

    // build alias
    CAlias alias = rpc_buildalias(params[0].get_str());
    if (JSONverbose > 0) result.push_back(Pair("alias", alias.ToJSON()));

    // look for cert for alias, just to inform the caller
    CBitcoinCert cert(alias);
    if (JSONverbose > 0) result.push_back(Pair("cert", cert.ToJSON()));

    CBcValue val;
    if (params.size() > 1)
      val = CBcValue(params[1].get_str());
    else
      {
	if (!cert.IsSet())
	  throw runtime_error("cert not found.\n");
	val = CBcValue(cert.GetHash160());
      }

    uint256 txid;
    bool fSigned = alias.VerifySignature(val,txid);
    // TODO should also return the outpoint
    // vector<unsigned int> outs = val.FindInCoins(coins); // default: (int64) BCPKI_MINAMOUNT, true

    // compile output
    if (JSONverbose > 0)
      result.push_back(Pair("val", val.ToJSON()));
    result.push_back(Pair("fSigned", fSigned));
    if (fSigned) {
      rpc_addtxid(txid,result);
    }

    return result;
}

Value bclist(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1 || params.size() < 1)
        throw runtime_error(
            "bclist <alias>\n"
            "Returns the unique transaction (or none) that contains the (currently) valid signatures of <alias>."
	    "Also outputs the values that are signed by this transaction.\n");

    Object result;

    // build alias
    CAlias alias = rpc_buildalias(params[0].get_str());
      
    // lookup
    uint256 txid;
    bool fRegistered = alias.Lookup(txid);

    // compile output
    result.push_back(Pair("fRegistered", fRegistered));
    if (JSONverbose > 0) result.push_back(Pair("alias", alias.ToJSON()));
    if (fRegistered) rpc_addtxid(txid,result,true);
    
    return result;
}

Value bcsign(const Array& params, bool fHelp)
{
  if (fHelp || params.size() < 1 || params.size() > 2)
    {
      string msg = "bcsign {'alias':alias,'n':nRequired,'owners':owner,...} [{'val':value,'n':nRequired,'owners':owner,...},...]\n"
	"The first argument is either a valid alias name or an object specifying the owners (i.e. the revocation requirements) for the signature. In the first case one single owner is used, coming from the keystore. In the second case every empty string owner is replaced by one from the keystore.\n" 
	"The second argument is a list of values in hex format (<= 32 bytes)."
	"The values are interpreted as little-endian numbers.\n"
	"The amounts are chosen automatically (currently 0.05 BTC per output)\n";
      
      throw runtime_error(msg);
    }

  rpc_testnetonly();
    
  // parse first argument
  CAlias alias;
  vector<CPubKey> owners; // empty
  unsigned int nOwners = 1;
  unsigned int nReq = 1;
  Object result;
  if (!rpc_parsealiasobject(params[0].get_str(), alias, nReq, nOwners, owners, result))
    alias = rpc_buildalias(params[0].get_str());
  if (JSONverbose > 0) result.push_back(Pair("aliasArg", alias.ToJSON()));
      
  // test lookup
  uint256 txid;
  if (!(JSONverbose > 0) && alias.Lookup(txid))
    throw runtime_error("RPC bcsign: valid signature already present in blockchain. not signing again.");

  // collect values including alias
  vector<CBcValue> values (1,alias);
  // parse second argument
  if (params.size() > 1) {
    Array valueArray = params[1].get_array();
    BOOST_FOREACH(const Value& val, valueArray)
      {
        string valStr = val.get_str();
	if (valStr.size() != 0) values.push_back(CBcValue(valStr));
      }
  }

  // sign
  CWalletTx wtx;
  Value bcsignresult = rpc_bcsign(values,nReq,nOwners,owners,wtx);
  if (JSONverbose > 0) result.push_back(Pair("bssignresult", bcsignresult));

  // additional wallet comments
  wtx.mapValue["signature"] = alias.GetName();
  // after successful commit we save the alias pubkey id in an account
  // we deliberately do not add the alias' priv key to our wallet, so the blockchain signature can not be accidentally revoked
  // note that pwalletMain->LockCoin(outpt) would not lock the output permanently, not across restarts
  // to revoke the user has to first import the privkey by hand (from the wtx comment field) and then use the spendoutpoint-RPC
  pwalletMain->SetAddressBookName(alias.GetPubKeyID(), alias.addressbookname(ADDR));
    
  // after successful commit we save the value pubkeys ids in their own accounts
  BOOST_FOREACH(CBcValue val, values) {
    pwalletMain->SetAddressBookName(val.GetPubKeyID(), val.addressbookname());
  }
    
  return result;
} // bcsign

Value bcsigncert(const Array& params, bool fHelp)
{
  if (fHelp || params.size() < 1 || params.size() > 2)
    {
      string msg = "bcsigncert <alias> <hex cert>\n"
	"bcsigncert '{\"alias\":\"aliasname\",\"n\":nRequired,\"owners\":[\"<pubkey>\",\"<pubkey>\",...]}' <hex cert>\n"
	"The first argument is either a valid alias name (limited charset, etc) or a quoted JSON object as described (see also bcsign)."
	"The second argument is a hex serialized protobuf message containing the certificate.\n"
	"This parses the certificate (i.e. protobuf message), hashes the data part of it, signs this hash under the given alias, adds the new signature to the certificate, and stores this certificate locally."
	"A lookup is preformed whether the given alias already has a signature in the blockchain, in which case we abort.";
      
      throw runtime_error(msg);
    }

  rpc_testnetonly();

  // parse first argument
  CAlias alias;
  vector<CPubKey> owners; // empty
  unsigned int nOwners = 1;
  unsigned int nReq = 1;
  Object result;
  if (!rpc_parsealiasobject(params[0].get_str(), alias, nReq, nOwners, owners, result))
      alias = rpc_buildalias(params[0].get_str());
  if (JSONverbose > 0) result.push_back(Pair("aliasArg", alias.ToJSON()));

  // test lookup
  uint256 txid;
  if (!(JSONverbose > 0) && alias.Lookup(txid))
    throw runtime_error("RPC bcsigncert: valid signature already present in blockchain. not signing again.");

  // build cert value
  if (!IsHex(params[1].get_str()))
    throw runtime_error("bcsigncert: second argument is not a hex string.");
  CBitcoinCert cert(params[1].get_str());
  CBcValue certval(cert.GetHash160());

  // build values vector
  vector<CBcValue> values;
  values.push_back(alias);
  values.push_back(certval); 

  // sign
  CWalletTx wtx;
  Value bcsignresult = rpc_bcsign(values,nReq,nOwners,owners,wtx);
  bcsignresult.get_obj().push_back(Pair("fname",alias.GetPubKeyIDHex()));
  result.push_back(Pair("bcsignresult", bcsignresult));

  // additional wallet comments
  wtx.mapValue["signature"] = alias.GetName();
  // after successful commit we save the alias pubkey id in an account
  // we deliberately do not add the alias' priv key to our wallet, so the blockchain signature can not be accidentally revoked
  // note that pwalletMain->LockCoin(outpt) would not lock the output permanently, not across restarts
  // to revoke the user has to first import the privkey by hand (from the wtx comment field) and then use the spendoutput-RPC
  pwalletMain->SetAddressBookName(alias.GetPubKeyID(), alias.addressbookname(ADDR));
  pwalletMain->SetAddressBookName(owners[0].GetID(), alias.addressbookname(OWNER));
  pwalletMain->SetAddressBookName(certval.GetPubKeyID(), certval.addressbookname());

  // add signature field to cert
  cert.AddSignature(alias);

  // store 
  cert.SaveAll();
  
  return result;
}

// RPCs send..
Value sendtoalias(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "sendtoalias <alias> '[method,values,...]' <amount> [minconf=6]\n"
	    "a certificate for alias is looked up in .bitcoin/testnet3/bcerts, parsed, and verified."
	    "if successful then funds are sent to a destination given in that certificate.\n"
	    "method is an integer: 4 for STATIC, 1 for P2CSINGLE, 2 for P2CMULTI."
	    "methods 1 and 2 (P2C) require a value which is taken as the ticket to derive the actual destination from the base that is given in the certificate."
            "<amount> is a real and is rounded to the nearest 0.00000001"
            + HelpRequiringPassphrase());

    rpc_testnetonly();

    // Minimum confirmations
    int nMinDepth = 6;
    if (params.size() > 3)
        nMinDepth = params[3].get_int();

    CAlias alias = rpc_buildalias(params[0].get_str());
    int64 nAmount = AmountFromValue(params[2]);

    CBitcoinCert cert;
    int nConfirmations = rpc_verify(alias,cert);
    if (nConfirmations < 0)
      throw runtime_error("sendtoalias: cert did not verify.");

    if (nConfirmations < nMinDepth)
      throw runtime_error(strprintf("sendtoalias: cert has only %d confirmations.",nConfirmations));

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    // Method
    Array method = params[1].get_array();
    if (method.size() == 0)
      throw runtime_error("sendtoalias: no method given, take first method from cert, not yet implemented.");

    //    if (!RPCTypeCheck(method, list_of(int_type)))
    // throw runtime_error("sendtoalias: method must be int_type.");

    unsigned int methodtype = method[0].get_int();
    CTxDestination dest;
    CWalletTx wtx;
    switch (methodtype) {
    case 4: // STATICADDR
      {
      CBitcoinAddress address;
      if (!cert.GetStatic(address))
	throw runtime_error("sendtoalias: cert does not contain static address.");
      wtx.mapValue["to"]      = alias.GetNormalized() + "<STATICADDR> = " + address.ToString();
      dest = address.Get(); 
      }
      break;
    case 1: // P2CSINGLE
      {
      CPubKey base;
      if (!cert.GetP2CSingle(base))
	throw runtime_error("sendtoalias: cert does not contain P2CSINGLE address.");
      if (method.size() < 2)
	throw runtime_error("sendtoalias: method type P2CSINGLE requires ticket.");
      vector<unsigned char> vch = ParseHex(method[1].get_str());
      wtx.mapValue["p2csingle"] = HexStr(base.Raw());
      wtx.mapValue["ticket"] += HexStr(vch);
      wtx.mapValue["to"] = alias.GetNormalized() + "<P2CSINGLE:" + HexStr(vch) + "> = ";
      CKey baseKey;
      baseKey.SetPubKey(base);
      dest = baseKey.GetDerivedKey(vch).GetPubKey().GetID();
      wtx.mapValue["to"] += CBitcoinAddress(dest).ToString();
      }
      break;
    case 2: // P2CMULTI
      {
      unsigned int nReq;
      vector<CPubKey> base;
      if (!cert.GetP2CMulti(nReq,base))
	throw runtime_error("sendtoalias: cert does not contain P2CSINGLE address.");
      if (method.size() < 2)
	throw runtime_error("sendtoalias: method type P2CSINGLE requires ticket.");
      vector<unsigned char> vch = ParseHex(method[1].get_str());
      wtx.mapValue["ticket"] += HexStr(vch);
      wtx.mapValue["to"] = alias.GetNormalized() + "<P2CMULTI:" + HexStr(vch) + "> = ";
      wtx.mapValue["p2cmulti"] = "";
      vector<CKey> derived;
      BOOST_FOREACH(CPubKey p, base) {
	wtx.mapValue["p2cmulti"] += HexStr(p.Raw()) + " ";
	CKey k;
	k.SetPubKey(p);
	derived.push_back(k.GetDerivedKey(vch));
      }
      CScript script;
      script.SetMultisig(nReq,derived);
      wtx.mapValue["to"] += script.ToString();
      dest = script.GetID();
      }
      break;
    default:
      throw runtime_error("sendtoalias: unknown payment method. only now 1=P2CSINGLE, 2=P2CMULTI, 4=STATICADDR.");
    }

    // Sending
    string strError = pwalletMain->SendMoneyToDestination(dest, nAmount, wtx);
    if (strError != "")
      throw JSONRPCError(RPC_WALLET_ERROR, strError);

    // compile output
    Object result;
    if (JSONverbose > 0) result.push_back(Pair("nConfirmations",nConfirmations));
    result.push_back(Pair("dest",CBitcoinAddress(dest).ToString()));
    result.push_back(Pair("txid", wtx.GetHash().GetHex()));
    int i = 0;
    BOOST_FOREACH(CTxOut out, wtx.vout) {
      CTxDestination tmpdest;
      if (ExtractDestination(out.scriptPubKey,tmpdest) && (tmpdest == dest))
	result.push_back(Pair("vout", i));
      i++;
    }

    return result;
}

Value spendoutpoint(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 2)
        throw runtime_error(
            "spendoutpoint <txid> <n>\n"
	    "spends the n-th output of txid to a change address.\n");

    rpc_testnetonly();

    RPCTypeCheck(params, list_of(str_type)(int_type));

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
     
    // Wallet comments
    CWalletTx wtx;
    wtx.mapValue["comment"] = strprintf("spending outpoint (%s,%d)",params[0].get_str().c_str(),params[1].get_int());
    wtx.mapValue["to"]      = "our change address";

    // compile output
    Object result;

    // create
    vector<pair<CScript, int64> > vecSend;
    CReserveKey keyChange(pwalletMain);
    int64 nFeeRequired = 0;
    vector<COutPoint> vecSpend;
    vecSpend.push_back(COutPoint(uint256(params[0].get_str()),params[1].get_int()));
    if (JSONverbose > 0) {
      Array entries;
      BOOST_FOREACH(COutPoint outp, vecSpend) 
	entries.push_back(OutPointToJSON(outp));
      result.push_back(Pair("outpoints", entries));
    }
    bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, vecSpend);
    if (!fCreated)
      throw JSONRPCError(RPC_WALLET_ERROR, "Transaction creation failed");
    result.push_back(Pair("nFee", ValueFromAmount(nFeeRequired)));
    if (JSONverbose > 0) result.push_back(Pair("changeKey", PubKeyToJSON(keyChange.GetReservedKey())));

    // commit
    if (!pwalletMain->CommitTransaction(wtx, keyChange))
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed");
    result.push_back(Pair("txid", wtx.GetHash().GetHex()));
    if (JSONverbose > 0) result.push_back(Pair("wtx", rpc_TxToJSON(wtx)));

    return result;
}

// utils for importticket

bool rpc_setderivedlabel(CTxDestination base, vector<unsigned char> ticket, CTxDestination derived) {
  string strLabel;
  if (pwalletMain->mapAddressBook.count(base))
    strLabel = pwalletMain->mapAddressBook[base];
  else
    strLabel = CBitcoinAddress(base).ToString();
  strLabel += "<" + HexStr(ticket.begin(),ticket.end()) + ">"; 
	
  pwalletMain->MarkDirty();
  return pwalletMain->SetAddressBookName(derived, strLabel);
}

bool rpc_addderivedkey(const CPubKey pubkey, const vector<unsigned char> ticket, CKey& keyRet) {
  // build base key
  CKey base;
  bool fNew = false;

  // DEBUG
  // if (!pwalletMain->HaveKey(pubkey.GetID())) 
  // throw runtime_error("rpc_addderivedkey: do not have pubkey:"+HexStr(pubkey.Raw()));

  if (pwalletMain->HaveKey(pubkey.GetID())) { // get full key from keystore
    if (!pwalletMain->GetKey(pubkey.GetID(), base))
      throw runtime_error("rpc_addderivedkey: GetKey failed.");
  } else { // set only pubkey and add to wallet and addressbook
    base.SetPubKey(pubkey);
    //    if (!pwalletMain->AddKey(base))
    // throw JSONRPCError(RPC_WALLET_ERROR, "Error adding base key from script to wallet");
    fNew = true;
  }

  // derive key
  keyRet = base.GetDerivedKey(ticket);
  
  if (fNew)
    pwalletMain->SetAddressBookName(pubkey.GetID(), "basekeystore");
  else {
    ;
    if (!pwalletMain->HaveKey(keyRet.GetPubKey().GetID())) 
      if (!pwalletMain->AddKey(keyRet)) // CAUTION: AddKey cannot add pure pubkeys?
	throw JSONRPCError(RPC_WALLET_ERROR, "Error adding derived key to wallet");
  }
  rpc_setderivedlabel(pubkey.GetID(),ticket, keyRet.GetPubKey().GetID());
  return true;
}

class CTicketVisitor : public boost::static_visitor<CTxDestination>
{
private:
  vector<unsigned char> ticket;
public:
  CTicketVisitor(vector<unsigned char>& vch) {
    ticket = vch;  
  }

  CTxDestination operator()(const CKeyID id) const {
    // look for key in wallet
    if (!pwalletMain->HaveKey(id))
      throw JSONRPCError(RPC_TYPE_ERROR, "Do not have the key for given address in store.");
    CKey base;
    if (!pwalletMain->GetKey(id, base))
      throw JSONRPCError(RPC_WALLET_ERROR, "Key for address not in keystore");
    // derive key
    CKey derived;
    if (!rpc_addderivedkey(base.GetPubKey(),ticket,derived))
      throw runtime_error("importticket: key derivation error.");
    // return derived id
    return derived.GetPubKey().GetID();
  }

  CTxDestination operator()(const CScriptID baseid) const {
    // look for script n wallet
    if (!pwalletMain->HaveCScript(baseid))
      throw JSONRPCError(RPC_TYPE_ERROR, "Do not have the script for given address in store.");
    CScript basescript;
    if (!pwalletMain->GetCScript(baseid, basescript))
      throw JSONRPCError(RPC_WALLET_ERROR, "Script for address not in keystore.");

    // extract pubkeys from script
    txnouttype type = TX_NONSTANDARD;
    vector<vector<unsigned char> > vSolutions;
    if (!Solver(basescript, type, vSolutions))
      throw runtime_error("importticket: could not parse base script.");
    vector<CPubKey> vBase;
    int nReq;
    if (type == TX_MULTISIG)
    {
        nReq = vSolutions.front()[0];
        for (unsigned int i = 1; i < vSolutions.size()-1; i++)
        {
	  vBase.push_back(CPubKey(vSolutions[i]));
        }
    }
    else if (type == TX_PUBKEY)
    {
        nReq = 1;
	vBase.push_back(CPubKey(vSolutions[0]));
    }
    else
      throw runtime_error("importticket: base script not of type TX_MULTISIG or TX_PUBKEY (need explicit pubkeys).");

    // derive keys
    vector<CKey> vKeys;
    BOOST_FOREACH(CPubKey base, vBase) {
      assert("hi");
      CKey key;
      if (!rpc_addderivedkey(base,ticket,key))
	throw runtime_error("importticket: key derivation error.");
      vKeys.push_back(key);
    }

    CScript script;
    script.SetMultisig(nReq,vKeys);
    if (!pwalletMain->AddCScript(script))
      throw JSONRPCError(RPC_WALLET_ERROR, "Error adding derived multisig script to wallet");
    rpc_setderivedlabel(baseid,ticket, script.GetID());

    return script.GetID();
  }

  CTxDestination operator()(const CNoDestination id) const {
    return id;
  }
};

Value importticket(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 4)
        throw runtime_error(
            "importticket <bitcoinaddr> <ticket> [label] [rescan=true]\n"
            "Adds derived keys to the keystore.\n"
	    "<ticket> is in hex format (<= 32 bytes)."
	    "<bitcoinaddr> can be a regular address or P2SH." 
            "This requires that the unhashed bitcoin address is present in the keystore, i.e. all pubkeys must be known.\n");

    string strAddress = params[0].get_str();
    string hexTicket = params[1].get_str();

    if (!IsHex(hexTicket))
        throw JSONRPCError(RPC_TYPE_ERROR, "ticket is not a valid hex string. odd length?");
      
    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 3)
        fRescan = params[3].get_bool();

    CBitcoinAddress address;
    if (!address.SetString(strAddress))
      throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    CTxDestination base = address.Get();

    Object result;

    // parse ticket
    vector<unsigned char> ticket = ParseHex(hexTicket); // little-endian interpretation
    if (JSONverbose > 0) result.push_back(Pair("ticket",HexStr(ticket.begin(),ticket.end())));

    // derive destination
    CTxDestination derived = boost::apply_visitor(CTicketVisitor(ticket), base);

    result.push_back(Pair("derived",CBitcoinAddress(derived).ToString()));

    {
      // TODO what about lock above?
        LOCK2(cs_main, pwalletMain->cs_wallet);

        if (fRescan) {
            pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwalletMain->ReacceptWalletTransactions();
        }
    }

    return result;
}

