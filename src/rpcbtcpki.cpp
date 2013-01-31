// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "bitcoinrpc.h"
#include "alias.h" 
#include "bcert.h"  
#include "init.h"
//in deprecated functions #include <openssl/sha.h>

using namespace json_spirit;
using namespace std;
using namespace boost;
using namespace boost::assign; // list_of

// TODO copy here from rpcraw...
/* do we need this?
#include <boost/assign/list_of.hpp>
#include "bitcoinrpc.h"
#include "base58.h"
*/


// utils
void rpc_ScriptPubKeyToJSON(const CScript& scriptPubKey, Object& out)
{
    txnouttype type;
    vector<CTxDestination> addresses;
    int nRequired;

    out.push_back(Pair("asm", scriptPubKey.ToString()));
    out.push_back(Pair("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired))
    {
        out.push_back(Pair("type", GetTxnOutputType(TX_NONSTANDARD)));
        return;
    }

    out.push_back(Pair("reqSigs", nRequired));
    out.push_back(Pair("type", GetTxnOutputType(type)));

    Array a;
    BOOST_FOREACH(const CTxDestination& addr, addresses)
        a.push_back(CBitcoinAddress(addr).ToString());
    out.push_back(Pair("addresses", a));
}

Value rpc_TxToJSON(const CTransaction& tx)
{
  Object entry;
    entry.push_back(Pair("txid", tx.GetHash().GetHex()));
    entry.push_back(Pair("version", tx.nVersion));
    entry.push_back(Pair("locktime", (boost::int64_t)tx.nLockTime));
    Array vin;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        Object in;
        if (tx.IsCoinBase())
            in.push_back(Pair("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
        else
        {
            in.push_back(Pair("txid", txin.prevout.hash.GetHex()));
            in.push_back(Pair("vout", (boost::int64_t)txin.prevout.n));
            Object o;
            o.push_back(Pair("asm", txin.scriptSig.ToString()));
            o.push_back(Pair("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
            in.push_back(Pair("scriptSig", o));
        }
        in.push_back(Pair("sequence", (boost::int64_t)txin.nSequence));
        vin.push_back(in);
    }
    entry.push_back(Pair("vin", vin));
    Array vout;
    for (unsigned int i = 0; i < tx.vout.size(); i++)
    {
        const CTxOut& txout = tx.vout[i];
        Object out;
        out.push_back(Pair("value", ValueFromAmount(txout.nValue)));
        out.push_back(Pair("n", (boost::int64_t)i));
        Object o;
        rpc_ScriptPubKeyToJSON(txout.scriptPubKey, o);
        out.push_back(Pair("scriptPubKey", o));
        vout.push_back(out);
    }
    entry.push_back(Pair("vout", vout));
    return entry;
}

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

vector<vector<unsigned char> > CoinValues(const CCoins coins) {
  vector<vector<unsigned char> > values;
  BOOST_FOREACH(const CTxOut &out, coins.vout) {
    txnouttype typeRet = TX_NONSTANDARD;
    vector<vector<unsigned char> > vSolutions;
    if (!Solver(out.scriptPubKey, typeRet, vSolutions))
      continue;
    if (typeRet != TX_MULTISIG)
      continue;
    if (out.nValue >= BCPKI_MINAMOUNT)
      values.push_back(vSolutions[1]);
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
    vector<vector<unsigned char> > values = CoinValues(coins);
    BOOST_FOREACH(vector<unsigned char> val, values) {
      uint160 hash = Hash160(val);
      result.push_back(Pair("value", HexStr(hash.begin(),hash.end())));
    }
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
    Array ownerArray; // just for return object
    while (owners.size() < nOwners) {
      // get new owner pubkey from keypool
      CPubKey newKey;
      if (!pwalletMain->GetKeyFromPool(newKey, false))
	throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
      owners.push_back(newKey);
      ownerArray.push_back(PubKeyToJSON(newKey));
    }
    if (JSONverbose > 0) result.push_back(Pair("owners", ownerArray));
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
    wtx.mapValue["bcsign"] = string("v") + BCPKI_VERSION;
    // values are needed later to spend the outputs for revocation (they need to be imported as privkeys) 
    wtx.mapValue["bcvalues"] = "";
    BOOST_FOREACH(CBcValue val, values) {
      wtx.mapValue["bcvalues"] += val.GetLEHex() + " ";
      wtx.mapValue["privkeys"] += val.GetPrivKeyB58() + " ";
    }
    wtx.mapValue["owners"] = "";
    BOOST_FOREACH(CPubKey owner, owners)
      wtx.mapValue["owners"] += HexStr(owner.Raw()) + " ";
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

// RPCs alias...
// do not access blockchain
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
            "Returns the list of pubkeys of type owner or base that have generated for the given alias.");

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

Value aliasdump(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "aliasget <alias>\n"
            "Returns different values associated with alias: the normalized alias, the hash of that (called the \"bcvalue\"), the derived pubkey (bcvalue*basepoint of curve, called the \"pubkey\"), the hash of that pubkey (called the \"id\"), and that hash b58encoded into a bitcoin address (called the \"address\")."
	    "The id (equivalently, the address) can be calculated from any of the other values, is therefore used as a locator (e.g. database index, filename) for meta-data associated with alias.\n");

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
	
	/*
	string helloStr("hello");
	std::vector<unsigned char> hello(helloStr.begin(),helloStr.end());
	result.push_back(Pair("hellohex", HexStr(hello)));
	result.push_back(Pair("hellohash", Hash(hello.begin(),hello.end()).GetHex()));
	uint256 hash1;
	SHA256(&hello[0], hello.size(), (unsigned char*)&hash1);
	result.push_back(Pair("hellosha", hash1.GetHex()));
	hash1 = 1;
	result.push_back(Pair("hello1", hash1.GetHex()));
	hash1 = 16;
	result.push_back(Pair("hello16", hash1.GetHex()));
	hash1 = 256;
	result.push_back(Pair("hello256", hash1.GetHex()));
	std::vector<unsigned char> hash2(32,0);
	SHA256(&hello[0], hello.size(), &hash2[0]);
	result.push_back(Pair("hash2", HexStr(hash2)));
	uint256 hash3(hash2);
	result.push_back(Pair("hash3", hash3.GetHex()));
	uint256 hash4(HexStr(hash2));
	result.push_back(Pair("hash4", hash4.GetHex()));
	*/
      }

    //    CBcValue val(params[1].get_str());
 
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
            "Returns the unique transaction (or none) that contains the (currently) valid signatures of <alias>.\n");

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
	"The first argument is a valid alias name (limited charset, etc)."
	"The optional second argument (null allowed) is a list of a number n (should be 1 or 2) and (currently) 1 or 2 pubkeys that \"own\" the alias."
	"At least n of the listed pubkeys are required to revoke the alias."
	"Null means n=1 and one fresh generated pubkey is chosen from a newly created account in the wallet."
	"The ownerpubkeys are given in compressed hex format (33bytes)."
	"An empty hex string (e.g. as in \",02...\" or \"02...,\" or \",\") is replaced by a freshly generated pubkey.\n"
	"The optional third argument (null allowed) is a list of (arbitrary length) of values in hex format."
	"The values are interpreted as little-endian numbers and can be up to 32 bytes in length."
	"Null means that a certificate with the correct filename for alias is looked up in the local certificate store and the hash of its data part is taken as the single vale."
	"Alternatively, an empty hex string is also replaced by this hash.\n"
	"Suppose N values are given and m (= 1 or 2) ownerpubkeys."
	"This call creates and commits a transaction with N+1 explit (i.e. non-P2SH) multi-signature outputs (plus one regular output for change, if applicable)."
	"Each output has the form: n+1 <value-pubkey> <owner-pubkey> .. m+1 OP_CHECKMULTISIG."
	"The value-pubkeys are derived from alias, value1, ..., valueN by taking first Hash160 and then multiplying the base point of the curve with that value."
	"The amounts are chosen automatically (currently 0.05 BTC per output, which is 100 times the transaction fee)\n";
      
      throw runtime_error(msg);
    }

  rpc_testnetonly();
    
    // collect output in here
    Object result;

    // parse first argument
    unsigned int nOwners = 0; // total number of owners expected
    unsigned int nReq;
    vector<CPubKey> owners;
    Array ownerArray; // just for return object
    string aliasStr;
    // there are two variants for first argument: long and short
    if (1) {
      // long variant
      RPCTypeCheck(params, list_of(obj_type)(array_type),true);
      const Object& aliasObj = params[0].get_obj();
      RPCTypeCheck(aliasObj, map_list_of("alias", str_type)("n", int_type)("owners", array_type),true);
  
      // alias
      if (find_value(aliasObj, "alias").type() == null_type)
        throw JSONRPCError(-8, "alias missing");
      aliasStr = find_value(aliasObj, "alias").get_str();
      if (JSONverbose > 0) result.push_back(Pair("aliasStr", aliasStr));
  
      // count owners
      if (find_value(aliasObj, "owners").type() != null_type) {
        nOwners = find_value(aliasObj, "owners").get_array().size();
        if (nOwners > 2)
  	throw JSONRPCError(-8, "only up to 2 owners allowed");
      }
      
      // nRequired
      if (find_value(aliasObj, "n").type() == null_type) {
        if (nOwners == 0)
  	nReq = nOwners = 1; // require one pubkey from keypool
        else
  	nReq = nOwners; // require all listed pubkeys
      }
      else {
        nReq = find_value(aliasObj, "n").get_int();
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
      // collect owners
      // external owners first
      if (find_value(aliasObj, "owners").type() != null_type) {
        BOOST_FOREACH(Value ownerVal, find_value(aliasObj, "owners").get_array()) {
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
    } // end long variant of first argument
    else {
      // short variant
      RPCTypeCheck(params, list_of(str_type)(array_type),true);
      aliasStr = params[0].get_str();
      nOwners = 1; // just one owner from the keypool
    }
    
    // build alias
    CAlias alias = rpc_buildalias(aliasStr);
    if (JSONverbose > 0) result.push_back(Pair("aliasArg", alias.ToJSON()));
      
    // test lookup
    uint256 txid;
    if (!(JSONverbose > 0) && alias.Lookup(txid))
      throw runtime_error("RPC bcsign: valid signature already present in blockchain. not signing again.");

    // collect values including alias
    vector<CBcValue> values (1,alias);
    // parse second argument
    bool fCertVal = (params.size() == 1);
    if (params.size() > 1) {
      Array valueArray = params[1].get_array();
      BOOST_FOREACH(const Value& val, valueArray)
      {
        string valStr = val.get_str();
	if (valStr.size() == 0)
	  fCertVal = true;
	else
	    values.push_back(CBcValue(valStr));
      }
    }

    // TODO this should be removed from here into bcsigncert, right?
    // add cert value
    if (fCertVal) {
      CBitcoinCert cert(alias);
      if (JSONverbose > 0) result.push_back(Pair("cert", cert.ToJSON()));
      /*
      string signee;
      cert.GetSignee(signee);
      result.push_back(Pair("signee", signee));
      CAlias signeealias(signee);
      result.push_back(Pair("signeeIDHex", signeealias.GetPubKeyIDHex()));
      result.push_back(Pair("aliasIDHex", alias.GetPubKeyIDHex()));
      */
      if (!(cert.IsSet()))
	//throw JSONRPCError(-8, "warning: certificate signature does not seem to match alias");
	return result;
      values.push_back(CBcValue(cert.GetHash160()));
    }

    // collect internal owners
    while (owners.size() < nOwners) {
      // get new owner pubkey from keypool
      CPubKey owner = rpc_aliasnew(alias,OWNER);
      owners.push_back(owner);
      ownerArray.push_back(PubKeyToJSON(owner));
    }
    if (JSONverbose > 0) result.push_back(Pair("owners", ownerArray));

    // build output scripts
    vector<pair<CScript,int64> > vecSend;
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

    // Wallet comments
    CWalletTx wtx;
    Value bcsigned = rpc_bcsign(values,nReq,owners.size(),owners,wtx);
    result.push_back(Pair("bcsigned", bcsigned));

    wtx.mapValue["signature"] = alias.GetName();
    // after successful commit we save the alias pubkey id in an account
    // we deliberately do not add the alias' priv key to our wallet, so the blockchain signature can not be accidentally revoked
    // note that pwalletMain->LockCoin(outpt) would not lock the output permanently, not across restarts
    // to revoke the user has to first import the privkey by hand (from the wtx comment field) and then use the spendoutput-RPC
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
	"The first argument is a valid alias name (limited charset, etc)."
	"The second argument is a hex serialized protobuf message containing the certificate.\n";
      
      throw runtime_error(msg);
    }
  // build alias
  CAlias alias = rpc_buildalias(params[0].get_str());

  // test lookup
  uint256 txid;
  if (!(JSONverbose > 0) && alias.Lookup(txid))
    throw runtime_error("RPC bcsigncert: valid signature already present in blockchain. not signing again.");

  // backward compatibility (one arg version)
  if (params.size() == 1) {
    Array arr;
    Object obj;
    obj.push_back(Pair("alias",alias.GetName()));
    arr.push_back(obj);
    return bcsign(arr,fHelp);
  }

  // build cert value
  if (!IsHex(params[1].get_str()))
    throw runtime_error("bcsigncert: second argument is not a hex string.");
  CBitcoinCert cert(params[1].get_str());
  CBcValue certval(cert.GetHash160());

  // build values vector
  vector<CBcValue> values;
  values.push_back(alias);
  values.push_back(certval); 
  vector<CPubKey> owners; // empty

  // sign
  CWalletTx wtx;
  Value result = rpc_bcsign(values,1,1,owners,wtx);

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
    if (fHelp || params.size() < 2 || params.size() > 2)
        throw runtime_error(
            "sendtoalias <alias> <amount>\n"
	    "a cert for alias is looked up in .bitcoin/testnet3/bcerts, parsed, and verified."
	    "if successful then funds are sent to the static bitcoin address contained in that certificate."
            "<amount> is a real and is rounded to the nearest 0.00000001"
            + HelpRequiringPassphrase());

    rpc_testnetonly();
    CAlias alias = rpc_buildalias(params[0].get_str());
    int64 nAmount = AmountFromValue(params[1]);

    CBitcoinCert cert;
    int nConfirmations = rpc_verify(alias,cert);
    if (nConfirmations < 0)
      throw runtime_error("sendtoalias: cert did not verify.");

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    
    CBitcoinAddress address;
    if (!cert.GetStatic(address))
      throw runtime_error("sendtoalias: cert does not contain static address.");

    // Wallet comments
    CWalletTx wtx;
    wtx.mapValue["to"]      = alias.GetNormalized() + "<static> = " + address.ToString();

    // Sending
    string strError = pwalletMain->SendMoneyToDestination(address.Get(), nAmount, wtx);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    // compile output
    Object result;
    result.push_back(Pair("nConfirmations",nConfirmations));
    result.push_back(Pair("static",address.ToString()));
    result.push_back(Pair("txid", wtx.GetHash().GetHex()));

    return result;
}

/* deprecated: this was sendtoaliasowner


    // Ticket
    if (params.size() > 2 && params[2].type() != null_type && !params[2].get_str().empty())
      {
	string hexticket = params[2].get_str();
	uint256 ticket;
	ticket.SetHex(hexticket);
	wtx.mapValue["comment"] = "Pay2Contract ticket: " + hexticket;
        address = reg.GetEntry(0).GetDerivedOwnerAddr(ticket);
      }
    else
      address = reg.GetEntry(0).GetOwnerAddr();
      
}
*/

Value spendoutpoint(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 2)
        throw runtime_error(
            "spendoutpoint <txid> <n>\n"
	    "spends the n-th output of txid to a change address.\n");

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
    {
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
    result.push_back(Pair("wtx", rpc_TxToJSON(wtx)));


    return result;
}

