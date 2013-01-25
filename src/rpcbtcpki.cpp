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

// RPCs
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
    result.push_back(Pair("alias", alias.ToJSON()));

    // look for cert for alias, just to inform the caller
    BitcoinCert cert(alias);
    result.push_back(Pair("cert", cert.ToJSON()));
    string signee;
    cert.GetSignee(signee);
    result.push_back(Pair("signee", signee));
    CAlias signeealias(signee);
    result.push_back(Pair("signeeIDHex", signeealias.GetPubKeyIDHex()));
    result.push_back(Pair("aliasIDHex", alias.GetPubKeyIDHex()));

    CBcValue val;
    if (params.size() > 1)
      val = CBcValue(params[1].get_str());
    else
      {
	if (!cert.IsSet())
	  return result;
	//	  throw runtime_error("cert not found.\n");
	val = CBcValue(cert.GetHash160());
	uint256 hash;
	bcert::BitcoinCertData data = cert.cert.data();
	string ser;
	data.SerializeToString(&ser);
	std::vector<unsigned char> vch(ser.begin(),ser.end());
	result.push_back(Pair("data", HexStr(vch)));
	result.push_back(Pair("datastr", HexStr(ser.begin(),ser.end())));
	uint160 hash160 = Hash160(vch);
	result.push_back(Pair("datahash160", HexStr(hash160.begin(),hash160.end())));
	
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

    // compile output
    if (JSONverbose > 0)
      result.push_back(Pair("val", val.ToJSON()));
    result.push_back(Pair("fSigned", fSigned));
    if (fSigned) {
      result.push_back(Pair("tx", TxidToJSON(txid)));
      CCoins coins;
      if (!pcoinsTip->GetCoins(txid, coins))
	throw runtime_error("CAlias::VerifySignature: GetCoins failed.");
      return val.IsValidInCoins(coins);
      //vector<unsigned int> outs = FindInCoins(coins, (int64) 100*50000, true);
      vector<unsigned int> outs = val.FindInCoins(coins);
      result.push_back(Pair("nOut", (int)outs[0]));
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
    result.push_back(Pair("alias", alias.ToJSON()));
      
    // lookup
    uint256 txid;
    bool fRegistered = alias.Lookup(txid);

    // compile output
    result.push_back(Pair("fRegistered", fRegistered));
    if (fRegistered)
      result.push_back(Pair("tx", TxidToJSON(txid)));
    if (JSONverbose > 0) {
      result.push_back(Pair("alias", alias.ToJSON()));
    }
    
    return result;
}


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
    // testnet only?
    if (BTCPKI_TESTNETONLY && !fTestNet)
      throw runtime_error("RPC bcsign: disabled on mainnet");
    
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
      result.push_back(Pair("aliasStr", aliasStr));
  
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
  
      result.push_back(Pair("nOwners", (int)nOwners));
      result.push_back(Pair("nReq", (int)nReq));
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
    CAlias alias(aliasStr);
    if (!alias.IsSet())
      throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "RPC getregistrations: alias may contain only characters a-z,A-Z,0-1,_,-, must start with letter and not end in _,-");
    result.push_back(Pair("aliasArg", alias.ToJSON()));

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

    // add cert value
    if (fCertVal) {
      BitcoinCert cert(alias);
      result.push_back(Pair("cert", cert.ToJSON()));
      /*
      string signee;
      cert.GetSignee(signee);
      result.push_back(Pair("signee", signee));
      CAlias signeealias(signee);
      result.push_back(Pair("signeeIDHex", signeealias.GetPubKeyIDHex()));
      result.push_back(Pair("aliasIDHex", alias.GetPubKeyIDHex()));
      */
      if (!(cert.IsSet() && cert.IsSigneeMatch()))
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
    result.push_back(Pair("owners", ownerArray));

    // build output scripts
    vector<pair<CScript,int64> > vecSend;
    Array outs;
    BOOST_FOREACH(CBcValue val, values)
      {
	pair<CScript,int64> out (val.MakeScript(owners,nReq),100*50000); // require nReq of the owner keys (currently 1 or 2) 
	vecSend.push_back(out);
	Object entry;
	entry.push_back(Pair("value",val.ToJSON()));
	entry.push_back(Pair("script",ScriptToJSON(out.first)));
	entry.push_back(Pair("nAmount",100*50000));
	outs.push_back(entry);
      }
    result.push_back(Pair("outs", outs));

    // Wallet comments
    CWalletTx wtx;
    wtx.mapValue["comment"] = "signature v";
    wtx.mapValue["comment"] += BTCPKI_VERSION;
    wtx.mapValue["comment"] += ": " + alias.GetName();

    // create transaction
    CReserveKey keyChange(pwalletMain);
    int64 nFeeRequired;
    if (!pwalletMain->CreateTransaction(vecSend,wtx,keyChange,nFeeRequired))
      throw JSONRPCError(RPC_WALLET_ERROR, "Transaction creation failed. Sufficient funds?");
    result.push_back(Pair("nFee", ValueFromAmount(nFeeRequired)));

    // commit
    if (!pwalletMain->CommitTransaction(wtx, keyChange))
      throw JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed");
    result.push_back(Pair("txid", wtx.GetHash().GetHex()));

    // after successful commit we save the alias pubkey in an account
    // TODO we don't check if it is new
    pwalletMain->SetAddressBookName(alias.GetPubKeyID(), alias.addressbookname(ADDR));
    // disabled: add alias priv key to wallet (this prevents accidentally revoking the registration because the output remains unspendable)
    // note that pwalletMain->LockCoin(outpt) locks only temporarily, no across restarts
    // make an import-RPC for that containing this: pwalletMain->AddKey(alias.GetKey())

    // after successful commit we save the value pubkeys in their own accounts
    // TODO give the cert a more descriptive label
    BOOST_FOREACH(CBcValue val, values) {
      pwalletMain->SetAddressBookName(val.GetPubKeyID(), val.addressbookname());
      // make an import-RPC for that containing this: pwalletMain->AddKey(val.GetKey())
    }
    
    return result;
} // bcsign

// TODO implement this, taking payment keys from cert
Value sendtoaliasowner(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "sendtoaliasowner <alias> <amount> [ticket]\n"
	    "a registration for <alias> is looked up in the blockchain"
	    "funds are sent to the owner pubkey"
	    "if there are several registration entries then the first one is chosen"
            "<amount> is a real and is rounded to the nearest 0.00000001"
	    "<ticket> is a hex number, if given then funds are sent to ticket*ownerpubkey" 
            + HelpRequiringPassphrase());

    return 0;
}

/* deprecated
    // testnet only?
    if (BTCPKI_TESTNETONLY && !fTestNet)
      throw runtime_error("RPC registeralias: disabled on mainnet");
    
    // build alias
    CAlias alias(params[0].get_str());
    if (!alias.IsSet())
      throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "RPC sendtoaliasowner: alias may contain only characters a-z,A-Z,0-1,_,-, must start with letter and not end in _,-");

    // Amount
    int64 nAmount = AmountFromValue(params[1]);

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    // Lookup
    CRegistration reg;
    if (!reg.Lookup(alias))
      throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "RPC sendtoaliasowner: alias not registered in the blockchain.");

    // Wallet comments
    CWalletTx wtx;
    wtx.mapValue["to"]      = "BTCPKI alias: " + alias.GetName();

    CBitcoinAddress address;
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
      
    // Sending
    string strError = pwalletMain->SendMoneyToDestination(address.Get(), nAmount, wtx);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}
*/

