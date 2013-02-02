// Copyright (c) 2009-2012 Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h" // for pwalletMain
#include "bitcoinrpc.h"
#include "ui_interface.h"
#include "base58.h"
#include "alias.h" // KeyToJSON

#include <boost/lexical_cast.hpp>

#define printf OutputDebugStringF

using namespace json_spirit;
using namespace std;

class CTxDump
{
public:
    CBlockIndex *pindex;
    int64 nValue;
    bool fSpent;
    CWalletTx* ptx;
    int nOut;
    CTxDump(CWalletTx* ptx = NULL, int nOut = -1)
    {
        pindex = NULL;
        nValue = 0;
        fSpent = false;
        this->ptx = ptx;
        this->nOut = nOut;
    }
};

Value importticket(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 4)
        throw runtime_error(
            "importticket <bitcoinaddr or pubkey> <ticket> [label] [rescan=true]\n"
            "ticket is in hex format\n"
            "Adds the private key for (as returned by dumpprivkey) to your wallet.");

    string strAddress = params[0].get_str();
    string hexTicket = params[1].get_str();

    if (!IsHex(hexTicket))
        throw JSONRPCError(RPC_TYPE_ERROR, "ticket is not a valid hex string. odd length?");
      
    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 3)
        fRescan = params[3].get_bool();

    // find key
    CKeyID keyID;
    if (!IsHex(strAddress)) {
      CBitcoinAddress address;
      if (!address.SetString(strAddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
      if (!address.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    } else {
      keyID = CPubKey(ParseHex(strAddress)).GetID();
    }

    CKey key;
    if (!pwalletMain->GetKey(keyID, key))
      throw JSONRPCError(RPC_WALLET_ERROR, "Key for address " + strAddress + " not in keystore");
    if (!key.HasPrivKey())
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");

    vector<unsigned char> ticket = ParseHex(hexTicket); // little-endian interpretation
    ticket.resize(32);
    CKey newkey = key.GetDerivedKey(uint256(ticket));
    Object result;
    if (JSONverbose > 0) {
      result.push_back(Pair("basekey",KeyToJSON(key)));
      result.push_back(Pair("ticket",HexStr(ticket.begin(),ticket.end())));
      result.push_back(Pair("derivedkey",KeyToJSON(newkey)));
    }
      
    //    CKeyID vchAddress = newkey.GetPubKey().GetID();
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

	string strLabel;
	if (pwalletMain->mapAddressBook.count(key.GetPubKey().GetID()))
	  strLabel += pwalletMain->mapAddressBook[key.GetPubKey().GetID()];
	else
	  strLabel += HexStr(key.GetPubKey().Raw());
	strLabel += "<" + hexTicket + ">"; 
	if (params.size() > 2)
	  strLabel += ": " + params[2].get_str();
	
        pwalletMain->MarkDirty();
        pwalletMain->SetAddressBookName(newkey.GetPubKey().GetID(), strLabel);

        if (!pwalletMain->AddKey(newkey))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding derived key to wallet");
	
        if (fRescan) {
            pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwalletMain->ReacceptWalletTransactions();
        }
    }

    return result;
}

Value importprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "importprivkey <bitcoinprivkey> [label] [rescan=true]\n"
            "Adds a private key (as returned by dumpprivkey) to your wallet."
	    "Now also accepts a little-endian hex number as the secret instead of bitcoinprivkey.\n");

    string strSecret = params[0].get_str();
    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    CKey key;
    if (IsHex(strSecret)) { // hex encoded secret
      vector<unsigned char> vch = ParseHex(strSecret);
      vch.resize(32);
      key.SetSecretByNumber(uint256(vch));
    } else {
      CBitcoinSecret vchSecret;
      if (!vchSecret.SetString(strSecret))
	throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
      bool fCompressed;
      CSecret secret = vchSecret.GetSecret(fCompressed);
      key.SetSecret(secret, fCompressed);
    }

    CKeyID vchAddress = key.GetPubKey().GetID();
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        pwalletMain->MarkDirty();
        pwalletMain->SetAddressBookName(vchAddress, strLabel);

        if (!pwalletMain->AddKey(key))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");
	
        if (fRescan) {
            pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwalletMain->ReacceptWalletTransactions();
        }
    }

    return Value::null;
}

Value dumpprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "dumpprivkey <bitcoinaddress> [raw=false]\n"
            "Reveals the private key corresponding to <bitcoinaddress>.");

    string strAddress = params[0].get_str();
    CBitcoinAddress address;
    if (!address.SetString(strAddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    CKeyID keyID;
    if (!address.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    CSecret vchSecret;
    bool fCompressed;
    if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");

    if (params.size() > 1 && params[1].get_bool())
      return HexStr(vchSecret.begin(),vchSecret.end());
    else
      return CBitcoinSecret(vchSecret, fCompressed).ToString();
}
