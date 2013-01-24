// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "bitcoinrpc.h"
//BTCPKI
#include "alias.h" 
#include "bcert.h"  
//temporary
#include <openssl/sha.h>

using namespace json_spirit;
using namespace std;

double GetDifficulty(const CBlockIndex* blockindex)
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (blockindex == NULL)
    {
        if (pindexBest == NULL)
            return 1.0;
        else
            blockindex = pindexBest;
    }

    int nShift = (blockindex->nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}


Object blockToJSON(const CBlock& block, const CBlockIndex* blockindex)
{
    Object result;
    result.push_back(Pair("hash", block.GetHash().GetHex()));
    CMerkleTx txGen(block.vtx[0]);
    txGen.SetMerkleBranch(&block);
    result.push_back(Pair("confirmations", (int)txGen.GetDepthInMainChain()));
    result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
    result.push_back(Pair("height", blockindex->nHeight));
    result.push_back(Pair("version", block.nVersion));
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
    Array txs;
    BOOST_FOREACH(const CTransaction&tx, block.vtx)
        txs.push_back(tx.GetHash().GetHex());
    result.push_back(Pair("tx", txs));
    result.push_back(Pair("time", (boost::int64_t)block.GetBlockTime()));
    result.push_back(Pair("nonce", (boost::uint64_t)block.nNonce));
    result.push_back(Pair("bits", HexBits(block.nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(blockindex)));

    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    if (blockindex->pnext)
        result.push_back(Pair("nextblockhash", blockindex->pnext->GetBlockHash().GetHex()));
    return result;
}


Value getblockcount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblockcount\n"
            "Returns the number of blocks in the longest block chain.");

    return nBestHeight;
}


Value getdifficulty(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getdifficulty\n"
            "Returns the proof-of-work difficulty as a multiple of the minimum difficulty.");

    return GetDifficulty();
}


Value settxfee(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1)
        throw runtime_error(
            "settxfee <amount>\n"
            "<amount> is a real and is rounded to the nearest 0.00000001");

    // Amount
    int64 nAmount = 0;
    if (params[0].get_real() != 0.0)
        nAmount = AmountFromValue(params[0]);        // rejects 0.0 amounts

    nTransactionFee = nAmount;
    return true;
}

Value getrawmempool(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getrawmempool\n"
            "Returns all transaction ids in memory pool.");

    vector<uint256> vtxid;
    mempool.queryHashes(vtxid);

    Array a;
    BOOST_FOREACH(const uint256& hash, vtxid)
        a.push_back(hash.ToString());

    return a;
}

Value getblockhash(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getblockhash <index>\n"
            "Returns hash of block in best-block-chain at <index>.");

    int nHeight = params[0].get_int();
    if (nHeight < 0 || nHeight > nBestHeight)
        throw runtime_error("Block number out of range.");

    CBlockIndex* pblockindex = FindBlockByHeight(nHeight);
    return pblockindex->phashBlock->GetHex();
}

Value getblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getblock <hash>\n"
            "Returns details of a block with given block-hash.");

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];
    block.ReadFromDisk(pblockindex);

    return blockToJSON(block, pblockindex);
}

Value gettxoutsetinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "gettxoutsetinfo\n"
            "Returns statistics about the unspent transaction output set.");

    Object ret;

    CCoinsStats stats;
    if (pcoinsTip->GetStats(stats)) {
        ret.push_back(Pair("bestblock", pcoinsTip->GetBestBlock()->GetBlockHash().GetHex()));
        ret.push_back(Pair("transactions", (boost::int64_t)stats.nTransactions));
        ret.push_back(Pair("txouts", (boost::int64_t)stats.nTransactionOutputs));
        ret.push_back(Pair("bytes_serialized", (boost::int64_t)stats.nSerializedSize));
    }
    return ret;
}

Value btcpkiverify(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2 || params.size() < 1)
        throw runtime_error(
            "btcpkiverify <alias> [<hash>]\n"
            "verify a blockchain signature under name <alias>.\n"
	    "<hash> is in hex format up to 256 bit (64 characters).\n"
	    "if no hash is given, we look for a cert for <alias> in .bitcoin/bcerts and verify that.\n");

    Object result;

    // build alias
    CAlias alias(params[0].get_str());
    if (!alias.IsSet())
      throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "RPC getregistrations: alias may contain only characters a-z,A-Z,0-1,_,-, must start with letter and not end in _,-");
    result.push_back(Pair("alias", alias.ToJSON()));
    string norm = alias.GetNormalized();
    vector<unsigned char> vch(norm.begin(),norm.end());
    uint160 hash = Hash160(vch);
    vector<unsigned char> vch2(hash.begin(),hash.end());
    result.push_back(Pair("vch2", HexStr(vch2.begin(),vch2.end())));

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
	  throw runtime_error("cert not found.\n");
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
    result.push_back(Pair("val", val.ToJSON()));
    result.push_back(Pair("fSigned", fSigned));
    if (fSigned)
      result.push_back(Pair("tx", TxidToJSON(txid)));
    return result;
}

Value getregistrations(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1 || params.size() < 1)
        throw runtime_error(
            "getregistrations <alias>\n"
            "Returns array of unspent transaction outputs that contain a registration of <alias>.\n"
            "This means that the output is TX_MULTISIG and contains the pubkey corresponding to <alias>.\n"
            "Results are an array of Objects, each of which has:\n"
            "{txid, vout, scriptPubKey, amount, .., owner, certhash, ... }");

    // build alias
    CAlias alias(params[0].get_str());
    if (!alias.IsSet())
      throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "RPC getregistrations: alias may contain only characters a-z,A-Z,0-1,_,-, must start with letter and not end in _,-");

      
    uint256 txid;
    bool fRegistered = alias.Lookup(txid);

    // compile output
    Object result;
    result.push_back(Pair("alias", alias.ToJSON()));
    result.push_back(Pair("fRegistered", fRegistered));
    if (fRegistered)
      result.push_back(Pair("tx", TxidToJSON(txid)));
    return result;
}

Value gettxout(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "gettxout <txid> <n> [includemempool=true]\n"
            "Returns details about an unspent transaction output.");

    Object ret;

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);
    int n = params[1].get_int();
    bool fMempool = true;
    if (params.size() > 2)
        fMempool = params[2].get_bool();

    CCoins coins;
    if (fMempool) {
        LOCK(mempool.cs);
        CCoinsViewMemPool view(*pcoinsTip, mempool);
        if (!view.GetCoins(hash, coins))
            return Value::null;
        mempool.pruneSpent(hash, coins); // TODO: this should be done by the CCoinsViewMemPool
    } else {
        if (!pcoinsTip->GetCoins(hash, coins))
            return Value::null;
    }
    if (n<0 || (unsigned int)n>=coins.vout.size() || coins.vout[n].IsNull())
        return Value::null;

    ret.push_back(Pair("bestblock", pcoinsTip->GetBestBlock()->GetBlockHash().GetHex()));
    if ((unsigned int)coins.nHeight == MEMPOOL_HEIGHT)
        ret.push_back(Pair("confirmations", 0));
    else
        ret.push_back(Pair("confirmations", pcoinsTip->GetBestBlock()->nHeight - coins.nHeight + 1));
    ret.push_back(Pair("amount", (boost::int64_t)coins.vout[n].nValue));
    Object o;
    o.push_back(Pair("asm", coins.vout[n].scriptPubKey.ToString()));
    o.push_back(Pair("hex", HexStr(coins.vout[n].scriptPubKey.begin(), coins.vout[n].scriptPubKey.end())));
    ret.push_back(Pair("scriptPubKey", o));
    ret.push_back(Pair("version", coins.nVersion));
    ret.push_back(Pair("coinbase", coins.fCoinBase));

    return ret;
}


