// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txdb.h"
#include "main.h"

using namespace std;

void static BatchWriteCoins(CLevelDBBatch &batch, const uint256 &hash, const CCoins &coins) {
    if (coins.IsPruned())
        batch.Erase(make_pair('c', hash));
    else
        batch.Write(make_pair('c', hash), coins);
}

void static BatchWriteHashBestChain(CLevelDBBatch &batch, const uint256 &hash) {
    batch.Write('B', hash);
}

CCoinsViewDB::CCoinsViewDB(size_t nCacheSize, bool fMemory, bool fWipe) : db(GetDataDir() / "coins", nCacheSize, fMemory, fWipe) {
}

bool CCoinsViewDB::GetCoins(uint256 txid, CCoins &coins) { 
    return db.Read(make_pair('c', txid), coins); 
}

bool CCoinsViewDB::SetCoins(uint256 txid, const CCoins &coins) {
    CLevelDBBatch batch;
    BatchWriteCoins(batch, txid, coins);
    return db.WriteBatch(batch);
}

bool CCoinsViewDB::HaveCoins(uint256 txid) {
    return db.Exists(make_pair('c', txid)); 
}

CBlockIndex *CCoinsViewDB::GetBestBlock() {
    uint256 hashBestChain;
    if (!db.Read('B', hashBestChain))
        return NULL;
    std::map<uint256, CBlockIndex*>::iterator it = mapBlockIndex.find(hashBestChain);
    if (it == mapBlockIndex.end())
        return NULL;
    return it->second;
}

bool CCoinsViewDB::SetBestBlock(CBlockIndex *pindex) {
    CLevelDBBatch batch;
    BatchWriteHashBestChain(batch, pindex->GetBlockHash()); 
    return db.WriteBatch(batch);
}

bool CCoinsViewDB::BatchWrite(const std::map<uint256, CCoins> &mapCoins, CBlockIndex *pindex) {
    printf("Committing %u changed transactions to coin database...\n", (unsigned int)mapCoins.size());

    CLevelDBBatch batch;
    for (std::map<uint256, CCoins>::const_iterator it = mapCoins.begin(); it != mapCoins.end(); it++)
        BatchWriteCoins(batch, it->first, it->second);
    if (pindex)
        BatchWriteHashBestChain(batch, pindex->GetBlockHash());

    return db.WriteBatch(batch);
}

CBlockTreeDB::CBlockTreeDB(size_t nCacheSize, bool fMemory, bool fWipe) : CLevelDB(GetDataDir() / "blktree", nCacheSize, fMemory, fWipe) {
}

bool CBlockTreeDB::WriteBlockIndex(const CDiskBlockIndex& blockindex)
{
    return Write(make_pair('b', blockindex.GetBlockHash()), blockindex);
}

bool CBlockTreeDB::ReadBestInvalidWork(CBigNum& bnBestInvalidWork)
{
    return Read('I', bnBestInvalidWork);
}

bool CBlockTreeDB::WriteBestInvalidWork(const CBigNum& bnBestInvalidWork)
{
    return Write('I', bnBestInvalidWork);
}

bool CBlockTreeDB::WriteBlockFileInfo(int nFile, const CBlockFileInfo &info) {
    return Write(make_pair('f', nFile), info);
}

bool CBlockTreeDB::ReadBlockFileInfo(int nFile, CBlockFileInfo &info) {
    return Read(make_pair('f', nFile), info);
}

bool CBlockTreeDB::WriteLastBlockFile(int nFile) {
    return Write('l', nFile);
}

bool CBlockTreeDB::WriteReindexing(bool fReindexing) {
    if (fReindexing)
        return Write('R', '1');
    else
        return Erase('R');
}

bool CBlockTreeDB::ReadReindexing(bool &fReindexing) {
    fReindexing = Exists('R');
    return true;
}

bool CBlockTreeDB::ReadLastBlockFile(int &nFile) {
    return Read('l', nFile);
}

bool CCoinsViewDB::GetFirstMatch(boost::function<bool (const CCoins)> f, uint256& txRet) { 
    leveldb::Iterator *pcursor = db.NewIterator();
    pcursor->SeekToFirst();

    int height = -1;
    while (pcursor->Valid()) {
        try {
            leveldb::Slice slKey = pcursor->key();
            CDataStream ssKey(slKey.data(), slKey.data()+slKey.size(), SER_DISK, CLIENT_VERSION);
            char chType;
	    
            ssKey >> chType;
            if (chType == 'c' && !fRequestShutdown) {
                leveldb::Slice slValue = pcursor->value();
                CDataStream ssValue(slValue.data(), slValue.data()+slValue.size(), SER_DISK, CLIENT_VERSION);
                CCoins coins;
                ssValue >> coins;
                uint256 txhash;
                ssKey >> txhash;

		if ((height > 0) && (coins.nHeight > height))
		  {
		    pcursor->Next();
		    continue; // while (pursor->Valid())
		  }

		if (f(coins))
		  {
		    txRet = txhash;
		    height = coins.nHeight;
		  }
            }
            pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
    delete pcursor;
    return (height > 0);
}

bool CCoinsViewDB::GetStats(CCoinsStats &stats) {
    leveldb::Iterator *pcursor = db.NewIterator();
    pcursor->SeekToFirst();

    while (pcursor->Valid()) {
        try {
            leveldb::Slice slKey = pcursor->key();
            CDataStream ssKey(slKey.data(), slKey.data()+slKey.size(), SER_DISK, CLIENT_VERSION);
            char chType;
            ssKey >> chType;
            if (chType == 'c' && !fRequestShutdown) {
                leveldb::Slice slValue = pcursor->value();
                CDataStream ssValue(slValue.data(), slValue.data()+slValue.size(), SER_DISK, CLIENT_VERSION);
                CCoins coins;
                ssValue >> coins;
                uint256 txhash;
                ssKey >> txhash;

                stats.nTransactions++;
                BOOST_FOREACH(const CTxOut &out, coins.vout) {
                    if (!out.IsNull())
                        stats.nTransactionOutputs++;
                }
                stats.nSerializedSize += 32 + slValue.size();
            }
            pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
    delete pcursor;
    stats.nHeight = GetBestBlock()->nHeight;
    return true;
}

bool CCoinsViewDB::GetFirstMultisigWithPubKey(const CPubKey& searchKey, uint256& txRet, CCoins& coinsRet, vector<unsigned int>& outRet) {
    leveldb::Iterator *pcursor = db.NewIterator();
    pcursor->SeekToFirst();

    int height = -1;
    while (pcursor->Valid()) {
        try {
            leveldb::Slice slKey = pcursor->key();
            CDataStream ssKey(slKey.data(), slKey.data()+slKey.size(), SER_DISK, CLIENT_VERSION);
            char chType;
	    
            ssKey >> chType;
            if (chType == 'c' && !fRequestShutdown) {
                leveldb::Slice slValue = pcursor->value();
                CDataStream ssValue(slValue.data(), slValue.data()+slValue.size(), SER_DISK, CLIENT_VERSION);
                CCoins coins;
                ssValue >> coins;
                uint256 txhash;
                ssKey >> txhash;
 
		if ((height > 0) && (coins.nHeight > height))
		  {
		    pcursor->Next();
		    continue; // while (pursor->Valid())
		  }

                vector<unsigned int> outs;
		for (unsigned int i=0; i<coins.vout.size(); i++) {
		  if (IsMultisigWithPubKey(coins.vout[i].scriptPubKey,searchKey))
		    {
		      outs.push_back(i);
		    }
		}

		if (outs.size() > 0) {
		      coinsRet = coins; 
		      txRet = txhash;
		      outRet = outs;
		      height = coins.nHeight;
		}
            }
            pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
    delete pcursor;
    return (height > 0);
}

bool CBlockTreeDB::LoadBlockIndexGuts()
{
    leveldb::Iterator *pcursor = NewIterator();

    CDataStream ssKeySet(SER_DISK, CLIENT_VERSION);
    ssKeySet << make_pair('b', uint256(0));
    pcursor->Seek(ssKeySet.str());

    // Load mapBlockIndex
    while (pcursor->Valid()) {
        try {
            leveldb::Slice slKey = pcursor->key();
            CDataStream ssKey(slKey.data(), slKey.data()+slKey.size(), SER_DISK, CLIENT_VERSION);
            char chType;
            ssKey >> chType;
            if (chType == 'b' && !fRequestShutdown) {
                leveldb::Slice slValue = pcursor->value();
                CDataStream ssValue(slValue.data(), slValue.data()+slValue.size(), SER_DISK, CLIENT_VERSION);
                CDiskBlockIndex diskindex;
                ssValue >> diskindex;

                // Construct block index object
                CBlockIndex* pindexNew = InsertBlockIndex(diskindex.GetBlockHash());
                pindexNew->pprev          = InsertBlockIndex(diskindex.hashPrev);
                pindexNew->nHeight        = diskindex.nHeight;
                pindexNew->nFile          = diskindex.nFile;
                pindexNew->nDataPos       = diskindex.nDataPos;
                pindexNew->nUndoPos       = diskindex.nUndoPos;
                pindexNew->nVersion       = diskindex.nVersion;
                pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
                pindexNew->nTime          = diskindex.nTime;
                pindexNew->nBits          = diskindex.nBits;
                pindexNew->nNonce         = diskindex.nNonce;
                pindexNew->nStatus        = diskindex.nStatus;
                pindexNew->nTx            = diskindex.nTx;

                // Watch for genesis block
                if (pindexGenesisBlock == NULL && diskindex.GetBlockHash() == hashGenesisBlock)
                    pindexGenesisBlock = pindexNew;

                if (!pindexNew->CheckIndex())
                    return error("LoadBlockIndex() : CheckIndex failed: %s", pindexNew->ToString().c_str());

                pcursor->Next();
            } else {
                break; // if shutdown requested or finished loading block index
            }
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
    delete pcursor;

    return true;
}
