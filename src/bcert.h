// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BCPKI_BCERT_H
#define BCPKI_BCERT_H

#include <string>
#include "bcert.pb.h"
#include "alias.h"
#include "json/json_spirit_utils.h"

#define BCPKI

json_spirit::Object ReadCertFile(const std::string filename);

class CBitcoinCert {
  bool fSet;
  std::vector<CAlias> signees;
  bcert::BitcoinCert cert; // temporarily public

  void init(); // 2nd step initialization (parse signees, etc)
  
 public:
  CBitcoinCert(CAlias alias); // parse from filename derived from alias, should be const CAlias
  CBitcoinCert(const std::string& hexStr); // parse from given hex string
  CBitcoinCert() { fSet = false; };
  bool ReadFile(const std::string filename); // filename without extension
  bool ReadAliasFile(CAlias alias); // parse from filename derived from alias, should be const CAlias
  void AddSignature(const CAlias alias); // adds a signature field of type BCPKI to the cert

  bool SaveFile(const std::string filename) const; 
  bool SaveFile(const CAlias alias) const; // filename derived from alias
  bool SaveAll() const; // filenames derived from all BCPKI signatures
  bool IsSet() const { return fSet; };
  bool HasSignee() const;
  bool HasSignee(const CAlias alias) const;
  bool GetStatic(CBitcoinAddress& addr) const;
  bool GetP2CSingle(CPubKey& pubkey) const;
  bool GetP2CMulti(unsigned int& nReq, std::vector<CPubKey>& pubkey) const;
  uint160 GetHash160() const; // hash of the data part
  std::string GetHash160Hex() const { uint160 hash = GetHash160(); return HexStr(hash.begin(),hash.end()); } 
  bool Verify(std::vector<std::pair<CAlias,unsigned int> >& result) const;
  json_spirit::Object ToJSON() const;
};

#endif // BCPKI_BCERT_H
