// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.h"
#include "uint256.h"
#include "hash.h"
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include "bcert.h"

using namespace json_spirit;
using namespace std;

// parse file name.bcrt
bool CBitcoinCert::ReadFile(const string name) {
  fSet = false;

  boost::filesystem::path path = GetDataDir() / "bcerts" / (name + ".bcrt");
  boost::filesystem::ifstream file(path);

  if (!file.good())
    return false;
  //    throw runtime_error("CBitcoinCert::readfromfile: file not found: " + name + ".bcrt");

  if (!cert.ParseFromIstream(&file))
    return false;
  //    throw runtime_error("CBitcoinCert::readfromfile: could not parse: " + name + ".bcrt");

  init(); // parse signees, fSet, etc
  return true;
}

bool CBitcoinCert::ReadAliasFile(CAlias alias) {
  return ReadFile(alias.GetPubKeyIDHex()) && HasSignee(alias);
}

CBitcoinCert::CBitcoinCert(CAlias alias) {
  if (!ReadFile(alias.GetPubKeyIDHex()))
    if (!ReadFile(alias.GetPubKeyHex()))
      if (!ReadFile(alias.GetLEHex()))
	if (!ReadFile(alias.GetNormalized()))
	  if (!ReadFile(alias.GetName()))
	    throw runtime_error("CBitcoinCert(CAlias alias): file not found or could not be parsed");
  //if (!HasSignee(alias))
  //  throw runtime_error("CBitcoinCert(CAlias alias): no matching BCPKI signature");
}

CBitcoinCert::CBitcoinCert(const string& hexStr) {
  if (!IsHex(hexStr)) 
    throw runtime_error("CBitcoinCert(string hexStr): argument is not a hex string.");
  vector<unsigned char> vch = ParseHex(hexStr);
  string ser(vch.begin(),vch.end());
  if (!cert.ParseFromString(ser))
    throw runtime_error("CBitcoinCert(string hexStr): hexStr could not be parsed.");
}

void CBitcoinCert::init() {
  // parse signees
  for (int i = 0; i < cert.signatures_size(); i++) {
    bcert::BitcoinCertSignature sig = cert.signatures(i);
    if (sig.algorithm().type() == 1)
      signees.push_back(CAlias(sig.value()));
  }
  fSet = true;
}

bool CBitcoinCert::HasSignee() const {
  return (fSet && (signees.size() > 0));
}

bool CBitcoinCert::HasSignee(const CAlias alias) const {
  if (!fSet)
    return false;
  BOOST_FOREACH(const CAlias signee, signees) {
    if (alias == signee)
      return true; // empty name means accept
  }
  return false;
}

bool CBitcoinCert::GetStatic(CBitcoinAddress& addr) const {
  bool fFound = false;
  for (int i = 0; i < cert.data().paymentkeys_size(); i++) {
    bcert::BitcoinCertData_PublicKey key = cert.data().paymentkeys(i);
    if (key.algorithm().type() == bcert::BitcoinCertData_PublicKey_Algorithm_Type_STATIC_BTCADDR) {
      addr.SetString(key.value(0));
      fFound = true;
    }
  }
  return fFound;
}

bool CBitcoinCert::GetP2CSingle(CPubKey& pubkey) const {
  for (int i = 0; i < cert.data().paymentkeys_size(); i++) {
    bcert::BitcoinCertData_PublicKey key = cert.data().paymentkeys(i);
    if (key.algorithm().type() == bcert::BitcoinCertData_PublicKey_Algorithm_Type_P2CSINGLE) {
      string str = key.value(0);
      vector<unsigned char> vch(str.begin(),str.end());
      pubkey = CPubKey(vch); 
      return true;
    }
  }
  return false;
}

bool CBitcoinCert::GetP2CMulti(unsigned int& nReq, vector<CPubKey>& pubkey) const {
  for (int i = 0; i < cert.data().paymentkeys_size(); i++) {
    bcert::BitcoinCertData_PublicKey key = cert.data().paymentkeys(i);
    if (key.algorithm().type() == bcert::BitcoinCertData_PublicKey_Algorithm_Type_P2CMULTI) {
      stringstream convert(key.value(0));
      if (!(convert >> nReq))
	continue;
      for(int i=1; i<key.value_size(); i++) {
	string str = key.value(i);
	vector<unsigned char> vch(str.begin(),str.end());
	pubkey.push_back(CPubKey(vch)); 
      }
      return true;
    }
  }
  return false;
}

uint160 CBitcoinCert::GetHash160() const {
  string ser;
  bcert::BitcoinCertData data = cert.data();
  data.SerializeToString(&ser);
  std::vector<unsigned char> vch(ser.begin(),ser.end());
  uint160 hash160 = Hash160(vch);
  return hash160; 
}

Object CBitcoinCert::ToJSON() const {
  Object result;
  result.push_back(Pair("fSet",fSet));
  for (int i = 0; i < cert.signatures_size(); i++) {
    bcert::BitcoinCertSignature sig = cert.signatures(i);
    result.push_back(Pair("sigtype",sig.algorithm().type()));
    result.push_back(Pair("sigversion",sig.algorithm().version()));
    result.push_back(Pair("sigvalue",sig.value()));
  }
  return result;
}
 
bool CBitcoinCert::Verify(vector<pair<CAlias,unsigned int> >& result) const {
  result.clear();
  if (!fSet || !HasSignee())
    return false;
  CBcValue val = CBcValue(GetHash160());
  BOOST_FOREACH(const CAlias signee, signees) {
    uint256 txid;
    if (signee.VerifySignature(val,txid)) {
      CCoins coins;
      if (!pcoinsTip->GetCoins(txid, coins))
	throw runtime_error("CAlias::VerifySignature: GetCoins failed.");
      // TODO make a function coins->confirmations, reuse
      unsigned int nConfirmations;
      if ((unsigned int)coins.nHeight == MEMPOOL_HEIGHT)
	nConfirmations = 0;
      else
	nConfirmations = pcoinsTip->GetBestBlock()->nHeight - coins.nHeight + 1;
      result.push_back(make_pair(signee,nConfirmations)); //Pair<Calias,unsigned int> m
    }
  }
  return (result.size() > 0);
}

void CBitcoinCert::AddSignature(const CAlias alias) {
  bcert::BitcoinCertSignature* sig = cert.add_signatures();
  sig->set_value(alias.GetName());
  sig->mutable_algorithm()->set_type(bcert::BitcoinCertSignature_SignatureAlgorithm_SignatureAlgorithmType_BCPKI);
  sig->mutable_algorithm()->set_version(string(BCPKI_SIGVERSION));
  signees.push_back(alias);
}

bool CBitcoinCert::SaveFile(const string name) const {
  boost::filesystem::path path = GetDataDir() / "bcerts" / (name + ".bcrt");
  boost::filesystem::ofstream file(path);

  if (!file.good())
    //    return false;
      throw runtime_error("CBitcoinCert::SaveFile: file error: " + name + ".bcrt");

  if (!cert.SerializeToOstream(&file))
    //    return false;
      throw runtime_error("CBitcoinCert::SaveFile: could not serialize: " + name + ".bcrt");

  return true;
}

bool CBitcoinCert::SaveFile(CAlias alias) const {
  return SaveFile(alias.GetPubKeyIDHex());
}

bool CBitcoinCert::SaveAll() const {
  bool success = true;
  BOOST_FOREACH(const CAlias alias, signees)
    success = SaveFile(alias) && success;
    
  return success;
}
