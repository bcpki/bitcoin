#include "util.h"
#include "uint256.h"
#include "hash.h"
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include "bcert.h"

using namespace json_spirit;

/* from util.cpp
#include "sync.h"
#include "version.h"
#include "ui_interface.h"
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()

// Work around clang compilation problem in Boost 1.46:
// /usr/include/boost/program_options/detail/config_file.hpp:163:17: error: call to function 'to_internal' that is neither visible in the template definition nor found by argument-dependent lookup
// See also: http://stackoverflow.com/questions/10020179/compilation-fail-in-boost-librairies-program-options
//           http://clang.debian.net/status.php?version=3.0&key=CANNOT_FIND_FUNCTION
namespace boost {
    namespace program_options {
        std::string to_internal(const std::string&);
    }
}

#include <boost/program_options/detail/config_file.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/foreach.hpp>
#include <boost/thread.hpp>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdarg.h>

#ifdef WIN32
#ifdef _MSC_VER
#pragma warning(disable:4786)
#pragma warning(disable:4804)
#pragma warning(disable:4805)
#pragma warning(disable:4717)
#endif
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501
#ifdef _WIN32_IE
#undef _WIN32_IE
#endif
#define _WIN32_IE 0x0501
#define WIN32_LEAN_AND_MEAN 1
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <io.h> // for _commit 
#include "shlobj.h"
#elif defined(__linux__)
# include <sys/prctl.h>
#endif
*/

using namespace std;

/* deprecated
Object ReadCertFile(const string filename)
{
    boost::filesystem::path pathCerts = GetDataDir() / "bcerts";
    boost::filesystem::path pathCert = pathCerts / (filename + ".crt");

    boost::filesystem::ifstream file(pathCert);

    Object result;
    result.push_back(Pair("path",pathCert.string()));
    result.push_back(Pair("good",file.good()));

    bcert::BitcoinCert cert;
    bool fParsed = cert.ParseFromIstream(&file);
    result.push_back(Pair("fParsed",fParsed));
    if(!fParsed)
      return result;
    for (int i = 0; i < cert.signatures_size(); i++) {
      bcert::BitcoinCertSignature sig = cert.signatures(i);
      result.push_back(Pair("sigtype",sig.algorithm().type()));
      result.push_back(Pair("sigversion",sig.algorithm().version()));
      result.push_back(Pair("sigvalue",sig.value()));
    }

    return result;
}
*/

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
  bool fFound = false;
  for (int i = 0; i < cert.data().paymentkeys_size(); i++) {
    bcert::BitcoinCertData_PublicKey key = cert.data().paymentkeys(i);
    if (key.algorithm().type() == bcert::BitcoinCertData_PublicKey_Algorithm_Type_P2CSINGLE) {
      string str = key.value(0);
      vector<unsigned char> vch(str.begin(),str.end());
      pubkey = CPubKey(vch); 
      fFound = true;
    }
  }
  return fFound;
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
  sig->mutable_algorithm()->set_version(string("0.3"));
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

/* some experiments with bitcoins hashing functions
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
