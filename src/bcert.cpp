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
bool BitcoinCert::init(const string name) {
  boost::filesystem::path path = GetDataDir() / "bcerts" / (name + ".bcrt");
  boost::filesystem::ifstream file(path);
  fSigneeMatch = false;

  if ((!file.good()) || (!cert.ParseFromIstream(&file)))
    return (fSet = false);
  else
    fSet = true;

  string signee;
  GetSignee(signee);
  fSigneeMatch = (CAlias(signee).GetPubKeyIDHex() == name); 

  return true;
  //result.push_back(Pair("path",pathCert.string()));
  //result.push_back(Pair("good",file.good()));
}

BitcoinCert::BitcoinCert(CAlias alias) {
  init(alias.GetPubKeyIDHex());
  
  /*
  if (!init(alias.GetPubKeyHex()))
    if (!init(alias.GetLEHex()))
      if (!init(alias.GetNormalized()))
	init(alias.GetName());
  */
};

bool BitcoinCert::GetSignee(string &name) const {
  if (!fSet || !cert.signatures_size())
    return false;
  for (int i = 0; i < cert.signatures_size(); i++) {
    bcert::BitcoinCertSignature sig = cert.signatures(i);
    if (sig.algorithm().type() != 1) // type BTCPKI?
      continue;
    name = sig.value();
    return true;
  }
  return false;
};
  
uint160 BitcoinCert::GetHash160() const {
  string ser;
  bcert::BitcoinCertData data = cert.data();
  data.SerializeToString(&ser);
  std::vector<unsigned char> vch(ser.begin(),ser.end());
  uint160 hash160 = Hash160(vch);
  return hash160; 
};

Object BitcoinCert::ToJSON() const {
  Object result;
  result.push_back(Pair("fSet",fSet));
  result.push_back(Pair("fSigneeMatch",fSigneeMatch));
  for (int i = 0; i < cert.signatures_size(); i++) {
    bcert::BitcoinCertSignature sig = cert.signatures(i);
    result.push_back(Pair("sigtype",sig.algorithm().type()));
    result.push_back(Pair("sigversion",sig.algorithm().version()));
    result.push_back(Pair("sigvalue",sig.value()));
  }
  return result;
}
 
