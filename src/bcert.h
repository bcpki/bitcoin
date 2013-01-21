#ifndef BTCPKI_BCERT_H
#define BTCPKI_BCERT_H

#include <string>
#include "bcert.pb.h"
#include "alias.h"
#include "json/json_spirit_utils.h"

json_spirit::Object ReadCertFile(const std::string filename);

class BitcoinCert {
  bcert::BitcoinCert cert;
  bool fSet;

  bool init(const std::string filename); //filename without extension
  
 public:
  BitcoinCert(CAlias alias); 
  bool IsSet() const { return fSet; };
  bool GetName(std::string &name) const;
  uint256 GetHash() const; // hash of the data
  json_spirit::Object ToJSON() const;
};

#endif // BTCPKI_BCERT_H
