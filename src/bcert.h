#ifndef BTCPKI_BCERT_H
#define BTCPKI_BCERT_H

#include <string>
#include "bcert.pb.h"
#include "alias.h"
#include "json/json_spirit_utils.h"

json_spirit::Object ReadCertFile(const std::string filename);

class BitcoinCert {
  bool fSet;
  bool fSigneeMatch;

  bool init(const std::string filename); // filename without extension
  
 public:
  bcert::BitcoinCert cert; // temporarily public
  BitcoinCert(CAlias alias); 
  bool IsSet() const { return fSet; };
  bool GetSignee(std::string &name) const;
  uint160 GetHash160() const; // hash of the data part
  json_spirit::Object ToJSON() const;
};

#endif // BTCPKI_BCERT_H
