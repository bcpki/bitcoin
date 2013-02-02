#!/usr/bin/python
# currently it just produces one single example and outputs: hex binary cert, ascii armored cert, two files mycert.bcrt and mycert.acrt
# TODO parse .yml
# TODO make it a command line tool, define and parse arguments

from bcert_pb2 import * 
import binascii
from bitcoin import hash_160 # this is ripemd(sha256())

# fill out a minimal bitcoin cert
cert = BitcoinCert()

# first the data part (the part is later signed by the "higher level cert" or "the blockchain")
cert.data.version = '0.1'
cert.data.subjectname = 'Foo Inc.'
email = cert.data.contacts.add()
email.type = email.EMAIL
email.value = 'foo@fooinc.com'
url = cert.data.contacts.add()
url.type = url.URL
url.value = 'http://www.fooinc.com'
paykey = cert.data.paymentkeys.add()
paykey.usage = paykey.PAYMENT
paykey.algorithm.type = paykey.algorithm.STATIC_BTCADDR 
key = paykey.value.append("mrMyF68x19kAc2byGKqR9MLfdAe1t5MPzh")
#paykey.algorithm.type = paykey.algorithm.P2CSINGLE
#key = paykey.value.append("0211b60f23135a806aff2c8f0fbbe620c16ba05a9ca4772735c08a16407f185b34".decode('hex'))

# see how the cert looks
print cert

# serialize it
def CertToAscii(cert):
  ser = cert.SerializeToString()
  crc = binascii.crc32(ser) & 0xffffff # keep only last 24 bit (should use CRC-24 like OpenPGP)
  # OpenPGP uses initializations for its crc-24, see http://tools.ietf.org/html/rfc2440
  asc = binascii.b2a_base64(cert.SerializeToString())[:-1]  # without trailing newline
  asc += '=' # checksum is seperated by =
  asc += binascii.b2a_base64(('%06x'%crc).decode('hex'))
  return asc
 
def CertToAsciiMsg(cert):
  ver = cert.version
  asc = CertToAscii(cert)
  res = '-----BEGIN BCPKI CERTIFICATE-----\n'
  res += 'Version: '+cert.version+'\n\n'
  res += '\n'.join(asc[i:i+72] for i in xrange(0, len(asc), 72))  
  res += '-----END BCPKI CERTIFICATE-----\n'
  return res

# output ascii
print CertToAsciiMsg(cert)

# output binary file
fname='mycert.bcrt'
f=open(fname,'wb')
f.write(cert.SerializeToString())
f.close()
print "binary cert written to: "+fname

# output ascii file
fname='mycert.acrt'
f=open(fname,'wb')
f.write(CertToAsciiMsg(cert))
f.close()
print "ascii cert written to: "+fname

# see the hash
print "hash of data part is: "+hash_160(cert.data.SerializeToString()).encode('hex')

# output hex binary
print "hex binary cert: "
print cert.SerializeToString().encode('hex')
