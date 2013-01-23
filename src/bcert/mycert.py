#!/usr/bin/python

from bcert_pb2 import * 
import binascii

# fill out a minimal bitcoin cert
cert = BitcoinCert()
cert.version = "0.2"

# first the data part (the part is later signed by the "higher level cert")
cert.data.version = "0.2"
cert.data.subjectname = 'Foo Inc.'
email = cert.data.contacts.add()
email.type = email.EMAIL
email.value = "foo@fooinc.com"
paykey = cert.data.paymentkeys.add()
paykey.usage = paykey.PAYMENT
paykey.algorithm.type = paykey.algorithm.BTCPKISINGLE # is default anyway
paykey.algorithm.version = "0.2"
key = paykey.value.append("0211b60f23135a806aff2c8f0fbbe620c16ba05a9ca4772735c08a16407f185b34".decode('hex'))
key = paykey.value.append("0211b60f23135a806aff2c8f0fbbe620c16ba05a9ca4772735c08a16407f185b34".decode('hex'))
print dir(paykey.value)

# see how the cert.data looks
print "data part of cert"
print cert.data

# compute hash of data (the signature signs this hash)
import hashlib 
def DataToHash(data):
  return hashlib.sha256(data.SerializeToString()).digest()

# see the hash
print "hash of data part of cert"
print DataToHash(cert.data).encode('hex')

# add signature to cert
sig = cert.signatures.add()
sig.algorithm.type = sig.algorithm.BTCPKI
sig.algorithm.version = "0.2"
sig.value = "foo3"  # for signatures of type BTCPKI the alias IS the value, 
                   # other types place the signature of BitcoinCertDataToHash(certData) here, 
                   # for BTCPKI this hash appears in the blockchain instead

# see how the cert looks
print "whole cert"
print cert

# serialize it
def CertToAscii(cert):
  ser = cert.SerializeToString()
  ver = cert.version
  crc = binascii.crc32(ser) & 0xffffff # keep only last 24 bit (should use CRC-24 like OpenPGP)
  # OpenPGP uses initializations for its crc-24, see http://tools.ietf.org/html/rfc2440
  asc = binascii.b2a_base64(cert.SerializeToString())[:-1]  # without trailing newline
  asc += '=' # checksum is seperated by =
  asc += binascii.b2a_base64(('%x'%crc).decode('hex'))
 
  res = '-----BEGIN BTCPKI CERTIFICATE-----\n'
  res += 'Version: '+cert.version+'\n\n'
  res += '\n'.join(asc[i:i+72] for i in xrange(0, len(asc), 72))  
  res += '-----END BTCPKI CERTIFICATE-----\n'
  return res

print "serialized and ascii armored"
print CertToAscii(cert)

# TODO: AsciiToCert

fname = sig.value+'.crt'
f=open(fname,'wb')
f.write(cert.SerializeToString())
f.close()
print "serialized binary form written to "+fname

# OLD
#from subprocess import Popen,PIPE,check_call,call
#p = Popen(['./bitcoind','-testnet','registeralias','foo3','0.5',hash],stdout=PIPE)
#result = p.stdout.read()
#print result

