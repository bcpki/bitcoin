#!/usr/bin/python

from bcert_pb2 import * 
import binascii

# fill out a minimal bitcoin cert
cert = BitcoinCert()
cert.version = "0.3"

# first the data part (the part is later signed by the "higher level cert" or "the blockchain")
cert.data.version = "0.3"
cert.data.subjectname = 'Foo Inc.'
email = cert.data.contacts.add()
email.type = email.EMAIL
email.value = "foo@fooinc.com"
url = cert.data.contacts.add()
url.type = url.URL
url.value = "http://www.fooinc.com"
paykey = cert.data.paymentkeys.add()
paykey.usage = paykey.PAYMENT
paykey.algorithm.type = paykey.algorithm.STATIC_BTCADDR # is default anyway
paykey.algorithm.version = "0.3"
key = paykey.value.append("mrMyF68x19kAc2byGKqR9MLfdAe1t5MPzh")
#key = paykey.value.append("0211b60f23135a806aff2c8f0fbbe620c16ba05a9ca4772735c08a16407f185b34".decode('hex'))

# this is standard in bitcoin ripemd(sha256())
from bitcoin import hash_160

# add signature to cert
sig = cert.signatures.add()
sig.algorithm.type = sig.algorithm.BTCPKI
sig.algorithm.version = "0.3"
sig.value = "foo2"  # for signatures of type BTCPKI the alias IS the value, 
                   # other types place the signature of BitcoinCertDataToHash(certData) here, 
                   # for BTCPKI this hash appears in the blockchain instead

# see how the cert looks
print cert

# serialize it
def CertToAscii(cert):
  ser = cert.SerializeToString()
  ver = cert.version
  crc = binascii.crc32(ser) & 0xffffff # keep only last 24 bit (should use CRC-24 like OpenPGP)
  # OpenPGP uses initializations for its crc-24, see http://tools.ietf.org/html/rfc2440
  asc = binascii.b2a_base64(cert.SerializeToString())[:-1]  # without trailing newline
  asc += '=' # checksum is seperated by =
  asc += binascii.b2a_base64(('%06x'%crc).decode('hex'))
 
  res = '-----BEGIN BTCPKI CERTIFICATE-----\n'
  res += 'Version: '+cert.version+'\n\n'
  res += '\n'.join(asc[i:i+72] for i in xrange(0, len(asc), 72))  
  res += '-----END BTCPKI CERTIFICATE-----\n'
  return res

# TODO: AsciiToCert

from e import derivepubkey

normalized = 'v0.3_F02'
id = hash_160(derivepubkey(hash_160(normalized))).encode('hex')
#fname = '$HOME/.bitcoin/testnet3/bcerts/'+id+'.bcrt'

fname = id+'.bcrt'
f=open(fname,'wb')
f.write(cert.SerializeToString())
f.close()
print "binary cert written to: "+fname

fname = id+'.acrt'
f=open(fname,'wb')
f.write(CertToAscii(cert))
f.close()
print "ascii cert written to: "+fname

fname = 'my.data'
f=open(fname,'wb')
f.write(cert.data.SerializeToString())
f.close()
print "binary data part written to: "+fname

# see the hash
print "hash of data part is: "+hash_160(cert.data.SerializeToString()).encode('hex')

# OLD
#from subprocess import Popen,PIPE,check_call,call
#p = Popen(['./bitcoind','-testnet','registeralias','foo3','0.5',hash],stdout=PIPE)
#result = p.stdout.read()
#print result

