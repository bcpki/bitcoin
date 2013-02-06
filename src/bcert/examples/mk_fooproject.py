#!/usr/bin/python

import sys
sys.path.append('..')
from bcert_pb2 import * 
import binascii

# fill out a minimal bitcoin cert
cert = BitcoinCert()

# first the data part (the part is later signed by the "higher level cert" or "the blockchain")
cert.data.version = '0.1'
cert.data.subjectname = 'Foo Project'
email = cert.data.contacts.add()
email.type = email.EMAIL
email.value = 'A@fooproject.com'
email = cert.data.contacts.add()
email.type = email.EMAIL
email.value = 'B@fooproject.com'
url = cert.data.contacts.add()
url.type = url.URL
url.value = 'http://www.fooproject.com'
paykey = cert.data.paymentkeys.add()
paykey.usage = paykey.PAYMENT
paykey.algorithm.type = paykey.algorithm.P2CMULTI # is default anyway
paykey.algorithm.version = '0.1'
paykey.value.append("2")
paykey.value.append("0285b2eb2c0f2e4a12646dbcf38d08c29ef557b5616048575b133a2084a56bb84a".decode('hex'))
paykey.value.append("03ba3137ddbee4e164390b7b67e0975d12969ef23ac1fd7b1f7e880319d072b323".decode('hex'))

# this is standard in bitcoin ripemd(sha256())
from bitcoin import hash_160

# add signature to cert
#sig = cert.signatures.add()
#sig.algorithm.type = sig.algorithm.BCPKI
#sig.algorithm.version = "0.3"
#sig.value = "foo1"  # for signatures of type BCPKI the alias IS the value, 
                   # other types place the signature of BitcoinCertDataToHash(certData) here, 
                   # for BCPKI this hash appears in the blockchain instead

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
  res = '-----BEGIN BTCPKI CERTIFICATE-----\n'
  res += 'Version: '+cert.version+'\n\n'
  res += '\n'.join(asc[i:i+72] for i in xrange(0, len(asc), 72))  
  res += '-----END BTCPKI CERTIFICATE-----\n'
  return res

# TODO: AsciiToCert

from e import derivepubkey

#print "deriving filename from: "+normalized
#fname = id+'.bcrt'
fname = 'fooproject.bcrt'
f=open(fname,'wb')
f.write(cert.SerializeToString())
f.close()
print "binary cert written to: "+fname

#fname = id+'.acrt'
#f=open(fname,'wb')
#f.write(CertToAscii(cert))
#f.close()
#print "ascii cert written to: "+fname

#fname = 'my.data'
#f=open(fname,'wb')
#f.write(cert.data.SerializeToString())
#f.close()
#print "binary data part written to: "+fname

# see the hash
print "hash of data part is: "+hash_160(cert.data.SerializeToString()).encode('hex')
print "hex binary cert: "+cert.SerializeToString().encode('hex')
#print CertToAscii(cert)
#print CertToAsciiMsg(cert)


# OLD
#from subprocess import Popen,PIPE,check_call,call
#p = Popen(['./bitcoind','-testnet','registeralias','foo3','0.5',hash],stdout=PIPE)
#result = p.stdout.read()
#print result

