#!/usr/bin/env python
#
# BCPKI - BlockchainPKI
# Copyright (C) 2013 timo.hanke@web.de, ilja@quantumlah
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#!/usr/bin/python

import sys
from bcert_pb2 import * 
import binascii
from bitcoin import hash_160 # this is ripemd(sha256())

import e 

alias=sys.argv[1]
## normalization here
normalized = 'F0PR0JECT'
prefixed = 'BCSIG_v0.4_'+normalized
print hash_160(prefixed).encode('hex')
id = e.point2idx(e.derivepoint(e.zero,hash_160(prefixed)))
fname = '/users/hanke/.bitcoin/testnet3/bcerts/'+id+'.bcrt'

print "reading: "+fname

cert = BitcoinCert()
f=open(fname)
cert.ParseFromString(f.read())
f.close()

# see how the cert looks
# TODO encode('hex') pubkeys of P2CSINGLE/MULTI 
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

# see the hash
print "hash of data part is: "+hash_160(cert.data.SerializeToString()).encode('hex')

# output hex binary
print "hex binary cert: "
print cert.SerializeToString().encode('hex')
