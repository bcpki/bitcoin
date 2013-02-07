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

from e import *
from bcert_pb2 import * 
from bitcoin import hash_160
import binascii

versno="0.4"

# ----- aliases -----

import re
def isvalidalias(alias):
  if not re.match("^[A-Za-z][A-Za-z0-9_-]*",alias):
    return false
  return re.match("^[A-Za-z0-9_-]*[A-Za-z0-9]",alias)

def normst(instring):
   instring=instring.upper().replace("-","").replace("_","").replace("O","0").replace("I","1").replace("L","1")
   instring=re.sub(r'([A-Z0-9])\1+', r'\1',instring)
   return instring

def norm(alias,versionin = versno):
   return "BCSIG_v"+str(versionin)+"_"+normst(alias)

def aliastofilename(alias,versionin = versno): # legacy version
   return hash2idx(hash_160(norm(alias,versionin)))

def alias2idx(alias,versionin = versno):
   return hash2idx(hash_160(norm(alias,versionin)))

def alias2pubkey(alias,versionin = versno):
   return hash2pubkey(hash_160(norm(alias,versionin)))

def alias2pubkeyx(alias,versionin = versno):
   return hash2pubkeyx(hash_160(norm(alias,versionin)))

def alias2addr(alias,versionin = versno):
   return bitcoin.public_key_to_bc_address(alias2pubkey(alias,versionin))

# ----- yaml -----
      
def getyaml(yamlin):
    import yaml
    yml=yaml.load(yamlin)
    ver=yml['data']['version']
    subject=yml['data']['subjectname']
    contacts=[]
    for i in yml['data']['contacts']:
        contacts+=[[i['type'],i['value']]]
    ty=yml['data']['paymentkeys'][0]['algorithm']['type']
    pubkeys=[]
    for i in yml['data']['paymentkeys']:
        pubkeys+=i['value']
    try:
        alias=yml['signature']['value']
    except:
        alias=""
    return ver,subject,contacts,ty,pubkeys,alias

# ----- to ascii -----

def getascii(asc):
   import re
   stripped1=asc.split("\r\n\r\n")[1].split("=")[0][:-1]
   stripped2=re.sub(r'\r\n','\n',stripped1)[:-1]
   bina=binascii.a2b_base64(stripped2)
   return bina

def _cert2ascii(cert):
  ser = cert.SerializeToString()
  asc = binascii.b2a_base64(ser)[:-1]  # without trailing newline
  crc = binascii.crc32(ser) & 0xffffff # keep only last 24 bit (should use CRC-24 like OpenPGP)
  # OpenPGP uses initializations for its crc-24, see http://tools.ietf.org/html/rfc2440
  return asc,binascii.b2a_base64(('%06x'%crc).decode('hex'))
 
def cert2asciiarmored(cert):
  ver = cert.version
  asc,crc = _cert2ascii(cert)
  res = '-----BEGIN BCPKI CERTIFICATE-----\n'
  res += 'Version: '+cert.version+'\n\n'
  res += '\n'.join(asc[i:i+72] for i in xrange(0, len(asc), 72))  
  res += '\n='+crc
  res += '-----END BCPKI CERTIFICATE-----\n'
  return res

def cert2asciimsg(cert):
  ver = cert.version
  asc,crc = _cert2ascii(cert)
  return asc+'='+crc

# ----- makecert -----

def makecert(versionin,subjectinp,contacts,ty,pubkeys,aliasin):
   # fill out a minimal bitcoin cert
   cert = BitcoinCert()
   cert.version = str(versionin)
   
   # first the data part (the part is later signed by the "higher level cert")
   cert.data.version = str(versionin)
   cert.data.subjectname = subjectinp
   for i in contacts:
      d=cert.data.contacts.add()
      d.type=eval("d."+i[0])
      d.value=i[1]
   paykey = cert.data.paymentkeys.add()
   paykey.usage = paykey.PAYMENT
   paykey.algorithm.type = eval("paykey.algorithm."+ty)
   paykey.algorithm.version = str(versionin)
   for i in pubkeys:
      if type(i) is int:
         paykey.value.append(str(i))
      else:
         paykey.value.append(i.decode('hex'))
   
   # add signature to cert
   if aliasin is not "":
      sig = cert.signatures.add()
      sig.algorithm.type = sig.algorithm.BCPKI
      sig.algorithm.version = str(versionin)
      sig.value = aliasin # for signatures of type BTCPKI the alias IS the value, 
                       # other types place the signature of BitcoinCertDataToHash(certData) here, 
                       # for BTCPKI this hash appears in the blockchain instead
   
   return cert

# ----- data part hash ----

def cert2hash(cert):
  return hash_160(cert.data.SerializeToString())
   
def cert2hashx(cert):
  return tohex(hash_160(cert.data.SerializeToString()))

# ----- yaml2bcrt ----

def yaml2cert(yamlin):
  (versionin,subject,contacts,ty,pubkeys,alias) = getyaml(yamlin)
  return makecert(versionin,subject,contacts,ty,pubkeys,alias)

def yaml2bcrt(yamlin):
  return yaml2cert(yamlin).SerializeToString()

def yaml2bcrtx(yamlin):
  return tohex(yaml2cert(yamlin).SerializeToString())

# ----- bcrt -----

def bcrt2cert(bcrt):
  cert = BitcoinCert()
  cert.ParseFromString(toraw(bcrt))
  return cert

def bcrt2asciiarmored(bcrt):
  return cert2asciiarmored(bcrt2cert(bcrt)) 

def bcrt2hash(bcrt):
  return cert2hash(bcrt2cert(bcrt)) 
  
def bcrt2hashx(bcrt):
  return tohex(cert2hash(bcrt2cert(bcrt)))
