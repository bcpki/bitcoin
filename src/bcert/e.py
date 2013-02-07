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

from ecdsa import ellipticcurve
from ecdsa import numbertheory
from ecdsa import ecdsa
from ecdsa import util
import bitcoin # from electrum code, contains base58 encode and others
from hashlib import sha256 # will probably need this too
from bitcoin import hash_160
from mycert2 import *
import binascii

versno="0.4"
basedir="/web/btcrypt.org/public_html/certs/"

# ----- testnet / mainnet -----

def testnet():
  bitcoin.addrtype = 0x6f 
  
def mainnet():
  bitcoin.addrtype = 0x00 

testnet() # default

# ----- curve definition secp256k1 -----

_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_b = 0x0000000000000000000000000000000000000000000000000000000000000007L
_a = 0x0000000000000000000000000000000000000000000000000000000000000000L
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L
C = ellipticcurve.CurveFp( _p, _a, _b ) 
G = ellipticcurve.Point( C, _Gx, _Gy, _r )
Z = 0*G

# ----- conversion functions -----

# notion
## point = EC point object
## pubkey = compressed pubkey (32+1 bytes) as binary string
## pubkeyx = pubkey in hex format
## id = hash160(pubkey) as binary string
## idx = id in hex format
## addr = base check encoding of id

# ishex, tohex, toraw
def ishex(s):
  for c in s:
    if not c in string.hexdigits: return False
  return True
def tohex(s):
  if ishex(s):
    return s
  else:
    return s.encode('hex')
def toraw(s):
  if ishex(s):
    return s.decode('hex')
  else:
    return s
  
#ECP = ecdsa.Public_key(G,P)
#ECQ = ecdsa.Public_key(G,Q)

# convert point 
def point2pubkey(p):
  x_str = util.number_to_string(p.x(), G.order())
  y_str = util.number_to_string(p.y(), G.order())
  return (chr(2 + (p.y() & 1)) + x_str)
def point2pubkeyx(p):
  return tohex(point2pubkey(p))
def point2id(p):
  return hash_160(point2pubkey(p))
def point2idx(p):
  return tohex(hash_160(point2pubkey(p)))
def point2addr(p):
  return bitcoin.public_key_to_bc_address(point2pubkey(p))

# convert pubkey
def pubkey2point(pubkey):
  x = int(tohex(pubkey)[2:],16)
  fx = (x * x * x + C.a() * x + C.b()) % C.p()
  y = numbertheory.square_root_mod_prime(fx,C.p())
  P = ellipticcurve.Point(C,x,y)
  if point2pubkey(P) != toraw(pubkey):
      P = ellipticcurve.Point(C,x,C.p()-y)
  return P
def pubkey2addr(pubkey): 
  return bitcoin.public_key_to_bc_address(toraw(pubkey))
def pubkey2id(pubkey): 
  return hash_160(toraw(pubkey))
def pubkey2idx(pubkey): 
  return tohex(pubkey2id(pubkey))

# convert id
def id2addr(id): 
  return bitcoin.hash_160_to_bc_address(toraw(id))

# convert address
def addr2id(addr):
  return bitcoin.bc_address_to_hash_160(addr)
def addr2idx(addr):
  return tohex(bitcoin.bc_address_to_hash_160(addr))

# little-endian binary value (e.g. hash)
def val2int(val):
  return int(tohex(toraw(val)[::-1]),16)

# derived pubkey  
def derivepoint(P,hash):
   return val2int(hash)*G+P
def derivepubkey(pubkey,hash):
   return point2pubkey(derivepoint(pubkey2point(pubkey),hash))
def derivepubkeyx(pubkey,hash):
   return tohex(point2pubkey(derivepoint(pubkey2point(pubkey),hash)))

# secret
def sec2point(sec):
  return int(tohex(sec),16)*G;
def sec2pubkey(sec):
  return point2pubkey(sec2point(sec));
def sec2pubkeyx(sec):
  return point2pubkeyx(sec2point(sec));
def sec2id(sec):
  return point2id(sec2point(sec));
def sec2idx(sec):
  return point2idx(sec2point(sec));
def sec2addr(sec):
  return point2addr(sec2point(sec));

# hash
def hash2pubkey(hexstr):
  return point2pubkey(derivepoint(Z,hexstr))

def hash2pubkeyx(hexstr):
  return point2pubkeyx(derivepoint(Z,hexstr))

def hash2id(hexstr):
  return point2id(derivepoint(Z,hexstr))

def hash2idx(hexstr):
  return point2idx(derivepoint(Z,hexstr))

def hash2addr(hexstr):
  return point2addr(derivepoint(Z,hexstr))

# ----- aliases -----

import re
def isvalidalias(alias):
  if not re.match("^[A-Za-z][A-Za-z0-9_-]*",alias):
    return false
  return re.match("^[A-Za-z0-9_-]*[A-Za-z0-9]",alias):

def normst(instring):
   instring=instring.upper().replace("-","").replace("_","").replace("O","0").replace("I","1").replace("L","1")
   instring=re.sub(r'([A-Z0-9])\1+', r'\1',instring)
   return instring

def aliastofilename(alias,versionin):
   normalias="BCSIG_v"+str(versionin)+"_"+normst(alias)
   return hash2idx(hash_160(normalias))

# ----- print -----

def printfile(filename):
   ff=open(filename,'r')
   for line in ff:
      print line.rstrip()
   ff.close();

def printcert(cert,outtype):
   try: 
      alias=cert.signatures[0].value
      versno=cert.signatures[0].algorithm.version
   except:
      alias=""
   if alias is not "":
      certfilename=aliastofilename(alias,versno)
   else: 
      certfilename="tmpfile" 
   afile="/web/btcrypt.org/public_html/certs/"+certfilename+".acrt"
   bfile="/web/btcrypt.org/public_html/certs/"+certfilename+".bcrt"
   f=open(bfile,'wb')
   f.write(cert.SerializeToString())
   f.close()
   asciicert=CertToAscii(cert)
   f=open(afile,'wb')
   f.write(asciicert)
   f.close()
   if outtype is "bincert":
      filename=certfilename
      # print "Content-type:application/octet-stream"
      print "Content-Disposition: attachment; filename="+filename+".bcrt"
      print "Content-type:text/plain\r\n\r"
      out=cert.SerializeToString()
      # print cert.SerializeToString()
      import sys
      sys.stdout.write(out.rstrip("\n"))
   elif outtype is "asciicert":
      print "Content-type:text/plain\r\n\r"
      print asciicert.rstrip('\n')
   else:
      print "Content-type:text/html\r\n\r\n"
      header="../public_html/header.php"
      footer="../public_html/footer.php"
      baseurl="http://btcrypt.org/"
      printfile(header)
      if alias is not "":
         normalias="BCSIG_v"+str(versno)+"_"+normst(alias)
         hashvalue=hash_160(normalias).encode('hex')
         pubkeyval=hash2pubkey(hashvalue)
         h160pubkey=hash_160(pubkeyval.decode('hex')).encode('hex')
         print "normalized alias: "+normalias+"<p>"
         print "hashed, normalize ALIAS: "+str(hashvalue)+"<p>"
         print "hashed, normalize alias, multiplied with basepoint: "+str(pubkeyval)
         print "Filename, which will be generated: "+str(h160pubkey)
      print "<p>Binary Encoded saved as: <A HREF=\""+baseurl+"certs/"+certfilename+".bcrt\">/certs/"+certfilename+".bcrt</A></p>"
      print "Simply check here: <A HREF=\""+baseurl+"cgi-bin/decode.cgi?fname="+certfilename+".bcrt\">/certs/"+certfilename+".bcrt</A></p>"
      print "<PRE>"
      print asciicert.rstrip('\n')
      print "</PRE>"
      print "<p>ASCII Encoded saved as: <A HREF=\""+baseurl+"certs/"+certfilename+".acrt\">/certs/"+certfilename+".acrt</A></p>"
      print "Check in the certificate here:"
      print "<p><form action=\""+baseurl+"cgi-bin/upload.cgi\" method=\"get\"><input type=\"hidden\" name=\"cert\" value=\""+certfilename+"\">"
      print "<p><button type=\"submit\" class=\"btn\">Upload certificate</button></p></form>"
      print "<H2>End of output</H2>"
      printfile(footer)

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

# ----- html -----

def gethtml(inlist):
   import cgi, cgitb 
   import re
   form = cgi.FieldStorage()
   for i in inlist:
      try: 
         value=re.sub(r'[^a-zA-Z0-9_\n\r :\-@/,\.\"\{\}\[\]=]\+', '',form.getvalue(i))
      except:
         value=""
      globals()[i] = value

# ----- ascii -----

def getascii(asc):
   import re
   stripped1=asc.split("\r\n\r\n")[1].split("=")[0][:-1]
   stripped2=re.sub(r'\r\n','\n',stripped1)[:-1]
   bina=binascii.a2b_base64(stripped2)
   return bina

# def gethtml(inlist):
#    import cgi, cgitb 
#    import re
#    form = cgi.FieldStorage()
#    for i in inlist:
#       value=re.sub(r'\W+', '',form.getvalue(i))
#       globals()[i] = value

