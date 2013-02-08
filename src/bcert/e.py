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

from ecdsa import ellipticcurve, numbertheory, ecdsa, util
import binascii, string, bitcoin # from electrum code, contains base58 encode and others

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
  return bitcoin.hash_160(point2pubkey(p))
def point2idx(p):
  return tohex(bitcoin.hash_160(point2pubkey(p)))
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
  return bitcoin.hash_160(toraw(pubkey))
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
#def val2int(val):
#  return int(tohex(toraw(val)[::-1]),16)
# big-endian binary value (e.g. hash)
def val2int(val):
  return int(tohex(val),16)

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

