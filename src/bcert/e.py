#!/usr/bin/python

from ecdsa import ellipticcurve
from ecdsa import numbertheory
from ecdsa import ecdsa
from ecdsa import util
import bitcoin # from electrum code, contains base58 encode and others
from bitcoin import hash_160 # from electrum code, contains base58 encode and others
import string
from hashlib import sha256 # will probably need this too

#bitcoin.addrtype = 0x00 # creates mainnet addresses
bitcoin.addrtype = 0x6f # creates testnet addresses

# secp256k1, http://www.oid-info.com/get/1.3.132.0.10
_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_b = 0x0000000000000000000000000000000000000000000000000000000000000007L
_a = 0x0000000000000000000000000000000000000000000000000000000000000000L
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L
C = ellipticcurve.CurveFp( _p, _a, _b ) 
G = ellipticcurve.Point( C, _Gx, _Gy, _r )
zero = 0*G;

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
  
# convert compressed pubkey (32+1 bytes) to point
def pubkey2point(pubkey):
  x = int(tohex(pubkey)[2:],16)
  fx = (x * x * x + C.a() * x + C.b()) % C.p()
  y = numbertheory.square_root_mod_prime(fx,C.p())
  P = ellipticcurve.Point(C,x,y)
  if point2pubkey(P) != toraw(pubkey):
      P = ellipticcurve.Point(C,x,C.p()-y)
  return P

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
