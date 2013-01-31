#!/usr/bin/python

from ecdsa import ellipticcurve
from ecdsa import numbertheory
from ecdsa import ecdsa
from ecdsa import util
import bitcoin # from electrum code, contains base58 encode and others
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

# convert compressed pubkey (32+1 bytes) to point
def pubkey2point(hexstr):
  x = int(hexstr[2:],16)
  fx = (x * x * x + C.a() * x + C.b()) % C.p()
  y = numbertheory.square_root_mod_prime(fx,C.p())
  P = ellipticcurve.Point(C,x,y)
  if point2pubkey(P) != hexstr:
      P = ellipticcurve.Point(C,x,C.p()-y)
  return P

#ECP = ecdsa.Public_key(G,P)
#ECQ = ecdsa.Public_key(G,Q)

# convert point to compressed pubkey (32+1 bytes)
def point2pubkey(p):
    x_str = util.number_to_string(p.x(), G.order())
    y_str = util.number_to_string(p.y(), G.order())
    return (chr(2 + (p.y() & 1)) + x_str)

# convert point to address
def point2addr(p):
    return pubkey2addr(point2pubkey(p))

# convert compressed pubkey to address
def pubkey2addr(pubkey): 
    return bitcoin.public_key_to_bc_address(pubkey)

# little-endian binary value (e.g. hash)
def hash2int(val):
  return int(val[::-1].encode('hex'),16)

# derived pubkey  
def derivepubkey(hash):
   return point2pubkey(hash2int(hash)*G)
