#!/usr/bin/python
# from electrum code

from hashlib import sha256
from ecdsa import ellipticcurve
from ecdsa import numbertheory
from ecdsa import ecdsa
from ecdsa import util
import bitcoin

bitcoin.addrtype = 0x6f

# secp256k1, http://www.oid-info.com/get/1.3.132.0.10
_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_b = 0x0000000000000000000000000000000000000000000000000000000000000007L
_a = 0x0000000000000000000000000000000000000000000000000000000000000000L
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L
C = ellipticcurve.CurveFp( _p, _a, _b ) 
G = ellipticcurve.Point( C, _Gx, _Gy, _r )

def calchash(hashstr):
   P=int(hashstr,16)*G
   order = generator_secp256k1.order()
   x_str = ecdsa.util.number_to_string(P.x(), order)
   y_str = ecdsa.util.number_to_string(P.y(), order)
   stri=chr(2 + (P.y() & 1)) + x_str
   return stri.encode('hex')

goo = '0211b60f23135a806aff2c8f0fbbe620c16ba05a9ca4772735c08a16407f185b34' # goo owner pubkey
goo4 = '03046d258651af2fbb6acb63414a604314ce94d644a0efd8832ca5275f2bc207c6' # goo4 owner pubkey
#Pcompr = '0300d5dab184fffe0558ec41a4119446eb4331da1523ac8a482858c75be63c98ad'

def point(hexstr):
  x = int(hexstr[2:],16)
  fx = (x * x * x + C.a() * x + C.b()) % C.p()
  y = numbertheory.square_root_mod_prime(fx,C.p())
  P = ellipticcurve.Point(C,x,y)
  if compr(P) != hexstr:
      P = ellipticcurve.Point(C,x,C.p()-y)
  return P

#ECP = ecdsa.Public_key(G,P)
#ECQ = ecdsa.Public_key(G,Q)

def compr(p):
    x_str = util.number_to_string(p.x(), G.order())
    y_str = util.number_to_string(p.y(), G.order())
    return (chr(2 + (p.y() & 1)) + x_str).encode('hex')

def addr(p):
    return bitcoin.public_key_to_bc_address(compr(p).decode('hex'))

def cmpr2addr(hexstr):
    return addr(point(hexstr))

t = int('fc0c347ea3906d4883d499eaccec1f4318a3d68129034938cb53949260bb1ee6',16)
R = t*G+point(goo4)

