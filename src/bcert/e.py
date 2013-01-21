#!/usr/bin/python
# from electrum code

from hashlib import sha256
import ecdsa

# secp256k1, http://www.oid-info.com/get/1.3.132.0.10
_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_b = 0x0000000000000000000000000000000000000000000000000000000000000007L
_a = 0x0000000000000000000000000000000000000000000000000000000000000000L
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L
curve_secp256k1 = ecdsa.ellipticcurve.CurveFp( _p, _a, _b )
generator_secp256k1 = ecdsa.ellipticcurve.Point( curve_secp256k1, _Gx, _Gy, _r )
oid_secp256k1 = (1,3,132,0,10)
SECP256k1 = ecdsa.curves.Curve("SECP256k1", curve_secp256k1, generator_secp256k1, oid_secp256k1 )

curve = SECP256k1

# demo
# works:
#hashstr1='eb623ed1e7849949c8c046e47de3286bb19417aec0702940c9beb29a6b3b2130' # ein alias hash
#hashstr2='03f1848b40621c5d48471d9784c8174ca060555891ace6d2b03c58eece946b1a91' # der pubkey dazu
# doesn't work:
#hashstr1='47bff9a8cece1a8eb6fe7afac6c303714afa2b0e3eac0c88fe6b8ff215cf5c91' # ein alias hash
#hashstr2='03c8431b9de51956f2d921bc6bb74881fa8653cf534d0597bdfbfedd151ceb477b' # der pubkey dazu
# doesn't work:
hashstr1='b791e8615905de527198e0ed00e334dc49a5d579284248637620bc7dd591e389' # das cert 'ilja'
hashstr2='03fc0caa3f182cd65459b1f2d2b7090d629e16224cfdbbf874a3380a36d3c5f995' # der certhash von der transaction 'ilja'
hashstr1='e0b98e1a3840822f4957c87c3305a3d305d02915bbceabf9af09a854a87a1bf3' # das cert 'ilja'
hashstr2='02e7e6b28c2886d23c2c6e3a6f49e3b719692bfac73a564f4c8fe9788d93d77a1e' # der certhash von der transaction 'ilja'

def calchash(hashstr):
   P=int(hashstr,16)*curve.generator
   order = generator_secp256k1.order()
   x_str = ecdsa.util.number_to_string(P.x(), order)
   y_str = ecdsa.util.number_to_string(P.y(), order)
   stri=chr(2 + (P.y() & 1)) + x_str
   return stri.encode('hex')

print 'Hash from Cert: \t\t'+hashstr1
print 'Result: \t\t\t'+calchash(hashstr1)
print 'Certhash in transaction: \t'+hashstr2

print '\n\n'

print 'Hash from Cert: \t\t'+hashstr2
print 'Result: \t\t\t'+calchash(hashstr2)
print 'Certhash in transaction: \t'+hashstr1
