#!/usr/bin/python

from cert_pb2 import * 
from hashlib import sha256
from subprocess import Popen,PIPE,check_call,call

Cert=BitcoinSimpleCert()
Cert.email='foo@foobar.org'
Cert.url='http://foo.foobar.org/'
Cert.ecdsa_pubkeys.append('03bb0bacd9b1f73a6ef17d230e431538628f18174b0eccaaeb543a7731d9094a7e'.decode('hex'))
Cert.ecdsa_pubkeys.append('02d556d37bc1491277ed00dedb8bd08b4a94097eec1cd9d9dc17eeeaaa32c25da7'.decode('hex'))
hash=sha256(Cert.SerializeToString()).digest().encode('hex')

p = Popen(['./bitcoind','-testnet','registeralias','foo3','0.5',hash],stdout=PIPE)
result = p.stdout.read()
print result

#f=open('my.cert','wb')
#f.write(Cert.SerializeToString())
#f.close()
