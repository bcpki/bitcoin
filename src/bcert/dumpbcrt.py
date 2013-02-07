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

import sys, getopt, os
from bcert import *

# default
ascii = data = binhex = store = filename = False
pretty = True

optlist,args = getopt.getopt(sys.argv[1:],'adxsf')

for (k,v) in optlist:
  if k in ["-a","-d","-x","-f"]:
    pretty = False
  if   k == "-a": ascii = True 
  elif k == "-d": data = True
  elif k == "-x": binhex = True
  elif k == "-s": store = True
  elif k == "-f": filename = True

if store:
  idx = alias2idx(args[0])
  fname = os.path.expanduser('~/.bitcoin/testnet3/bcerts/'+idx+'.bcrt')
  if filename: print idx 
else:
  fname = args[0]
  
bcrt = open(fname).read()

if pretty: print bcrt2cert(bcrt) 
if ascii: print bcrt2asciiarmored(bcrt) 
if data: print bcrt2hashx(bcrt)
if binhex: print bcrt.encode('hex')
