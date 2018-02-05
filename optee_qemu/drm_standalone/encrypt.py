#!/usr/bin/env python

import sys


DEC = sys.argv[1]
ENC = sys.argv[2]

with open(DEC, "rb") as dec, open(ENC, "wb") as enc:
    content = dec.read()
    for c in content:
        c = chr(ord(c) ^ 0x32)
        enc.write(c)
