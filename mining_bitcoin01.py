#coding=utf-8

import struct, binascii, hashlib

#Block 490000

ver = 536870912
prev_block = "000000000000000000d3a9237438b8764dab8b5bf24d3e175bfa1c4a255c7287"
mrkl_root = "7a17aaae5bbb40bd3a3c99a78b1ea4579f309da4758c948ef9bc88b9fa3df82c"
time_ = 0x59e3a17d # unix_time=1508090237,2017年10月16日 週一 01時57分17秒 CST
bits = 0x1800eb30 #402713392
 
exp = bits >> 24
mant = bits & 0xffffff
target_hexstr = '%064x' % (mant * (1<<(8*(exp - 3))))
target_str = target_hexstr.decode('hex')

sha256 = hashlib.sha256

nonce = 1474000000
while nonce < 0x10000000000:
    header = ( struct.pack("<L", ver) + prev_block.decode('hex')[::-1] +
          mrkl_root.decode('hex')[::-1] + struct.pack("<LLL", time_, 
bits, nonce))
    hash = sha256(sha256(header).digest()).digest()
    print nonce, hash[::-1].encode('hex')
    if hash[::-1] < target_str:
        print 'Mining success'
        break
    nonce += 1
