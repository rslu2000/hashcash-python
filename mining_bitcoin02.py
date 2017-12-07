#coding:utf-8
#python2
import struct, binascii, hashlib

ver = int(raw_input("請輸入區塊的版本編號："))
prev_block = raw_input("請輸入前一區塊的哈希值:")
mrkl_root = raw_input("請輸入梅根樹節點的哈希值:")
time_ = int(raw_input("請輸入時間戳記："))
bits = int(raw_input("請輸入難度值:"))
nonce =int(raw_input("請輸入求解的起始範圍："))

exp = bits >> 24
mant = bits & 0xffffff
target_hexstr = '%064x' % (mant * (1<<(8*(exp - 3))))
target_str = target_hexstr.decode('hex')

sha256 = hashlib.sha256

while nonce < 0x10000000000:
    header = ( struct.pack("<L", ver) + prev_block.decode('hex')[::-1] +
          mrkl_root.decode('hex')[::-1] + struct.pack("<LLL", time_, bits, nonce))
    hash = sha256(sha256(header).digest()).digest()
    print nonce, hash[::-1].encode('hex')
    if hash[::-1] < target_str:
        print 'Mining success'
        break
    nonce += 1
