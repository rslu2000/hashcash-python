# coding:utf-8
# python3
# https://replit.com/@rslu2000/mining#main02.py
# https://https://live.blockcypher.com/
# https://www.unixtimestamp.com/index.php
# 時間戳轉換 https://www.epochconverter.com/
# 範例 開挖第600000號區塊
# https://api.blockcypher.com/v1/btc/main/blocks/00000000000000000007316856900e76b4f7a9139cfbfba89842c8d196cd5f91
# timestamp 1571443461
# ver:536870912  "bits": 387294044  "nonce": 1066642855,
# "prev_block": "00000000000000000003ecd827f336c6971f6f77a0b9fba362398dd867975645",
# "mrkl_root": "66b7c4a1926b41ceb2e617ddae0067e7bfea42db502017fde5b695a50384ed26",
import struct
import binascii
import hashlib

# ver = int(raw_input("請輸入區塊的版本編號："),16)
ver = int(input("請輸入區塊的版本編號(10進制))："))
print(ver)
prev_block = input("請輸入前一區塊的哈希值:")
b_prev_block = bytes.fromhex(prev_block)
mrkl_root = input("請輸入梅根樹節點的哈希值:")
b_mrkl_root = bytes.fromhex(mrkl_root)
time_ = int(input("請輸入時間戳記(10進制)："))
bits = int(input("請輸入難度值(10進制):"))
print(bits)
nonce = int(input("請輸入求解的起始範圍(10進制)："))
print(nonce)

exp = bits >> 24
mant = bits & 0xffffff
target_hexstr = '%064x' % (mant * (1 << (8 * (exp - 3))))
# hex string converted to bytes
target_str = bytes.fromhex(target_hexstr)
print("target_hexstr:" + target_hexstr)
# bytes to be printed out, bytes should be done bytes=>hex string
print("target_str:" + target_str.hex())
sha256 = hashlib.sha256

while nonce < 0x10000000000:
    header = (struct.pack("<L", ver) + b_prev_block[::-1] +
              b_mrkl_root[::-1] + struct.pack(
                  "<LLL", time_, bits, nonce))
    print("header:" + header.hex())
    hash = sha256(sha256(header).digest()).digest()
    print("Hash:" + hash.hex())
    print(nonce, hash[::-1].hex())
    if hash[::-1] < target_str:
        print('Mining success')
        break
    nonce += 1
