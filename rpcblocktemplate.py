#coding=utf-8
#python2
import urllib2,base64,json,hashlib,struct,random,time

RPC_URL = "http://104.199.215.247:8332"
RPC_USER = "rslu"
RPC_PASS = "1234"

def rpc(method, params=None):
    rpc_id = random.getrandbits(32)

    callstr = json.dumps({"id": rpc_id, "method": method, "params": params})

    authstr = base64.encodestring('%s:%s' % (RPC_USER, RPC_PASS)).strip()

    request = urllib2.Request(RPC_URL)
    request.add_header("Authorization", "Basic %s" % authstr)
    request.add_data(callstr)
    f = urllib2.urlopen(request)
    response = json.loads(f.read())
    #print response['id']
    #print response.keys()
    #print response['result'].keys() 
    if response['id'] != rpc_id:
        raise ValueError("invalid response id!")
    elif response['error'] != None:
        raise ValueError("rpc error: %s" % json.dumps(response['error']))

    return response['result']

def block_prepare(block_template, coinbase_message, extranonce_start, address, timeout=False, debugnonce_start=False):
    # Add an empty coinbase transaction to the block template
    coinbase_tx = {}
    block_template['transactions'].insert(0, coinbase_tx)
    # Add a nonce initialized to zero to the block template
    block_template['nonce'] = 0
    extranonce = extranonce_start
    # Update the coinbase transaction with the extra nonce
    coinbase_script = coinbase_message + int2lehex(extranonce, 4)
    coinbase_tx['data'] = tx_make_coinbase(coinbase_script, address, block_template['coinbasevalue'], block_template['height'])
    coinbase_tx['hash'] = tx_compute_hash(coinbase_tx['data'])

    # Recompute the merkle root
    tx_hashes = [tx['hash'] for tx in block_template['transactions']]
    block_template['merkleroot'] = tx_compute_merkle_root(tx_hashes)
    print 'version:' + str(block_template['version'])
    print 'previousblockhash:' + block_template['previousblockhash']
    print 'merkleroot:' + block_template['merkleroot']
    print 'curtime:' + str(block_template['curtime'])
    print 'bits:' + block_template['bits']
    print 'mining block height:' + str(block_template['height'])
    print 'total txs:' +str(len(block_template['transactions']))
    return block_template





# Convert an unsigned integer to a little endian ASCII Hex
def int2lehex(x, width):
    if width == 1: return "%02x" % x
    elif width == 2: return "".join(["%02x" % ord(c) for c in struct.pack("<H", x)])
    elif width == 4: return "".join(["%02x" % ord(c) for c in struct.pack("<L", x)])
    elif width == 8: return "".join(["%02x" % ord(c) for c in struct.pack("<Q", x)])

def bin2hex(s):
    h = ""
    for c in s:
        h += "%02x" % ord(c)
    return h

def hex2bin(s):
    b = ""
    for i in range(len(s)/2):
        b += chr(int(s[2*i : 2*i + 2], 16))
    return b

def int2varinthex(x):
    if x < 0xfd: return "%02x" % x
    elif x <= 0xffff: return "fd" + int2lehex(x, 2)
    elif x <= 0xffffffff: return "fe" + int2lehex(x, 4)
    else: return "ff" + int2lehex(x, 8)

def bitcoinaddress2hash160(s):
    table = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    x = 0
    s = s[::-1]
    for i in range(len(s)):
        x += (58**i)*table.find(s[i])

    # Convert number to ASCII Hex string
    x = "%050x" % x
    # Discard 1-byte network byte at beginning and 4-byte checksum at the end
    return x[2:50-8]


def encode_coinbase_height(n, min_size = 1):
  	s = bytearray(b'\1')

  	while n > 127:
  		s[0] += 1
  		s.append(n % 256)
  		n //= 256

  	s.append(n)

  	while len(s) < min_size + 1:
  		s.append(0)
  		s[0] += 1

  	return bytes(s)


def tx_make_coinbase(coinbase_script, address, value, height):
    # See https://en.bitcoin.it/wiki/Transaction

    coinbase_script = bin2hex(encode_coinbase_height(height)) + coinbase_script

    # Create a pubkey script
    # OP_DUP OP_HASH160 <len to push> <pubkey> OP_EQUALVERIFY OP_CHECKSIG
    pubkey_script = "76" + "a9" + "14" + bitcoinaddress2hash160(address) + "88" + "ac"

    tx = ""
    # version
    tx += "01000000"
    # in-counter
    tx += "01"
    # input[0] prev hash
    tx += "0"*64
    # input[0] prev seqnum
    tx += "ffffffff"
    # input[0] script len
    tx += int2varinthex(len(coinbase_script)/2)
    # input[0] script
    tx += coinbase_script
    # input[0] seqnum
    tx += "ffffffff"
    # out-counter
    tx += "01"
    # output[0] value (little endian)
    tx += int2lehex(value, 8)
    # output[0] script len
    tx += int2varinthex(len(pubkey_script)/2)
    # output[0] script
    tx += pubkey_script
    # lock-time
    tx += "00000000"

    return tx

def tx_compute_hash(tx):
    h1 = hashlib.sha256(hex2bin(tx)).digest()
    h2 = hashlib.sha256(h1).digest()
    return bin2hex(h2[::-1])


def tx_compute_merkle_root(tx_hashes):
    # Convert each hash into a binary string
    for i in range(len(tx_hashes)):
        # Reverse the hash from big endian to little endian
        tx_hashes[i] = hex2bin(tx_hashes[i])[::-1]

    # Iteratively compute the merkle root hash
    while len(tx_hashes) > 1:
        # Duplicate last hash if the list is odd
        if len(tx_hashes) % 2 != 0:
            tx_hashes.append(tx_hashes[-1][:])

        tx_hashes_new = []
        for i in range(len(tx_hashes)/2):
            # Concatenate the next two
            concat = tx_hashes.pop(0) + tx_hashes.pop(0)
            # Hash them
            concat_hash = hashlib.sha256(hashlib.sha256(concat).digest()).digest()
            # Add them to our working list
            tx_hashes_new.append(concat_hash)
        tx_hashes = tx_hashes_new

    # Format the root in big endian ascii hex
    return bin2hex(tx_hashes[0][::-1])

def mining_block(block_template):
    ver = block_template['version']
    prev_block = block_template['previousblockhash']
    mrkl_root = block_template['merkleroot']
    time_ = block_template['curtime']
    bits = int(block_template['bits'],16)
    nonce = block_template['nonce']
    print bits
    print nonce
    #bits= hex2bin(bits)
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



if __name__ == "__main__":
    coinbase_message=bin2hex('developed by Professor Lu,RUEISHAN')
    address='1APtYTnTxVG1HEt9b7V4pyA4JDgwtDqjvV'
    block_template=rpc("getblocktemplate")
    block_prepare(block_template, coinbase_message, 0, address, timeout=60)
    ans =raw_input("Do you want to mine this block? y or n: ")
    if ans =='y':
        mining_block(block_template)
