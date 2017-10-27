import urllib2
import base64
import json
import hashlib
import struct
import random
import time

RPC_URL = "http://127.0.0.1:8332"
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
    print response['id']
    print response.keys()
    print response['result'].keys() 
    if response['id'] != rpc_id:
        raise ValueError("invalid response id!")
    elif response['error'] != None:
        raise ValueError("rpc error: %s" % json.dumps(response['error']))

    return response['result']

if __name__ == "__main__":
   
    rpc("getblocktemplate")
