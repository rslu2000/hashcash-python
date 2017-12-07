#!/usr/bin/python3
import urllib,base64,json,hashlib,struct,random,time,requests

RPC_URL = "http://35.201.191.103:8332"
RPC_USER = "rslu"
RPC_PASS = "1234"

def rpc(method, params=None):
    rpc_id = random.getrandbits(32)

    callstr = json.dumps({"id": rpc_id, "method": method, "params": params})
    res1 = requests.post(url=RPC_URL, data=callstr, auth=(RPC_USER, RPC_PASS))
    response = json.loads(res1.text)
    print (response['id'])
    print (response.keys())
    print (response['result'].keys())
    if response['id'] != rpc_id:
        raise ValueError("invalid response id!")
    elif response['error'] != None:
        raise ValueError("rpc error: %s" % json.dumps(response['error']))

if __name__ == "__main__":
    block_template=rpc("getblocktemplate")