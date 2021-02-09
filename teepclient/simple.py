import asyncio
import aiocoap
import aiocoap.resource
import cbor
import binascii

import Crypto.Hash.SHA256 as SHA256
import Crypto.PublicKey.RSA as RSA
import Crypto.Cipher.PKCS1_OAEP as PKCS1_OAEP
import Crypto.Cipher.PKCS1_v1_5 as PKCS1_v1_5

from base64 import b64encode,b64decode

#from lib import *

import json
import logging
import os
# Get an instance of a logger
logger = logging.getLogger(__name__)

APP_IMAGE = os.getcwd() + '/teepclient/enclave_a/enclave_a.signed'
#APP_IMAGE = os.getcwd() + '/enclave_a/enclave_a.signed'

def catcher(f):
    try: return f()
    except: return None

"""
### Server

class myresource(aiocoap.resource.Resource):
    cnt = 0
    enclaves = []
    async def render_put(self, request):
        input = cbor.loads(request.payload)
        output = cbor.dumps({'error':1})
        if 'install' in input:
            e_binary = input['install']
            s = SHA256.new(); s.update(e_binary); h = s.digest()
            e = create_enclave(e_binary)
            id = len(self.enclaves)
            self.enclaves.append((s,e))
            if e != None:
                r = get_remote_report_with_pubkey(e)
                if r != None:
                    output = cbor.dumps({'key':r[0], 'report': r[1], 'id':id, 'sha':h})

        elif 'seal' in input:
            (s, e) = self.enclaves[input['id']]
            sd = seal_bytes(e, input['seal'])
            output = cbor.dumps({'sealed': sd})

        elif 'unseal' in input:
            (s, e) = self.enclaves[input['id']]
            d = unseal_bytes(e, input['unseal'])
            print(d)
            output = cbor.dumps({'data': d})
        
        elif 'encrypt' in input:
            (s, e) = self.enclaves[input['id']]
           # print("simple.py - enclave:",e)
           # print("simple.py - encrypt:",input['encrypt'])
           # print("simple.py - key:",input['key'])
           # print("simple.py - message:",input['message'])
            (output,size) = encrypt(e,input['encrypt'],input['key'],input['message'])
            output = cbor.dumps({'message': output,'size':size})

        return aiocoap.Message(code=aiocoap.CONTENT, payload=output)

def start_server(ip='::', port=5683):
    root = aiocoap.resource.Site()
    root.add_resource(['teep'], myresource())
    e = asyncio.get_event_loop()
    ctx = aiocoap.Context.create_server_context(root, bind=(ip, port))
    e = asyncio.get_event_loop()
    e.create_task(ctx)
    e.run_forever()
"""

### Client

async def put_coap(uri, data:bytes):
    msg = aiocoap.Message(uri=uri,
        code=aiocoap.PUT,
        payload=data)

    ctx = await aiocoap.Context.create_client_context()
    return await ctx.request(msg).response

def ask(uri, query={'donald':'duck'}):
    response = asyncio.run(put_coap(uri, cbor.dumps(query)))
    return cbor.loads(response.payload)

def install(uri, filename):
    with open(filename, 'rb') as f: binary = f.read()
    response = asyncio.run(put_coap(uri, cbor.dumps({'install':binary})))
    return cbor.loads(response.payload)



def trim0(b):
    return b[:b.find(b'\0')]

def sealingtest(uri='coap://127.0.0.1:5683/teep'):
    # Ask the remote TEEP agent to create a new instance.
    # It returns a pubkey and report from that instance
    #ans = install(uri, '/home/ubuntu/Asclepios-TrustedAuthority/teepclient/enclave_a/enclave_a.signed')
    ans = install(uri, 'enclave_a/enclave_a.signed')
    data = f'Some string'.encode()
    print("in simple.py - input data:",data)
    print("in simple.py - length of data:",len(data))
    assert len(data)<256-11, "pkcs_v1_5 message length limit exceeded with data"
    pk = RSA.importKey(trim0(ans['key']))
    c = PKCS1_v1_5.new(pk).encrypt(data)
    # seal data
    s = ask(uri, {'id':ans['id'], 'seal':c})['sealed']
    # Since the enclave can open sealed data, it can do things to it.
    # Here we just return it - which is not what one should usually do.
    # typically one would compute some statistic on a medical journal.
    print(ask(uri, {'unseal':s, 'id':ans['id']})['data'])
    
    # encryption 
    key = '123456789123456'

    ret = ask(uri, {'encrypt':True, 'id':ans['id'],'message':data,'key':key})
    print("in simple.py - ciphertext:",ret['message']);
    print("in simple.py - size of ciphertext:",ret['size']);

    # decryption
    ret = ask(uri, {'encrypt':False, 'id':ans['id'],'message':ret['message'],'key':key})
    print("in simple.py - plaintext:",ret['message']);
    print("in simple.py - size of plaintext:",ret['size']);

def initenclave(uri='coap://127.0.0.1:5683/teep'):
    ans = install(uri, APP_IMAGE)
    return ans;

# Retrieve public key from SGX enclave
def getpubkey(enclave):#,uri='coap://127.0.0.1:5683/teep'):
    # Ask the remote TEEP agent to create a new instance.
    # It returns a pubkey and report from that instance
    #ans = install(uri, '/TA/teepclient/enclave_a/enclave_a.signed')
    #logger.debug("getpubkey func - generated public key (PEM format):",ans['key'])
    #pk=ans['key'].decode('utf-8')#trim0.decode.rstrip()
    #logger.debug("getpubkey func - generated public key (utf-8 decoded):",pk)

    #return pk,ans['report'],ans['id']

    logger.debug("getpubkey func - generated public key (PEM format):",enclave['key'])
    pk=trim0(enclave['key']).decode('utf-8')#enclave['key'].decode('utf-8')#trim0.decode.rstrip()
    logger.debug("getpubkey func - generated public key (utf-8 decoded):",pk)

    return pk,enclave['report'],enclave['id'],enclave['sha']


# RSA PKCS1_v1_5
def sealkey(enclave_id,encrypted_key,uri='coap://127.0.0.1:5683/teep'):
    logger.debug("enclave_id:{},encrypted key:{}",enclave_id,encrypted_key)
    oeid = int(enclave_id)
    #sealed_pk = ask(uri, {'id':oeid, 'seal':b64decode(encrypted_key)})['sealed']
    sealed_pk = ask(uri, {'id':oeid, 'seal':encrypted_key})['sealed']
    #logger.debug("unsealed data:%s",ask(uri, {'unseal':sealed_pk, 'id':oeid})['data']) #test only
    return sealed_pk

# test only
def unsealkey(enclave_id,sealed_key,uri='coap://127.0.0.1:5683/teep'):
    logger.debug("enclave_id:{}, sealed key:{}",enclave_id,sealed_key)
    oeid = int(enclave_id)
    key = ask(uri, {'id':oeid, 'unseal':sealed_key})['data']
    return key

# encrypt/decrypt 1 data block using the sealed key
def encrypt_w_sealkey(enclave_id,encrypt,sealed_key,message,uri='coap://127.0.0.1:5683/teep'):
    ret = ask(uri, {'enc_with_sealkey':encrypt, 'id':int(enclave_id),'message':message,'sealed_key':sealed_key})
    logger.debug("output:{},size:{}",ret['message'],ret['size'])
    return ret['message'],ret['size']

# encrypt/decrypt 1 data block
def encrypt(enclave_id,encrypt,key,message,uri='coap://127.0.0.1:5683/teep'):
    ret = ask(uri, {'encrypt':encrypt, 'id':enclave_id,'message':message,'key':key})
    logger.debug("output:{},size:{}",ret['message'],ret['size'])
    return ret['message'],ret['size']
