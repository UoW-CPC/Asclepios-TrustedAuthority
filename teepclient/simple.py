import asyncio
import aiocoap
import aiocoap.resource
import cbor
import binascii

import Crypto.Hash.SHA256 as SHA256
import Crypto.PublicKey.RSA as RSA
import Crypto.Cipher.PKCS1_OAEP as PKCS1_OAEP
import Crypto.Cipher.PKCS1_v1_5 as PKCS1_v1_5

#from base64 import b64encode,b64decode

#from lib import *

def catcher(f):
    try: return f()
    except: return None


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
    data = f'Some string to a'.encode()
    assert len(data)<256-11, "pkcs_v1_5 message length limit exceeded with data"
    #pk = RSA.importKey(trim0(ans['key']))
    #c = PKCS1_v1_5.new(pk).encrypt(data)
    # seal data
    #s = ask(uri, {'id':ans['id'], 'seal':c})['sealed']
    # Since the enclave can open sealed data, it can do things to it.
    # Here we just return it - which is not what one should usually do.
    # typically one would compute some statistic on a medical journal.
    #print(ask(uri, {'unseal':s, 'id':ans['id']})['data'])

    # encryption 
  #  ret = ask(uri, {'encrypt':True, 'id':ans['id'],'message':bytes(data),'key':bytes('itzkbgulrcsjmnv',encoding='utf8')})
    ret = ask(uri, {'encrypt':True, 'id':ans['id'],'message':data,'key':'itzkbgulrcsjmnv'})
    print("in simple.py - ciphertext:",ret['message']);
   
    print("in simple.py - size of ciphertext:",ret['size']);
    # decryption
#    ret = ask(uri, {'encrypt':False, 'id':ans['id'],'message':ret['message'],'key':'itzkbgulrcsjmnv'})

 #   print("in simple.py - plaintext:",ret['message']);
 #   print("in simple.py - size of plaintext:",ret['size']);
