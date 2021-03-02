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

# The application image to be installed into SGX enclave
APP_IMAGE = os.getcwd() + '/teepclient/enclave_a/enclave_a.signed'
#APP_IMAGE = os.getcwd() + '/enclave_a/enclave_a.signed'

def catcher(f):
    try: return f()
    except: return None

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

""" for testing
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
"""

def existenclave(enclaveid, uri='coap://127.0.0.1:5683/teep'):
    oeid = int(enclaveid)
    ret = ask(uri, {'id_exist':oeid})['exist']
    print("Check if enclave exists:",ret)
    return ret

def initenclave(uri='coap://127.0.0.1:5683/teep'):
    """ Initialize a SGX enclave and install the application image defined by APP_IMAGE into the enclave
    
    Parameters
    ----------
    uri : URL string
        The URI of the teep-deployer server
    
    Returns
    ---------
    ans : Dictionary object
        The information of the initialized enclave. Example: {'key':public_key, 'report': attestation_report, 'id':0, 'sha':hash_value} 
    """

    logger.debug("initiate enclave")
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

    logger.debug("getpubkey func - generated public key (PEM format):{0}".format(enclave['key']))
    pk=trim0(enclave['key']).decode('utf-8')#enclave['key'].decode('utf-8')#trim0.decode.rstrip()
    logger.debug("getpubkey func - generated public key (utf-8 decoded):{0}".format(pk))

    return pk,enclave['report'],enclave['id'],enclave['sha']

def sealkey(enclave_id,encrypted_key,uri='coap://127.0.0.1:5683/teep'):
    """ Sealing data using a SGX enclave

    Parameters
    ----------
    enclave_id : number
        The identification of the enclave. This is its index in the array eenclaves defined at teep-deployer server.
    encrypted_key : string
        The data which has been encrypted with the enclave's public key using RSA PKCS1_v1_5.
    uri : URL
        The URL of the teep-deployer server.
    
    Returns
    ---------
    sealed_pk : string
        The sealed data.
    """

    logger.debug("enclave_id:%s,encrypted key:%s",enclave_id,encrypted_key)
    oeid = int(enclave_id)
    #sealed_pk = ask(uri, {'id':oeid, 'seal':b64decode(encrypted_key)})['sealed']
    sealed_pk = ask(uri, {'id':oeid, 'seal':encrypted_key})['sealed']
    #logger.debug("unsealed data:%s",ask(uri, {'unseal':sealed_pk, 'id':oeid})['data']) #test only
    return sealed_pk

"""
# test only
def unsealkey(enclave_id,sealed_key,uri='coap://127.0.0.1:5683/teep'):
    logger.debug("enclave_id:%s, sealed key:%s",enclave_id,sealed_key)
    oeid = int(enclave_id)
    key = ask(uri, {'id':oeid, 'unseal':sealed_key})['data']
    return key
"""

def encrypt_w_sealkey(enclave_id,encrypt,sealed_key,message,uri='coap://127.0.0.1:5683/teep'):
    """ Encrypt/ decrypt data using a sealed key.
    The sealed key is first unsealed inside a SGX enclave, then the unsealed key is used for encryption/ decryption.

    Parameters
    ----------
    enclave_id : number
        The identification of the enclave. This is its index in the array eenclaves defined at teep-deployer server.
    encrypt : boolean
        True if encrypting, False if decrypting
    sealed_key : string
        The sealed key
    message : string
        The input data. It is plaintext if encrypt=True, ciphertext if encrypt=False
    uri : URL
        The URL of the teep-deployer server
    
    Returns
    ---------
    ret['message'] : string
        The output data. It is the ciphertext if encrypt=True, the plaintext if encrypt=False
    ret['size'] : number
        The size of the output data
    """
    logger.debug("encrypt/ decrypt with sealed key")
    ret = ask(uri, {'enc_with_sealkey':encrypt, 'id':int(enclave_id),'message':message,'sealed_key':sealed_key})
    logger.debug("sealed key:%s,input:%s,input size:%d,output:%s,size:%d",sealed_key,message,len(message),ret['message'],ret['size'])
    return ret['message'],ret['size']

def encrypt(enclave_id,encrypt,key,message,uri='coap://127.0.0.1:5683/teep'):
    """ Encrypt/ decrypt data
    This function is only for testing, and should not be used in order to avoid transmitting the encryption/ encryption key in plaintext.

    Parameters
    ----------
    enclave_id : number
        The identification of the enclave. This is its index in the array eenclaves defined at teep-deployer server.
    encrypt : boolean
        True if encrypting, False if decrypting
    key : string
        The key
    message : string
        The input data. It is plaintext if encrypt=True, ciphertext if encrypt=False
    uri : URL
        The URL of the teep-deployer server
    
    Returns
    ---------
    ret['message'] : string
        The output data. It is the ciphertext if encrypt=True, the plaintext if encrypt=False
    ret['size'] : number
        The size of the output data
    """

    ret = ask(uri, {'encrypt':encrypt, 'id':enclave_id,'message':message,'key':key})
    logger.debug("output:%s,size:%d",ret['message'],ret['size'])
    return ret['message'],ret['size']
