import simple;
import Crypto.Hash.SHA256 as SHA256
import Crypto.PublicKey.RSA as RSA
import Crypto.Cipher.PKCS1_OAEP as PKCS1_OAEP
import Crypto.Cipher.PKCS1_v1_5 as PKCS1_v1_5
def trim0(b):
    return b[:b.find(b'\0')]

URL_TEEP='coap://teep-server:5683/teep'
#URL_TEEP='coap://127.0.0.1:5683/teep'
#URL_TEEP='coap://172.18.0.2:5683/teep'

#enc=simple.initenclave(URL_TEEP)

#key=f'123456789123456'.encode()
msg = b'Some string to b'

# RSA encryption to the key
#assert len(key)<256-11, "pkcs_v1_5 message length limit exceeded with data"
#pk = RSA.importKey(trim0(enc['key']))
#c = PKCS1_v1_5.new(pk).encrypt(key)
#print("encrypted key:{},type:{}",c,type(c))
# seal data
#s=simple.sealkey(enc['id'],c,URL_TEEP);
#print("sealed key:{},length:{}",s,len(s));

#unseal data - test only
#print("unseal key:{}",simple.unsealkey(enc['id'],s,URL_TEEP))

#pk = RSA.importKey(trim0(enc['key']))
#encrypted_key = PKCS1_v1_5.new(pk).encrypt(key)
#print("enclave_id:{}",enc['id'])
#sealed_key = simple.sealkey(enc['id'],encrypted_key,URL_TEEP);
#print("enclave id:{},sealed key:{}",enc['id'],sealed_key);
#unsealed_key = simple.unsealkey(enc['id'],sealed_key,URL_TEEP);
#print("unsealed key:{}",unsealed_key);

# encryption with sealed keys
s=b'8\xa6@\x81\xe5^\xde\xdd\xe5\xca2d\xb8\x01bf\x1b4a\xb8g\xdf\x80\xf61\xdb\x0e\x05\xbe\x04z\xfa'
ct,size_ct = simple.encrypt_w_sealkey(0,True,s,msg,URL_TEEP);
print("ciphertext:{},size:{}",ct,size_ct)

pt,size_pt=simple.encrypt_w_sealkey(0,False,s,ct,URL_TEEP)
print("plaintext:{},size:{}",pt,size_pt)

# encryption with key in plaintext
#ct,size_ct = simple.encrypt(enc['id'],True,key,msg,URL_TEEP);
#print("ciphertext:{},size:{}",ct,size_ct)
#pt,size_pt=simple.encrypt(enc['id'],False,key,ct,URL_TEEP)
#print("plaintext:{},size:{}",pt,size_pt)
