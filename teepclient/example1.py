import Crypto.PublicKey.RSA as RSA
import Crypto.Hash.SHA256 as SHA256
import Crypto.Cipher.PKCS1_v1_5 as PKCS1_v1_5
import binascii
from math import log
from lib import *

def readfile(filename):
    with open(filename, 'rb') as f:
        return f.read()

ea_binary = readfile('enclave_a/enclave_a.signed')
eb_binary = readfile('enclave_b/enclave_b.signed')

ea  = create_enclave(ea_binary)
ea2 = create_enclave(ea_binary)
eb  = create_enclave(eb_binary)



# first ask the enclave about its public key and get a report
# and then ask the other enclave to verify the report and store the pubkey
pa, ra = get_remote_report_with_pubkey(ea)
res = verify_report_and_set_pubkey(eb, pa, ra) 
assert res == 0, "enclave b couldn't attest a"

# prepare to use ea's public key from python
def trim0(b):
    return b[:b.find(b'\0')]  # need to remove padding '\0' bytes
pk = RSA.importKey(trim0(pa))


# and the same the other way around
pb, rb = get_remote_report_with_pubkey(eb)
res = verify_report_and_set_pubkey(ea, pb, rb)
assert res == 0, "enclave a couldn't attest b"

print("Both sides attested correctly.")

if False:
    """this is how the MRSIGNER is computed in crypto.cpp; 
         as the SHA256 of the public key modulus in little endian"""
    modulus = pk.n
    modulus_len = 1+int(log(modulus)/log(256))
    modulus_bytes_le = bytes([(modulus>>(8*i))%256 for i in range(modulus_len)])
    s = SHA256.new(); s.update(modulus_bytes_le); d = s.digest()
    print(binascii.hexlify(d).decode())


# seal data to enclaves that uses ea's code

data = f'this is a VERY secret message.'.encode()
assert len(data)<256-11, "pkcs_v1_5 message length limit exceeded with data"

# encrypt using pa = ea's public key
c = PKCS1_v1_5.new(pk).encrypt(data)

s = seal_bytes(ea, c)
print('ea2 sees: ', unseal_bytes(ea2, s))
print('eb sees:  ', unseal_bytes(eb, s))
