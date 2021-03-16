import cbor
import json
import jwcrypto # https://jwt.io/
import binascii
import ecdsa

# CWT example
# CWT is a CBOR entity tag token containing "claims" about
# identity, validity, issuer etc,
# Here it wrapped in COSE with a signature is signed. Cose is serialized into CBOR

txt = 'd28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30'

def hex_cbor(s):
    "from hex-digits to parsed cbor"
    return cbor.loads(bytes.fromhex(s.replace('\n','').replace(' ','')))


def tohex(b):
    "binary string to hex-digits"
    return binascii.hexlify(b).decode()

cose = hex_cbor(txt)
assert cose.tag == 18  # 18 = cose-sign1 type message


protected = cbor.loads(cose.value[0])
key = ". alg".split()
protected = {key[k]:protected[k] for k in protected}

unprotected = cose.value[1]
key = ". . . . kid".split()
unprotected = {key[k]:unprotected[k] for k in unprotected}
# now thanks to value[1] say kid = AsymmetricECDSA256
# we know that there are two more values, the
# protected data and the signature


payload = cbor.loads(cose.value[2])
# rename keys from 1,2,3,... to 'iss', sub','aud', ...
key = ". iss sub aud exp nbf iat cti".split()
payload = {key[k]:payload[k] for k in payload}
del key

signature = cose.value[3]
signature = binascii.hexlify(signature).decode()

print(protected)
print(unprotected)
print(payload)
print(signature)


# key from https://tools.ietf.org/html/rfc8392#page18

cose_key = """   a72358206c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858
   bc206c1922582060f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db
   9529971a36e7b9215820143329cce7868e416927599cf65a34f3ce2ffda55a7e
   ca69ed8919a394d42f0f2001010202524173796d6d6574726963454344534132
   35360326
"""
cose_key = hex_cbor(cose_key)
kid = cose_key[2].decode()


sign_key = {'d': tohex(cose_key[-4]), "kid": kid}
verify_key = {'x': tohex(cose_key[-2]), 'y': tohex(cose_key[-3]), "kid": kid}

curve = ecdsa.NIST256p
hash = hashlib.sha256
#hash = hashlib.sha1
#msg = cose.value[0]+cose.value[2]
msg = cose.value[2]
d,x,y=int(sign_key['d'],16),int(verify_key['x'],16),int(verify_key['y'],16)
sk=ecdsa.SigningKey.from_secret_exponent(d, curve=curve, hashfunc=hash)

pt = ecdsa.ellipticcurve.Point(curve.curve, x=x, y=y)
vk = ecdsa.VerifyingKey.from_public_point(pt,curve=curve,hashfunc=hash)
print(vk.verify(sk.sign(msg), msg))

print(tohex(sk.sign(msg)))
print(signature)


vk.verify(bytes.fromhex(signature), msg)

# failed.... sigh....


sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1) 
vk = sk.get_verifying_key()
sig = sk.sign(b"message")
vk.verify(sig, b"message")


"""
https://tools.ietf.org/pdf/draft-ietf-rats-eat-02.pdf

An Entity Attestation Token (EAT) provides a signed (attested) set of
 claims that describe state and characteristics of an entity,

An EAT is either a CWT or JWT with some attestation-oriented claims.


https://tools.ietf.org/pdf/rfc8392.pdf
CBOR Web Token (CWT) is a compact means of representing claims to be
transferred between two parties. The claims in a CWT are encoded in
the Concise Binary Object Representation (CBOR), and CBOR Object
Signing and Encryption (COSE) is used for added application-layer
security protection. 


https://tools.ietf.org/pdf/rfc8152.pdf
CBOR Object Signing and Encryption (COSE)
describes how to create and process
signatures, message authentication codes, and encryption using CBOR
for serialization. This specification additionally describes how to
represent cryptographic keys using CBOR.


CDDL is a format for defining CBOR data

CDDL is defined in ABNF format
https://tools.ietf.org/html/draft-greevenbosch-appsawg-cbor-cddl-09#appendix-D

ABNF (Augmented BNF) 
https://tools.ietf.org/html/rfc5234  


The TEEP architecture
https://datatracker.ietf.org/doc/draft-ietf-teep-architecture/

HTTP Transport for Trusted Execution Environment Provisioning: Agent-to- TAM Communication
https://datatracker.ietf.org/doc/draft-ietf-teep-otrp-over-http/

Trusted Execution Environment Provisioning (TEEP) Protocol
https://datatracker.ietf.org/doc/draft-ietf-teep-protocol/
The TEEP messages are sent in CBOR which are defined in CDDL






"""



import Crypto.Cipher
Crypto.Cipher.AES.new(key=b'x'*32, IV=b'0'*32).encrypt(b'tre sma grisar! '*2)
pk = Crypto.PublicKey.RSA.importKey("""\ 
-----BEGIN PUBLIC KEY----- 
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2hotJzl2p4BTVEoRiZI8 
zla9KyehvOZkMifXpOD5ybkzjQdzTZBX5U+e7uDhHdCmXJ6RtVuaBWnhROlyKuri 
wB8mc30a7cmGyFbkrvmYVc1mSgzsE8qu3n/pzGI6vtbnIaLFoFBKnNG9o2Yrmlpw 
N7qnM+1Jb9sBB72DNqjcFvwTe4VE7e09O7+gBAi7wkbUXemqqNOmewRecfPg5qbK 
got+SiF8HBPWGxcVTnYjqnq3Qu3Wf3xOCBeiJVSEXnxcaQULPvkt0rWZfMq57NZb 
eMIJtPu917ep5hCk42gRfPCevMvQPW8/I7VVhf66UlLldh2SiYv/nitE7apc6BNU 
xQIDAQAB 
-----END PUBLIC KEY----- 
""")                                                                                                                                                                                                                                                                                                       
pk.encrypt(b'kalle ankas kanon!', None)[0]
