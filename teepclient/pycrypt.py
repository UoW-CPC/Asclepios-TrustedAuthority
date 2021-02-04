from Crypto.PublicKey import RSA
import asn1

key = RSA.generate(2048)
f = open('mykey.pem','wb')
f.write(key.export_key('PEM'))
f.close()
print('public key:%s',key.publickey().export_key())
f = open('mykey.pem','r')
key = RSA.import_key(f.read())

s = b'`\xdb\xb0\xda\x04\x7f\x00\x00\xb5\xf2\x0c\xda\x04\x7f\x00\x00\xd83/\xda\x04\x7f\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xa0\x0c/\xda\x04\x7f\x00\x00`\xdc\xb0\xda\x04\x7f\x00\x00\xf4\xc2\x00\xda\x04\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe0\xd50\xda\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xf83/\xda\x04\x7f\x00\x00\x80\x01\x00\x00\x00\x00\x00\x00 \xe10\xda\x04\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xb0m\x1d\x02\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x10\x00\x00\x00\x00\x00\x00\x00@\xdc\xb0\xda\x04\x7f\x00\x008\x19\x08\xda\x04\x7f\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xa0\x0c/\xda\x04\x7f\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xf83/\xda\x04\x7f\x00\x00\xd83/\xda\x04\x7f\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xa0\x0c/\xda\x04\x7f\x00\x00\xed\xd4\x00\xda\x04\x7f\x00\x000\x19\xd2S\xff\x7f\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xa0\xac\x1d\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0\xdc\xb0\xda\x04\x7f\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0\xe20\xda\x04\x7f\x00\x00\xb0\xe20\xda\x04\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x10\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x88\x1a\xd2S\x00\x00\x00\x00'

encoder = asn1.Encoder()
encoder.start()
encoder.write('-----BEGIN RSA PRIVATE KEY-----')
encoded_bytes = encoder.output()
print(encoded_bytes)

decoder = asn1.Decoder()
decoder.start(encoded_bytes)
tag, value = decoder.read()
print(value)
#print(s.decode('asn.1'))

