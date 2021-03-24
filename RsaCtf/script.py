from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

with open('pubkey.pem') as f:
    key = RSA.importKey(f.read())
    
print(key.e)
print(key.n)
#factor n to get p
p = 10410080216253956216713537817182443360779235033823514652866757961082890116671874771565125457104853470727423173827404139905383330210096904014560996952285911
phi = p ** 2 * (p-1)
#lets get secret key d
d = inverse(key.e, phi)

with open('key') as f:
    psk = bytes_to_long(bytes.fromhex(f.read()))
#psk - decrypted with RSA cipher
psk = long_to_bytes(pow(psk, d, key.n))
#print (psk)   
#lets decrypt flag.txt.aes with AES key
cipher = AES.new(psk, AES.MODE_ECB)
with open('flag.txt.aes', 'rb') as f:
    flag = f.read().strip()

#print(bytes_to_long(flag))
flag = cipher.decrypt(flag)
print(flag)