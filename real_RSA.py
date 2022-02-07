from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
import time


#245= 2048/8 -11
file=open("test_245B.txt","r")
message=file.read()
file.close()

key = RSA.generate(2048)
cipher = PKCS1_v1_5.new(key)
en_start=time.time()
ciphertext=cipher.encrypt(message)
en_rtime=time.time() - en_start
print("encryption running time: "+str(en_rtime)+" sec")
    
#print(ciphertext)

#decrypt
de_start=time.time()
sentinel=""
message=cipher.decrypt(ciphertext, sentinel)
#print(message)
de_rtime=time.time() - de_start
print("decryption running time: "+str(de_rtime)+" sec")
