from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import time


def printinhex(text):
    t=[]
    for c in text:
        t.append(hex(ord(c)))
    print(t)
        
print("Testing real world implementation of AES with 245B file")

test="test_245B.txt"

key=b'myflaaagismyflag'

iv_arr=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
iv=b''
for n in iv_arr:
    iv=iv+chr(n)


print("\n-------------ECB mode of operation--------------")

def do_ECB(text):
    en_start=time.time()
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(text, 16))
    en_rtime=time.time() - en_start
    print("encryption running time: "+str(en_rtime)+" sec")

    de_start=time.time()
    plaintext = unpad(cipher.decrypt(ciphertext), 16)
    de_rtime=time.time() - de_start

    print("decryption running time: "+str(de_rtime)+" sec")    


print("\n.....245B.....\n")

file=open(test,"r")
text=file.read()
file.close()

do_ECB(text)

print("\n-------------CBC mode of operation--------------")

def do_CBC(text):
    en_start=time.time()
    cipher = AES.new(key, AES.MODE_CBC,iv)
    ciphertext = cipher.encrypt(pad(text, 16))
    en_rtime=time.time() - en_start
    print("encryption running time: "+str(en_rtime)+" sec")

    #printinhex(ciphertext)

    cipher2 = AES.new(key, AES.MODE_CBC,iv)

    de_start=time.time()
    plaintext = unpad(cipher2.decrypt(ciphertext), 16)
    de_rtime=time.time() - de_start

    print("decryption running time: "+str(de_rtime)+" sec")


print("\n.....245B.....\n")

file=open(test,"r")
text=file.read()
file.close()

do_CBC(text)



print("\n-------------CFB mode of operation--------------")

def do_CFB(text):
    en_start=time.time()
    cipher = AES.new(key, AES.MODE_CFB,iv=iv,segment_size=128)
    ciphertext = cipher.encrypt(text)
    en_rtime=time.time() - en_start
    print("encryption running time: "+str(en_rtime)+" sec")

    #printinhex(ciphertext)

    cipher2 = AES.new(key, AES.MODE_CFB,iv=iv,segment_size=128)

    de_start=time.time()
    plaintext = cipher2.decrypt(ciphertext)
    de_rtime=time.time() - de_start

    #print(plaintext)

    print("decryption running time: "+str(de_rtime)+" sec")


print("\n.....245B.....\n")

file=open(test,"r")
text=file.read()
file.close()

do_CFB(text)



print("\n-------------OFB mode of operation--------------")

def do_OFB(text):
    en_start=time.time()
    cipher = AES.new(key, AES.MODE_OFB,iv=iv)
    ciphertext = cipher.encrypt(text)
    en_rtime=time.time() - en_start
    print("encryption running time: "+str(en_rtime)+" sec")

    #printinhex(ciphertext)

    cipher2 = AES.new(key, AES.MODE_OFB,iv=iv)

    de_start=time.time()
    plaintext = cipher2.decrypt(ciphertext)
    de_rtime=time.time() - de_start

    #print(plaintext)

    print("decryption running time: "+str(de_rtime)+" sec")



print("\n.....245B.....\n")

file=open(test,"r")
text=file.read()
file.close()

do_OFB(text)


print("\n-------------CTR mode of operation--------------")

nonce_arr=[0,1,2,3,4,5,6,7]
nonce=b''
for n in nonce_arr:
    nonce=nonce+chr(n)

def do_CTR(text):
    en_start=time.time()
    cipher = AES.new(key, AES.MODE_CTR,nonce=nonce)
    ciphertext = cipher.encrypt(text)
    en_rtime=time.time() - en_start
    print("encryption running time: "+str(en_rtime)+" sec")

    #printinhex(ciphertext)

    cipher2 = AES.new(key, AES.MODE_CTR,nonce=nonce)

    de_start=time.time()
    plaintext = cipher2.decrypt(ciphertext)
    de_rtime=time.time() - de_start

    #print(plaintext)

    print("decryption running time: "+str(de_rtime)+" sec")



print("\n.....245B.....\n")

file=open(test,"r")
text=file.read()
file.close()

do_CTR(text)



