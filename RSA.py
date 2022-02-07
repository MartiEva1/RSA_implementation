from sympy import randprime
import random
import time
from string import find

def gcd(n1,n2):
    while n2:
        n1, n2 = n2, n1 % n2
    return n1

def EEA(n1, n2):  
    s_0=1
    t_0=0
    s=0    
    t=1
    while n2:
        q=n1/n2
        s, s_0 = s_0 - q*s, s
        t, t_0 = t_0 - q*t, t
        n1,n2 = n2, n1%n2
    return n1, s_0, t_0


def random_e(phi):
    flag=False
    while(flag==False):
        e = random.randrange(3, phi)
        if (gcd(phi,e) == 1):
            flag=True
    return e


def key_gen():
    #2**1023
    start=89884656743115795386465259539451236680898848947115328636715040578866337902750481566354238661203768010560056939935696678829394884407208311246423715319737062188883946712432742638151109800623047059726541476042502884419075341171231440736956555270413618581675255342293149119973622969239858152417678164812112068608
    #2**1024 -1
    end=179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224137215
    p=randprime(start,end)
    q=randprime(start,end)

    n=p*q
    phi= (p-1)*(q-1)
    e=random_e(phi)
    gcd,s,t=EEA(phi, e)

    d=t%phi
    if(t<0):
        d=t+phi
        while(d<0):
            d=d+phi
    return e, d, n

def SandM(x,e,n):
    r=x
    for b in e:
        r=(r*r)%n
        if(b=='1'):
            r=(r*x)%n
    return r

def rsaep(m,e,n):
    if(m>n-1):
        print("ERROR: message representative out of range")
        return
    return SandM(m,e,n)

def rsadp(c,d,n):
    if(c>n-1):
        print("ERROR: ciphertext representative out of range")
        return
    return SandM(c,d,n)

#RSAES-PKCS1-v1_5
    
def i2osp(x, l):
        if x >= 256**l:
            print("ERROR: integer too large")
            return
        msg = ''
        while x:
            msg= msg + chr(x % 256)
            x = x // 256
        msglen=len(msg)
        for i in range(l - msglen):
            msg= msg +chr(0)
        return msg

def os2ip(msg):
        msgLen = len(msg)
        x = 0
        for i in range(msgLen):
            x = x + ( ord(msg[i]) * (256**i) )
        return x
    
    
def pkcs1_v1_5_en(text,e,n):
    l=len(text)
    if(l>245):
        print("ERROR: message too long")
        return
    num=256-l-3
    PS=""
    for i in range(num):
        PS=PS+chr(random.randrange(1, 255))
    EM=chr(0)+chr(2)+PS+chr(0)+text
    m=os2ip(EM)
    c=rsaep(m,e,n)
    ciphertext=i2osp(c,256)
    return ciphertext

def pkcs1_v1_5_de(ciphertext,d,n):
    l=len(ciphertext)
    if(l>256):
        print("ERROR: decryption error")
        return
    c=os2ip(ciphertext)
    m=rsadp(c,d,n)
    EM=i2osp(m,256)
    if(EM[0]!=chr(0) or EM[1]!=chr(2)):
        print("ERROR: decryption error!")
        return
    index=EM.find(chr(0),2,-1)
    return EM[index+1:]

#general function: ideally they could be calling both pkcs_v1_5 and OEAP

def encrypt(text,pub_k,n):
    e=bin(pub_k)[3:]
    ciphertext=pkcs1_v1_5_en(text,e,n)
    return ciphertext

def decrypt(ciphertext,priv_k,n):
    d=bin(priv_k)[3:]
    plaintext=pkcs1_v1_5_de(ciphertext,d,n)
    return plaintext


#--------------------------MAIN-------------------------
        
def input_fun():
    input_string=raw_input("Do you want to encrypt a string or a file? (s/f) \n")
    if(input_string=="s"):
        string=raw_input("Insert the string you want to encrypt \n")
        return string
    elif(input_string=="f"):
        name=raw_input("Insert the name of the file \n")
        file=open(name,"r")
        string=file.read()
        file.close()
        return string
    else:
        print("Error: your instruction doesn't exist.")
        return input_fun()
    
string=input_fun()    
pub_k,priv_k,n=key_gen()


en_start=time.time()
ciphertext=encrypt(string,pub_k,n)
en_rtime=time.time() - en_start
print("encryption running time: "+str(en_rtime)+" sec")

de_start=time.time()
plaintext=decrypt(ciphertext,priv_k,n)
de_rtime=time.time() - de_start
print("decryption running time: "+str(de_rtime)+" sec")

printed=raw_input("Do you want to see the ciphertext and plaintex on a terminal or a file or nowhere? (t/f/n) \n")
if(printed=="t"):
    print("\n ciphertext \n")
    #print(ciphertext)
    print(ciphertext)
    print("\n plaintext \n")
    print(plaintext)
elif(printed=="f"):
    file=open("results.txt","w")
    file.write("\n ciphertext \n"+str(ciphertext)+"\n plaintext \n"+str(plaintext))
    file.close
    print("\n printed on 'results.txt' \n")
else:
    print("Done!")
    
        
