from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

import hashlib

def text_padding(text, unit):
    while len(text) % unit != 0:
        text += '_'.encode('utf-8')
    return text

def process_DES(text):
    key = input("key(must be 8 bytes): ").encode('utf-8') 
    while len(key) != 8:
        print("For DES, key length must be 8 bytes")
        key = input("key(must be 8 bytes): ").encode('utf-8') 
    des = DES.new(key, DES.MODE_ECB)
    
    target_text = text_padding(text, 8)
    encrypted = des.encrypt(target_text)
    print("encrypted: "+ str(encrypted))
    decrypted = des.decrypt(encrypted)
    decrypted = decrypted.decode('utf-8')
    print("decrypted: "+decrypted)

def process_DES3(text):
    des3 = None
    length = None
    while True:
        key = input("key(must be 16 or 24 bytes): ").encode('utf-8')
        length = len(key)
        try:
            key = DES3.adjust_key_parity(key)
            des3 = DES3.new(key, DES3.MODE_ECB)
            break
        except ValueError:
            pass
    target_text = text_padding(text, 8)
    encrypted = des3.encrypt(target_text)
    print("encrypted: "+ str(encrypted))
    decrypted = des3.decrypt(encrypted)
    decrypted = decrypted.decode('utf-8')
    print("decrypted: "+decrypted)

def process_AES(text):
    key = input("key(must be 16 or 24 or 32 bytes): ").encode('utf-8')
    while len(key) != 16 and len(key) != 24 and len(key) != 32:
        print("For DES, key length must be 16 or 24 or 32 bytes")
        key = input("key(must be 16 or 24 or 32 bytes): ").encode('utf-8')
    length = len(key)
    
    aes = AES.new(key, AES.MODE_ECB)
    target_text = text_padding(text, 16)
    encrypted = aes.encrypt(target_text)
    print("encrypted: "+ str(encrypted))
    decrypted = aes.decrypt(encrypted)
    decrypted = decrypted.decode('utf-8')
    print("decrypted: "+decrypted)

def process_RSA(text):
    length = None
    encrypted = None
    decrypted = None
    rsa = None
    while True:
        try:
            while True:
                try:
                    length = int(input("key length(must be X*256, and greater or equal to 1024): "))
                except ValueError:
                    continue
                if length % 256 == 0 and length >= 1024:
                    break
            key = RSA.generate(length)
            rsa = PKCS1_OAEP.new(key)
            encrypted = rsa.encrypt(text)
            decrypted = rsa.decrypt(encrypted)
            decrypted = decrypted.decode('utf-8')
            break
        except ValueError:
            print("key length is not long enough to encrypt plain text, input larger number")
            continue
        
    print("encrypted: "+ str(encrypted))

    print("decrypted: "+decrypted)
    
def main():
    data = input("original data: ")
    data = data.encode('utf-8')
    print(" ")
    while True:
        cipher_type = input("cipyer type(DES/DES3/AES): ")
        if cipher_type == "DES":
            process_DES(data)
            break
        elif cipher_type == "DES3":
            process_DES3(data)
            break
        elif cipher_type == "AES":
            process_AES(data)
            break
        else:
            print("Wrong cipher type! : "+cipher_type)

    print(" ")
    while True:
        hash_type = input("hash type(SHA256/SHA384/SHA512): ")
        target_text = data
        if hash_type == "SHA256":
            print(hashlib.sha256(target_text).hexdigest())
            break
        elif hash_type == "SHA384":
            print(hashlib.sha384(target_text).hexdigest())
            break
        elif hash_type == "SHA512":
            print(hashlib.sha512(target_text).hexdigest())
            break
        else:
            print("Wrong hash type! : " + hash_type)
    print(" ")
    print("RSA")
    process_RSA(data)
     
     
if __name__ == "__main__":
    main()
