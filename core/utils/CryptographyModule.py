import os, sys
import random
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from rest_framework.exceptions import ValidationError
import struct
import json

<<<<<<< HEAD
sys.path.append('../../backend')
from settings import P, PUBLIC_KEY, PRIVATE_KEY
=======
from backend.settings import P, G, PUBLIC_KEY, PRIVATE_KEY
>>>>>>> 816bff5f1be0b72b1385ff21ac90a17d30276c15

class CryptoCipher(object):

    def __init__(self, key): 
        self.blockSize = AES.block_size
        self.p = P
        # self.g = G
        # print(self.public_key_encryption(PUBLIC_KEY, pub))
        temp_key = self.private_key_decryption(PRIVATE_KEY, key)
        print(temp_key)
        self.key = hashlib.sha256(temp_key.encode()).digest()

    def encrypt_text(self, plainText):
        plainText = self.pad(plainText)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(plainText.encode()))

    def decrypt_text(self, cipherText):
        cipherText = base64.b64decode(cipherText)

        iv = cipherText[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(cipherText[AES.block_size:])).decode()

    def pad(self, s):
        return s + (self.blockSize - len(s) % self.blockSize) * chr(self.blockSize - len(s) % self.blockSize)

    @staticmethod
    def unpad(s):
        return s[:-ord(s[len(s)-1:])]


    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            plainText = fo.read()

        plainText = plainText + b"\0" * (AES.block_size - len(plainText) % AES.block_size)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        enc = base64.b64encode(iv + cipher.encrypt(plainText))

        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)


    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            cipherText = fo.read()

        cipherText = base64.b64decode(cipherText)
        iv = cipherText[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(cipherText[AES.block_size:])
        dec = plaintext.rstrip(b"\0")

        with open("decrypted_"+file_name[:-4], 'wb') as fo:
            fo.write(dec)

    def private_key_decryption(self, private_key, encrypted):
        return str(pow(encrypted, int(PRIVATE_KEY, 16), int(self.p, 16)))

    def public_key_encryption(self, public_key, plain_text):
        return str(pow(int(plain_text, 16), int(public_key, 16), int(self.p, 16)))




# some example to show how to use this module
if __name__=="__main__":
    ## Using to encrypt/decrypt a 'string' message with given key
    

    # session_key = pow(int(PUBLIC_KEY_client, 16), int(PRIVATE_KEY, 16), int(P, 16))
    # print(session_key)

    # ses = 12102292340787506527703514819128586984757329604944520300483314667474312146401387724578562014938173459611215076980505992852635232655068555405060650525566178029715405285302655764946200132300458136951341989263187824994655485923896641660706255421345970417306891397652712803859750564638556741855530638263193012867978806300613860896538482501056953232760257703174859232871452549767671649657487467801173885382121024863158317837902897735687508938742799694028848280123028608192431484369926324068390881839758415967377098367720623409825036375949914340426574884923240519705637188437856002015567603773793884911654806404721057780096
    # pub = session_key
    
    
    # a = pow(10, PUBLIC_KEY, int(P,16))
    a = 19932357042291180844281721172973927269566136734323207371678966231752835204083982805860019791127650045939347819243766056711379400501942059898360220047179625449366095347511213770686915251832194026883299160780231110667053777554982902270114288632671912173533514562297893854700560210229930982968478569241663740469109484114886374414824896006361919401304592874563567018721715033957026147167104904516719861063354608168253066913186257285443504965057920154406683006324471503139064927667818305537471683175176648683853124143758477153047801051914739172841448203423207942053136818162769295227948176016567597915337290889925202789574
    # b = pow(a, int(PRIVATE_KEY, 16), int(P,16))
    # print(b)

    cipher = CryptoCipher(a)
    a = "{}".format({"username":"moein","password":"12345","confidentiality_label": 1,"integrity_label": 1})
    print(a)
    c = cipher.encrypt_text(a)
    print(c)
    e = b'cE8EYTWGqyapOnenaW70eHQ7rMEasblG4r+ttKxfpOElzt0+SNbqNK7IG+weCCK1NWK9te1d3lxjFrBvHAmPDePgU5JtUxZcirB5E29I+9gMaHXlCwYYRteUcT0/vUmbo+MY5G7bbtVok+sZjiIY5w=='
    print(cipher.decrypt_text(e))

    ### Using to encrypt/decrypt any file with specified key

    # a.encrypt_file("./scr.png")
    # a.decrypt_file("scr.png.enc")

<<<<<<< HEAD
    # a.encrypt_file("data.txt")
    # a.decrypt_file("data.txt.enc")
=======

def get_data(request):
    headers = request.headers
    if headers.get('Session-Key'):
        return CryptoCipher(headers['Session-Key'])
    else:
        raise ValidationError("session_key is invalid.")

>>>>>>> 816bff5f1be0b72b1385ff21ac90a17d30276c15
