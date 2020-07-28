import os
import random
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import struct

class CryptoCipher(object):

    def __init__(self, key): 
        self.blockSize = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

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


# some example to show how to use this module

## Using to encrypt/decrypt a 'string' message with given key
# a = CryptoCipher("7A24432646294A404E635266556A576E5A7234753778214125442A472D4B6150")
# e = a.encrypt_text("hi")
# print(e)
# print(a.decrypt_text(e))

### Usint to encrypt/decrypt any file with specified key

# a.encrypt_file("./op.svg")
# a.decrypt_file("op.svg.enc")

# a.encrypt_file("data.txt")
# a.decrypt_file("data.txt.enc")